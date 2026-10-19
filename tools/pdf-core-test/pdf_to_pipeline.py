"""Standalone, opt-in PDF bridge for the existing processing core.

No production modules are changed; no PII manifest is exported.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import io
import json
import logging
import math
import re
import sys
import unicodedata
from collections import Counter
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import uuid4

HERE = Path(__file__).resolve().parent
# The harness lives in tools/pdf-core-test inside the pipeline repository.
DEFAULT_PIPELINE = HERE.parents[1]
VERSION = "pdf-core-test-v1"
DIAGNOSTIC_FIELD_NAMES = frozenset(
    {
        "answer",
        "analysis",
        "reasoning",
        "response",
        "output",
        "result",
        "results",
        "data",
        "error",
        "detail",
        "message",
        "status",
        "pii",
        "entities",
        "detections",
        "properties",
        "type",
        "schema",
        "json_schema",
        "schema_used",
        "structured_output",
        "has_pii",
        "findings",
        "value",
        "anchor",
        "pii_type",
    }
)
JSON_VALUE_KINDS = frozenset(
    {"object", "array", "string", "boolean", "integer", "number", "null"}
)
TRANSPORT_FAILURE_KINDS = frozenset(
    {
        "READ_TIMEOUT",
        "CONNECT_TIMEOUT",
        "WRITE_TIMEOUT",
        "POOL_TIMEOUT",
        "CONNECT_ERROR",
        "READ_ERROR",
        "WRITE_ERROR",
        "PROTOCOL_ERROR",
        "OTHER_TRANSPORT_ERROR",
    }
)


class TestInputError(ValueError):
    """Fixed code only; never retain document contents in errors."""


class CoreRunError(TestInputError):
    """Only harness counters and core-allowlisted diagnostic fields."""

    def __init__(self, code, report):
        super().__init__(code)
        self.report = report


def fail(code: str):
    raise TestInputError(code)


def read_text(path: Path) -> str:
    with path.open(encoding="utf-8", newline="") as stream:
        return stream.read()


def write_text(path: Path, text: str):
    with path.open("x", encoding="utf-8", newline="") as stream:
        stream.write(text)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def encoded(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def load_json(path: Path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("INVALID_JSON")
            result[key] = value
        return result

    return json.loads(read_text(path), object_pairs_hook=pairs)


def positive(value, code="INVALID_BUDGET"):
    if type(value) is not int or value <= 0:
        fail(code)
    return value


def private_work_dir(work: Path, pipeline: Path):
    work = work.resolve()
    for root in (HERE, pipeline.resolve()):
        if work == root or root in work.parents:
            fail("WORK_DIR_MUST_BE_OUTSIDE_CODE")
    if any((parent / ".git").exists() for parent in (work, *work.parents)):
        fail("WORK_DIR_MUST_BE_OUTSIDE_GIT")
    return work


@contextmanager
def quiet_libraries():
    # Library diagnostics may contain paths/PDF content; never print them.
    previous = logging.root.manager.disable
    logging.disable(sys.maxsize)
    try:
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            yield
    finally:
        logging.disable(previous)


def attach_pipeline(pipeline: Path):
    pipeline = pipeline.resolve()
    if not (pipeline / "pii_pipeline" / "service" / "app.py").is_file():
        fail("PIPELINE_NOT_FOUND")
    sys.path.insert(0, str(pipeline))
    # Bundled Python is retained first for third-party libraries.
    dependencies = pipeline / ".venv" / "Lib" / "site-packages"
    if dependencies.is_dir() and str(dependencies) not in sys.path:
        sys.path.append(str(dependencies))


def plan_ranges(
    source: str,
    window_chars: int,
    overlap_blocks: int,
    max_windows: int,
    boundary: str = "paragraph",
):
    positive(window_chars)
    positive(max_windows)
    if type(overlap_blocks) is not int or overlap_blocks < 0:
        fail("INVALID_BUDGET")
    if not source.strip():
        fail("EMPTY_SOURCE")
    # Include separators in their preceding block; preserve every character.
    if boundary not in ("paragraph", "line"):
        fail("INVALID_BOUNDARY_POLICY")
    separator = r"\r?\n[ \t]*\r?\n" if boundary == "paragraph" else r"\r?\n"
    boundaries = [0, *(match.end() for match in re.finditer(separator, source))]
    if boundaries[-1] != len(source):
        boundaries.append(len(source))
    blocks = list(pairwise(boundaries))
    if any(end - start > window_chars for start, end in blocks):
        fail("BLOCK_EXCEEDS_WINDOW")
    ranges = []
    index = 0
    while index < len(blocks):
        end_index = index + 1
        while end_index < len(blocks) and (
            blocks[end_index][1] - blocks[index][0] <= window_chars
        ):
            end_index += 1
        ranges.append({"start": blocks[index][0], "end": blocks[end_index - 1][1]})
        if len(ranges) > max_windows:
            fail("WINDOW_CAP_EXCEEDED")
        if end_index == len(blocks):
            break
        next_index = max(index + 1, end_index - overlap_blocks)
        # Retain only the complete overlap blocks that also fit the next new
        # block. Otherwise a large next block can produce contained windows
        # that make no coverage progress and violate the reviewed-plan contract.
        while next_index < end_index and (
            blocks[end_index][1] - blocks[next_index][0] > window_chars
        ):
            next_index += 1
        index = next_index
    return ranges


def validate_ranges(source, ranges, cap, max_windows):
    positive(cap)
    positive(max_windows)
    if not isinstance(ranges, list) or not 0 < len(ranges) <= max_windows:
        fail("INVALID_WINDOWS")
    previous = None
    covered = 0
    for item in ranges:
        if not isinstance(item, dict) or set(item) != {"start", "end"}:
            fail("INVALID_WINDOWS")
        start, end = item["start"], item["end"]
        if type(start) is not int or type(end) is not int:
            fail("INVALID_WINDOWS")
        if not 0 <= start < end <= len(source) or end - start > cap:
            fail("INVALID_WINDOWS")
        if not source[start:end].strip():
            fail("EMPTY_WINDOW")
        if previous is not None and (start <= previous[0] or end <= previous[1]):
            fail("INVALID_WINDOWS")
        if start > covered:
            fail("WINDOW_COVERAGE_GAP")
        previous = (start, end)
        covered = end
    if covered != len(source):
        fail("WINDOW_COVERAGE_GAP")


def extract_pdf(
    pdf: Path, page_text_dir: Path | None, ask_password: bool, extractor: str = "pypdf"
):
    from pypdf import PdfReader

    if extractor not in ("pypdf", "pdfplumber"):
        fail("INVALID_EXTRACTOR")
    password = None
    with quiet_libraries():
        reader = PdfReader(str(pdf))
        if reader.is_encrypted and not ask_password:
            fail("ENCRYPTED_PDF")
    if reader.is_encrypted:
        password = getpass.getpass("PDF password (not stored): ")
        with quiet_libraries():
            if not reader.decrypt(password):
                fail("PDF_PASSWORD_REJECTED")
    with quiet_libraries():
        count = len(reader.pages)
        if not count:
            fail("EMPTY_PDF")
        if page_text_dir is not None:
            expected = {f"{index:04d}.txt" for index in range(1, count + 1)}
            actual = {path.name for path in page_text_dir.iterdir()}
            if expected != actual:
                fail("PAGE_TEXT_FILES_MUST_MATCH_ALL_PAGES")
            texts = [
                read_text(page_text_dir / f"{index:04d}.txt")
                for index in range(1, count + 1)
            ]
        elif extractor == "pdfplumber":
            try:
                import pdfplumber
            except ModuleNotFoundError:
                fail("PDFPLUMBER_UNAVAILABLE")
            with pdfplumber.open(str(pdf), password=password) as alternate:
                if len(alternate.pages) != count:
                    fail("EXTRACTOR_PAGE_COUNT_MISMATCH")
                texts = [page.extract_text() or "" for page in alternate.pages]
        else:
            texts = [page.extract_text() or "" for page in reader.pages]
    del password
    return texts


def prepare(
    pdf,
    work,
    *,
    window_chars,
    overlap_blocks,
    max_windows,
    page_text_dir=None,
    ask_password=False,
    boundary="paragraph",
    extractor="pypdf",
):
    if work.exists():
        fail("WORK_DIR_ALREADY_EXISTS")
    positive(window_chars)
    positive(max_windows)
    texts = extract_pdf(pdf, page_text_dir, ask_password, extractor)
    return prepare_texts(
        texts,
        work,
        window_chars=window_chars,
        overlap_blocks=overlap_blocks,
        max_windows=max_windows,
        boundary=boundary,
        source_kind="pdf",
        conversion="page-text-import" if page_text_dir else extractor + "-plain",
    )


def prepare_md(
    markdown, work, *, window_chars, overlap_blocks, max_windows, boundary="paragraph"
):
    if work.exists():
        fail("WORK_DIR_ALREADY_EXISTS")
    positive(window_chars)
    positive(max_windows)
    raw = read_text(markdown)
    # UTF-8 BOM is an encoding marker, not document content.
    raw = raw.removeprefix("\ufeff")
    if not raw.strip():
        fail("EMPTY_SOURCE")
    return prepare_texts(
        [raw],
        work,
        window_chars=window_chars,
        overlap_blocks=overlap_blocks,
        max_windows=max_windows,
        boundary=boundary,
        source_kind="markdown",
        conversion="markdown-import",
    )


def prepare_texts(
    texts,
    work,
    *,
    window_chars,
    overlap_blocks,
    max_windows,
    boundary,
    source_kind,
    conversion,
):
    raw = "\n\n".join(texts)
    normalized_pages = [unicodedata.normalize("NFC", text) for text in texts]
    source = "\n\n".join(normalized_pages)
    pages = []
    cursor = 0
    for index, text in enumerate(normalized_pages, 1):
        pages.append(
            {
                "page": index,
                "start": cursor,
                "end": cursor + len(text),
                "reviewed": False,
                "confirmed_blank": False,
                "status": "TEXT_PRESENT" if text.strip() else "OCR_REQUIRED",
            }
        )
        cursor += len(text) + 2
    planning_error = None
    try:
        ranges = plan_ranges(
            source, window_chars, overlap_blocks, max_windows, boundary
        )
        validate_ranges(source, ranges, window_chars, max_windows)
    except TestInputError as error:
        planning_error = str(error)
        ranges = []
    meta = {
        "version": VERSION,
        "source_nfc_sha256": digest(source),
        "raw_sha256": digest(raw),
        "pages": pages,
        "conversion": conversion,
        "source_kind": source_kind,
        "review_unit_kind": "page" if source_kind == "pdf" else "document",
        "page_separator": "\n\n",
    }
    plan = {
        "version": VERSION,
        "source_nfc_sha256": digest(source),
        "reviewed": False,
        "window_chars": window_chars,
        "overlap_blocks": overlap_blocks,
        "max_windows": max_windows,
        "boundary": boundary,
        "planning_error": planning_error,
        "windows": ranges,
    }
    work.mkdir(parents=True, exist_ok=False)
    write_text(work / "source.raw.md", raw)
    write_text(work / "source.md", source)
    write_text(work / "pages.json", encoded(meta))
    write_text(work / "detection-windows.json", encoded(plan))
    return {
        "status": "REVIEW_REQUIRED",
        "conversion": meta["conversion"],
        "source_kind": source_kind,
        "pages_total": len(pages) if source_kind == "pdf" else None,
        "review_units_total": len(pages),
        "pages_needing_ocr_or_blank_review": sum(
            p["status"] == "OCR_REQUIRED" for p in pages
        ),
        "detection_windows": len(ranges),
        "planning_error": planning_error,
    }


def read_prepared(work: Path, *, require_review: bool):
    source = read_text(work / "source.md")
    raw = read_text(work / "source.raw.md")
    meta = load_json(work / "pages.json")
    plan = load_json(work / "detection-windows.json")
    if not source.strip() or unicodedata.normalize("NFC", raw) != source:
        fail("SOURCE_CHANGED")
    if not isinstance(meta, dict) or not isinstance(plan, dict):
        fail("INVALID_PREPARATION")
    if meta.get("version") != VERSION or plan.get("version") != VERSION:
        fail("INVALID_PREPARATION")
    if meta.get("source_nfc_sha256") != digest(source) or plan.get(
        "source_nfc_sha256"
    ) != digest(source):
        fail("SOURCE_CHANGED")
    if meta.get("raw_sha256") != digest(raw) or meta.get("page_separator") != "\n\n":
        fail("SOURCE_CHANGED")
    pages = meta.get("pages")
    if not isinstance(pages, list) or not pages:
        fail("INVALID_PAGE_INDEX")
    source_kind = meta.get("source_kind", "pdf")
    if source_kind not in ("pdf", "markdown"):
        fail("INVALID_PREPARATION")
    if source_kind == "markdown" and (
        len(pages) != 1 or meta.get("conversion") != "markdown-import"
    ):
        fail("INVALID_PREPARATION")
    cursor = 0
    for number, page in enumerate(pages, 1):
        if (
            not isinstance(page, dict)
            or type(page.get("page")) is not int
            or page["page"] != number
        ):
            fail("INVALID_PAGE_INDEX")
        start, end = page.get("start"), page.get("end")
        if (
            type(start) is not int
            or type(end) is not int
            or start != cursor
            or not start <= end <= len(source)
        ):
            fail("INVALID_PAGE_INDEX")
        has_text = bool(source[start:end].strip())
        if page.get("status") != ("TEXT_PRESENT" if has_text else "OCR_REQUIRED"):
            fail("INVALID_PAGE_INDEX")
        if (
            type(page.get("reviewed")) is not bool
            or type(page.get("confirmed_blank")) is not bool
        ):
            fail("INVALID_PAGE_INDEX")
        if has_text and page["confirmed_blank"]:
            fail("INVALID_BLANK_PAGE")
        cursor = end
        if number < len(pages):
            if source[cursor : cursor + 2] != "\n\n":
                fail("INVALID_PAGE_INDEX")
            cursor += 2
        if require_review:
            if not page["reviewed"]:
                fail("PAGE_REVIEW_REQUIRED")
            if not has_text and not page["confirmed_blank"]:
                fail("OCR_REQUIRED")
    if cursor != len(source):
        fail("INVALID_PAGE_INDEX")
    if type(plan.get("reviewed")) is not bool:
        fail("WINDOW_REVIEW_REQUIRED")
    if require_review and plan["reviewed"] is not True:
        fail("WINDOW_REVIEW_REQUIRED")
    # A manually corrected plan must remove its old planning_error.
    if plan.get("planning_error") is not None:
        fail("WINDOW_PLAN_REQUIRED")
    positive(plan.get("window_chars"))
    positive(plan.get("max_windows"))
    overlap = plan.get("overlap_blocks")
    if type(overlap) is not int or overlap < 0:
        fail("INVALID_BUDGET")
    if plan.get("boundary") not in ("paragraph", "line"):
        fail("INVALID_BOUNDARY_POLICY")
    validate_ranges(
        source, plan.get("windows"), plan["window_chars"], plan["max_windows"]
    )
    return source, meta, plan


def review(work: Path, blank_pages: list[int]):
    source, meta, plan = read_prepared(work, require_review=False)
    if meta.get("source_kind") == "markdown" and blank_pages:
        fail("INVALID_BLANK_PAGE")
    blanks = set(blank_pages)
    if len(blanks) != len(blank_pages) or any(
        type(n) is not int or not 1 <= n <= len(meta["pages"]) for n in blanks
    ):
        fail("INVALID_BLANK_PAGE")
    for page in meta["pages"]:
        has_text = bool(source[page["start"] : page["end"]].strip())
        if page["page"] in blanks and has_text:
            fail("INVALID_BLANK_PAGE")
        if not has_text and page["page"] not in blanks:
            fail("OCR_REQUIRED")
        page["reviewed"] = True
        page["confirmed_blank"] = page["page"] in blanks
    plan["reviewed"] = True
    # Replacing review files never changes the source or produces test results.
    for name, data in (("pages.json", meta), ("detection-windows.json", plan)):
        temp = work / ("." + uuid4().hex + ".json")
        try:
            write_text(temp, encoded(data))
            temp.replace(work / name)
        finally:
            temp.unlink(missing_ok=True)
    return {
        "status": "READY_FOR_CORE",
        "source_kind": meta.get("source_kind", "pdf"),
        "pages_total": len(meta["pages"])
        if meta.get("source_kind", "pdf") == "pdf"
        else None,
        "review_units_total": len(meta["pages"]),
        "detection_windows": len(plan["windows"]),
    }


@dataclass(frozen=True)
class RunBudget:
    max_calls: int
    max_verification_windows: int
    deadline_seconds: int

    def validate(self, detection_count: int):
        positive(self.max_calls)
        positive(self.max_verification_windows)
        positive(self.deadline_seconds)
        if detection_count + 1 > self.max_calls:
            fail("CALL_CAP_TOO_SMALL")


class TracedClient:
    def __init__(self, client, max_calls, progress=None, recovery_mode=False):
        self.client = client
        self.max_calls = max_calls
        self.calls = []
        self.request_count = 0
        self.tracks_requests = hasattr(client, "request_callback")
        if self.tracks_requests:
            client.request_callback = self.reserve_request
        if hasattr(client, "request_finished_callback"):
            client.request_finished_callback = self.finish_request
        self.failure_code = None
        self.progress = progress
        self.recovery_mode = recovery_mode

    def emit(self, event, item):
        if self.progress is not None:
            self.progress({"event": event, **item})

    async def heartbeat(self, item, started):
        while True:
            await asyncio.sleep(30)
            self.emit(
                "CALL_WAITING",
                {**item, "elapsed_seconds": round(perf_counter() - started, 3)},
            )

    def reserve_request(self, role, input_characters, *, timeouts=None):
        if self.request_count >= self.max_calls:
            self.failure_code = "CALL_CAP_EXCEEDED"
            fail("CALL_CAP_EXCEEDED")
        self.request_count += 1
        if self.calls:
            self.calls[-1]["request_role"] = role
        self.emit(
            "PROXY_REQUEST_STARTED",
            {
                "proxy_request_number": self.request_count,
                "role": role,
                "input_characters": input_characters,
                **(
                    {"request_timeouts_seconds": safe_timeout_diagnostics(timeouts)}
                    if type(timeouts) is dict
                    else {}
                ),
            },
        )

    def finish_request(self, role, elapsed_seconds, outcome):
        """Per-request timing; outcome is an HTTP status or a transport kind."""
        timing = {
            "proxy_request_number": self.request_count,
            "role": role,
            "elapsed_seconds": round(elapsed_seconds, 3),
            "outcome": outcome,
        }
        if self.calls:
            self.calls[-1].setdefault("proxy_request_timings", []).append(
                {key: timing[key] for key in ("role", "elapsed_seconds", "outcome")}
            )
        self.emit("PROXY_REQUEST_FINISHED", timing)

    async def call(self, role, source, prompt, *, method=None, method_kwargs=None):
        if self.request_count >= self.max_calls:
            self.failure_code = "CALL_CAP_EXCEEDED"
            fail("CALL_CAP_EXCEEDED")
        item = {
            "call_number": len(self.calls) + 1,
            "role": role,
            "window_number": 1 + sum(call["role"] == role for call in self.calls),
            "input_characters": len(source),
            "status": "STARTED",
        }
        self.calls.append(item)
        requests_before = self.request_count
        if not self.tracks_requests:
            self.reserve_request(role, len(source))
        started = perf_counter()
        self.emit("CALL_STARTED", item)
        heartbeat = (
            asyncio.create_task(self.heartbeat(item, started))
            if self.progress is not None
            else None
        )
        try:
            options = dict(method_kwargs or {})
            if prompt is not None:
                options["prompt"] = prompt
            result = await getattr(self.client, method or role)(source, **options)
            if role == "verify" and result.has_pii is True and not self.recovery_mode:
                self.failure_code = "RESIDUAL_DETECTED"
                fail("RESIDUAL_DETECTED")
            item["status"] = "SUCCESS"
            if method == "detect_outcome" and result.issues:
                item["status"] = "DETECTION_ISSUES"
                item["issue_count"] = len(result.issues)
                item["reason_codes"] = sorted(
                    {issue.reason_code for issue in result.issues}
                )
            if role == "verify" and result.has_pii is True:
                item["status"] = "RESIDUAL_DETECTED"
            if role == "verify":
                # Parsed canonical types only; findings never carry values.
                item["finding_types"] = sorted(
                    {finding.pii_type for finding in result.findings}
                )
            return result
        except asyncio.CancelledError:
            item["status"] = "CANCELLED"
            raise
        except Exception as error:
            # The proxy sanitizes observer exceptions as transport failures.
            # Keep our already-set call-cap outcome and never spend another call.
            if self.failure_code == "CALL_CAP_EXCEEDED":
                item["status"] = self.failure_code
                fail("CALL_CAP_EXCEEDED")
            from pii_pipeline.llm.proxy import (
                LlmProxyHttpError,
                LlmProxyResponseError,
                LlmProxyTimeoutError,
                LlmProxyTransportError,
            )
            from pii_pipeline.llm.response import (
                DetectionResponseError,
                VerificationResponseError,
            )

            if isinstance(error, DetectionResponseError):
                self.failure_code = "DETECTION_RESPONSE_REJECTED"
                item["reason_code"] = error.reason_code
                item["details"] = dict(error.details)
            elif isinstance(error, VerificationResponseError):
                self.failure_code = "VERIFICATION_RESPONSE_REJECTED"
                item["reason_code"] = error.reason_code
            elif isinstance(error, LlmProxyHttpError):
                self.failure_code = "PROXY_HTTP_ERROR"
                if error.status_code is not None:
                    item["http_status"] = error.status_code
            elif isinstance(error, LlmProxyTimeoutError):
                self.failure_code = "PROXY_TIMEOUT"
            elif isinstance(error, LlmProxyTransportError):
                self.failure_code = "PROXY_TRANSPORT_ERROR"
            elif isinstance(error, LlmProxyResponseError):
                self.failure_code = "INVALID_RESPONSE"
                item["reason_code"] = error.reason_code
            else:
                self.failure_code = self.failure_code or "CORE_REJECTED"
            if isinstance(error, (LlmProxyTimeoutError, LlmProxyTransportError)):
                kind = getattr(self.client, "transport_failure_kind", None)
                if type(kind) is str and kind in TRANSPORT_FAILURE_KINDS:
                    item["transport_kind"] = kind
            if isinstance(error, (DetectionResponseError, VerificationResponseError)):
                shape = getattr(self.client, "response_shape", None)
                if type(shape) is dict:
                    item["response_shape"] = safe_response_shape(shape)
            item["status"] = self.failure_code
            raise
        finally:
            if heartbeat is not None:
                heartbeat.cancel()
                try:
                    await heartbeat
                except asyncio.CancelledError:
                    pass
            item["proxy_requests"] = self.request_count - requests_before
            item["elapsed_seconds"] = round(perf_counter() - started, 3)
            self.emit("CALL_FINISHED", item)

    async def select_matches(self, source, matches, *, required_matches=()):
        return await self.call(
            "resolve",
            source,
            None,
            method="select_matches",
            method_kwargs={"matches": matches, "required_matches": required_matches},
        )

    async def detect(self, source, *, prompt):
        return await self.call("detect", source, prompt)

    async def verify(self, source, *, prompt):
        return await self.call("verify", source, prompt)

    async def detect_outcome(self, source, *, prompt, rule_matches=None):
        return await self.call(
            "detect",
            source,
            prompt,
            method="detect_outcome",
            method_kwargs={"rule_matches": rule_matches},
        )


def safe_response_shape(shape):
    """Filter diagnostic metadata again; no arbitrary keys, strings or values."""
    result = {}
    for key in (
        "key_count",
        "unexpected_key_count",
        "candidate_count",
        "decision_count",
        "unrecognized_key_count",
    ):
        value = shape.get(key)
        if type(value) is int and 0 <= value <= 1_000_000:
            result[key] = value
    for key in (
        "candidates_present",
        "decisions_present",
        "decisions_is_array",
        "decisions_is_object",
        "candidates_is_array",
        "has_pii_present",
        "findings_present",
        "required_keys_present",
        "sole_value_has_candidates",
        "request_has_detection_schema",
        "schema_echo_present",
        "schema_echo_is_object",
        "schema_echo_matches_request",
    ):
        value = shape.get(key)
        if type(value) is bool:
            result[key] = value
    tags = shape.get("recognized_unexpected_keys")
    if type(tags) is list:
        result["recognized_unexpected_keys"] = sorted(
            {tag for tag in tags if type(tag) is str and tag in DIAGNOSTIC_FIELD_NAMES}
        )
    kind = shape.get("sole_value_kind")
    if type(kind) is str and kind in JSON_VALUE_KINDS:
        result["sole_value_kind"] = kind
    return result


def json_value_kind(value):
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is dict:
        return "object"
    if type(value) is list:
        return "array"
    if type(value) is str:
        return "string"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    return None


def safe_timeout_diagnostics(values):
    """Only numeric phase budgets; never serialize a settings/timeout object."""
    return {
        key: value
        for key in ("connect", "read", "write", "pool")
        if type(value := values.get(key)) in (int, float)
        and math.isfinite(value)
        and value > 0
    }


def transport_failure_kind(error):
    """Classify by known types, without exception names/messages/causes/requests."""
    import httpx

    for error_type, kind in (
        (httpx.ReadTimeout, "READ_TIMEOUT"),
        (httpx.ConnectTimeout, "CONNECT_TIMEOUT"),
        (httpx.WriteTimeout, "WRITE_TIMEOUT"),
        (httpx.PoolTimeout, "POOL_TIMEOUT"),
        (httpx.ConnectError, "CONNECT_ERROR"),
        (httpx.ReadError, "READ_ERROR"),
        (httpx.WriteError, "WRITE_ERROR"),
        (httpx.ProtocolError, "PROTOCOL_ERROR"),
    ):
        if isinstance(error, error_type):
            return kind
    return "OTHER_TRANSPORT_ERROR"


def diagnostic_client_class():
    from pii_pipeline.llm.client import LlmProxyClient

    class DiagnosticClient(LlmProxyClient):
        request_callback = None
        request_finished_callback = None
        response_shape = None
        schema_echo_shape = None
        transport_failure_kind = None

        async def _send_once(self, form, timeout):
            self.transport_failure_kind = None
            root = set(json.loads(form["json_schema"])["properties"])
            role = (
                "select"
                if root == {"decisions"}
                else ("detect" if root == {"candidates"} else "verify")
            )
            if self.request_callback is not None:
                self.request_callback(
                    role, len(form["context"]), timeouts=timeout.as_dict()
                )
            started = perf_counter()
            try:
                response = await super()._send_once(form, timeout)
            except Exception as error:
                self.transport_failure_kind = transport_failure_kind(error)
                if self.request_finished_callback is not None:
                    self.request_finished_callback(
                        role, perf_counter() - started, self.transport_failure_kind
                    )
                raise  # The production client still sanitizes and classifies failure.
            if self.request_finished_callback is not None:
                self.request_finished_callback(
                    role, perf_counter() - started, f"HTTP_{int(response.status_code)}"
                )
            # Observe already-read success JSON only. No request context, headers,
            # error body, arbitrary key name or response value is retained.
            self.schema_echo_shape = {}
            try:
                if response.status_code == 200:
                    envelope = response.json()
                    requested_schema = json.loads(form["json_schema"])
                    if type(envelope) is dict:
                        self.schema_echo_shape = {
                            "schema_echo_present": "schema_used" in envelope,
                            "schema_echo_is_object": type(envelope.get("schema_used"))
                            is dict,
                        }
                        if type(envelope.get("schema_used")) is dict:
                            self.schema_echo_shape["schema_echo_matches_request"] = (
                                envelope["schema_used"] == requested_schema
                            )
            except Exception:  # noqa: BLE001 - diagnostics cannot repair/reject output.
                self.schema_echo_shape = {}
            return response

        async def structured_output(
            self, *, context, json_schema, prompt, use_thinking
        ):
            self.response_shape = None
            self.schema_echo_shape = None
            self.transport_failure_kind = None
            output = await super().structured_output(
                context=context,
                json_schema=json_schema,
                prompt=prompt,
                use_thinking=use_thinking,
            )
            # The base client already validates a dict success payload. Never
            # retain it here or serialize model-supplied field names/values.
            expected = set(json_schema["properties"])
            unexpected = output.keys() - expected
            recognized = unexpected & DIAGNOSTIC_FIELD_NAMES
            sole_value = next(iter(output.values())) if len(output) == 1 else None
            self.response_shape = safe_response_shape(
                {
                    "key_count": len(output),
                    "unexpected_key_count": len(output.keys() - expected),
                    "recognized_unexpected_keys": sorted(recognized),
                    "unrecognized_key_count": len(unexpected - recognized),
                    "required_keys_present": all(key in output for key in expected),
                    "candidates_present": "candidates" in output,
                    "decisions_present": "decisions" in output,
                    "decisions_is_array": isinstance(output.get("decisions"), list),
                    "decisions_is_object": isinstance(output.get("decisions"), dict),
                    "decision_count": len(output["decisions"])
                    if isinstance(output.get("decisions"), (list, dict))
                    else None,
                    "candidates_is_array": isinstance(output.get("candidates"), list),
                    "has_pii_present": "has_pii" in output,
                    "findings_present": "findings" in output,
                    "candidate_count": len(output["candidates"])
                    if isinstance(output.get("candidates"), list)
                    else None,
                    "sole_value_kind": json_value_kind(sole_value)
                    if len(output) == 1
                    else None,
                    "sole_value_has_candidates": (
                        type(sole_value) is dict and "candidates" in sole_value
                    )
                    if len(output) == 1
                    else None,
                    "request_has_detection_schema": (
                        json_schema.get("type") == "object"
                        and expected == {"candidates"}
                        and json_schema.get("required") == ["candidates"]
                        and json_schema.get("additionalProperties") is False
                    ),
                    **(self.schema_echo_shape or {}),
                }
            )
            return output

    return DiagnosticClient


async def execute_core(
    source, meta, plan, client, budget: RunBudget, progress=None, *, recovery_policy
):
    from pii_pipeline.core.redaction import RedactionError
    from pii_pipeline.core.verification import VerificationError, make_detection_checker
    from pii_pipeline.llm.processing import LlmDocumentProcessor
    from pii_pipeline.llm.prompts import (
        DETECTION_PROMPT_VERSION,
        VERIFICATION_PROMPT_VERSION,
    )
    from pii_pipeline.llm.windows import make_text_window
    from pii_pipeline.recovery.process import (
        RECOVERY_MERGE_REASON_CODES,
        RECOVERY_VERSION,
        RecoveryMergeError,
        process_markdown_with_recovery_async,
    )
    from pii_pipeline.rules.thai import detect_thai_rule_pii

    budget.validate(len(plan["windows"]))
    frozen = tuple((w["start"], w["end"]) for w in plan["windows"])
    traced = TracedClient(client, budget.max_calls, progress, recovery_mode=True)
    verification_count = 0
    stage = "rule_detection"
    recovery_report = {}
    residual_started = False

    def recovery_progress(event):
        nonlocal stage, residual_started
        if event["event"] == "RESIDUAL_RECOVERY_STARTED":
            residual_started = True
        recovery_report.update(
            {
                key: event[key]
                for key in ("role_calls", "recovery_calls", "conflict_selection_calls")
                if key in event
            }
        )
        if event["event"] in (
            "DETECTION_WINDOW_OUTCOME",
            "VERIFICATION_RETRY",
            "RESIDUAL_RECOVERY_STARTED",
            "FINAL_VERIFIED",
            "CONFLICT_SELECTION_FINISHED",
        ):
            traced.failure_code = None
        if event["event"] in (
            "RECOVERY_STARTED",
            "RESIDUAL_RECOVERY_STARTED",
            "DETECTION_WINDOW_STARTED",
        ):
            stage = "semantic_detection"
        if event["event"] == "VERIFICATION_WINDOW_STARTED":
            stage = "llm_verification"
        if event["event"] == "CONFLICT_SELECTION_STARTED":
            stage = "detection_merge_or_redaction"
        if event["event"] == "DETECTION_WINDOW_REJECTED":
            stage = "detection_merge_or_redaction"
            recovery_report["merge_diagnostics"] = {
                key: event[key]
                for key in (
                    "window_number",
                    "attempt",
                    "recovery",
                    "retained_matches",
                    "incoming_matches",
                )
            }
        if event["event"] == "FINAL_VERIFIED":
            recovery_report.update(
                {key: value for key, value in event.items() if key != "event"}
            )
        if progress is not None:
            progress(event)

    def detection_planner(actual):
        if actual != source:
            traced.failure_code = "SOURCE_CHANGED"
            fail("SOURCE_CHANGED")
        return [make_text_window(actual, start, end) for start, end in frozen]

    def verification_planner(actual):
        nonlocal verification_count, stage
        stage = "llm_verification"
        try:
            ranges = plan_ranges(
                actual,
                plan["window_chars"],
                plan["overlap_blocks"],
                budget.max_verification_windows,
                plan["boundary"],
            )
            validate_ranges(
                actual, ranges, plan["window_chars"], budget.max_verification_windows
            )
            if traced.request_count + len(ranges) > budget.max_calls:
                fail("CALL_CAP_EXCEEDED")
            verification_count = len(ranges)
            traced.emit("VERIFICATION_PLANNED", {"verification_windows": len(ranges)})
            return [make_text_window(actual, r["start"], r["end"]) for r in ranges]
        except TestInputError as error:
            traced.failure_code = str(error)
            raise

    processor = LlmDocumentProcessor(traced, detection_planner, verification_planner)

    def rule_detector(actual):
        nonlocal stage
        stage = "rule_detection"
        try:
            return detect_thai_rule_pii(actual)
        except Exception:
            traced.failure_code = "RULE_DETECTION_REJECTED"
            raise

    numeric_checker = make_detection_checker([detect_thai_rule_pii])

    def rules_has_pii(actual):
        nonlocal stage
        stage = "rule_verification"
        found = numeric_checker(actual)
        if found:
            traced.failure_code = "RULE_RESIDUAL_DETECTED"
        return found

    started = perf_counter()
    traced.emit("CORE_STARTED", {"detection_windows": len(frozen)})

    def stopped(code, *, reason_code=None):
        raise CoreRunError(
            code,
            {
                "stage": stage,
                "detection_windows": len(frozen),
                "verification_windows": verification_count,
                "elapsed_seconds": round(perf_counter() - started, 3),
                "retry_count": 0,
                "proxy_request_count": traced.request_count,
                "calls": traced.calls,
                **(
                    {"reason_code": reason_code}
                    if reason_code in RECOVERY_MERGE_REASON_CODES
                    else {}
                ),
                "recovery": {"version": RECOVERY_VERSION, **recovery_report},
            },
        ) from None

    try:
        async with asyncio.timeout(budget.deadline_seconds):
            result = await process_markdown_with_recovery_async(
                source,
                processor,
                rule_detectors=(rule_detector,),
                rules_has_pii=rules_has_pii,
                policy=recovery_policy,
                progress=recovery_progress,
            )
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        stopped("WHOLE_RUN_TIMEOUT")
    except RecoveryMergeError as error:
        stage = "detection_merge_or_redaction"
        stopped("DETECTION_MERGE_REJECTED", reason_code=error.reason_code)
    except Exception as error:  # noqa: BLE001 - never copy exception messages/causes.
        if residual_started and isinstance(error, VerificationError):
            # Residual PII was flagged and bounded recovery could not clear it;
            # the last event (re-detection) is not the cause.
            stage = "residual_recovery"
            stopped(traced.failure_code or "RESIDUAL_NOT_RESOLVED")
        fallback = {
            "rule_detection": "RULE_DETECTION_REJECTED",
            "semantic_detection": "SEMANTIC_DETECTION_REJECTED",
            "detection_merge_or_redaction": "DETECTION_MERGE_OR_REDACTION_REJECTED",
            "rule_verification": "RULE_VERIFICATION_REJECTED",
            "llm_verification": "LLM_VERIFICATION_REJECTED",
        }[stage]
        if isinstance(error, RedactionError):
            fallback = "REDACTION_REJECTED"
        stopped(traced.failure_code or fallback)
    summary = {
        "status": "CORE_VERIFIED",
        "version": VERSION,
        "detection_prompt": DETECTION_PROMPT_VERSION,
        "verification_prompt": VERIFICATION_PROMPT_VERSION,
        "source_kind": meta.get("source_kind", "pdf"),
        "pages_total": len(meta["pages"])
        if meta.get("source_kind", "pdf") == "pdf"
        else None,
        "pages_reviewed": len(meta["pages"])
        if meta.get("source_kind", "pdf") == "pdf"
        else None,
        "review_units_total": len(meta["pages"]),
        "review_units_reviewed": len(meta["pages"]),
        "source_characters": len(source),
        "redacted_characters": len(result.redacted_markdown),
        "detection_windows": len(frozen),
        "verification_windows": verification_count,
        "full_window_coverage": True,
        "retry_count": 0,
        "test_budgets": {
            "window_characters": plan["window_chars"],
            "boundary": plan["boundary"],
            "overlap_blocks": plan["overlap_blocks"],
            "max_detection_windows": plan["max_windows"],
            "max_verification_windows": budget.max_verification_windows,
            "max_calls": budget.max_calls,
            "whole_run_deadline_seconds": budget.deadline_seconds,
        },
        "entries_by_type": dict(
            sorted(Counter(entry.pii_type for entry in result.entries).items())
        ),
        "independent_rule_coverage": [
            "CASE_NUMBER",
            "TITLE_DEED_NUMBER",
            "OFFICIAL_LETTER_NUMBER",
            "LAND_PARCEL_NUMBER",
            "ID_NUMBER",
            "PHONE",
            "FAX",
            "BANK_ACCOUNT_NUMBER",
            "PASSPORT_NUMBER",
            "EMAIL",
        ],
        "human_accuracy_evaluation": "NOT_PERFORMED",
        "manifest_exported": False,
        "elapsed_seconds": round(perf_counter() - started, 3),
        "proxy_request_count": traced.request_count,
        "calls": traced.calls,
    }
    summary["recovery"] = {"version": RECOVERY_VERSION, **recovery_report}
    return result.redacted_markdown, summary


def publish(work: Path, redacted: str, summary: dict):
    run_id = "run-" + uuid4().hex
    summary = {**summary, "run_id": run_id}
    results = work / "results"
    results.mkdir(exist_ok=True)
    staged = results / ("." + run_id)
    staged.mkdir()
    try:
        write_text(staged / "redacted.md", redacted)
        write_text(staged / "summary.json", encoded(summary))
        staged.rename(results / run_id)
    finally:
        # Only our two named files and our unique staging directory are removed.
        if staged.exists():
            for name in ("redacted.md", "summary.json"):
                (staged / name).unlink(missing_ok=True)
            staged.rmdir()
    return summary


async def run_live(
    work,
    pipeline,
    settings_file,
    budget,
    progress=None,
    detection_use_thinking=False,
    max_recovery_calls=4,
    max_residual_rounds=1,
    window_number=None,
    reserved_recovery_calls=0,
):
    source, meta, plan = read_prepared(work, require_review=True)
    if window_number is not None:
        positive(window_number, "INVALID_WINDOW_NUMBER")
        if window_number > len(plan["windows"]):
            fail("INVALID_WINDOW_NUMBER")
        selected = plan["windows"][window_number - 1]
        source = source[selected["start"] : selected["end"]]
        plan = {**plan, "windows": [{"start": 0, "end": len(source)}]}
    budget.validate(len(plan["windows"]))
    attach_pipeline(pipeline)
    from pii_pipeline.core.redaction import validate_redaction_source
    from pii_pipeline.llm.config import LlmProxySettings
    from pii_pipeline.recovery.process import RecoveryPolicy

    policy = RecoveryPolicy(
        max_role_calls=budget.max_calls,
        max_recovery_calls=max_recovery_calls,
        max_residual_rounds=max_residual_rounds,
        deadline_seconds=budget.deadline_seconds,
        reserved_recovery_calls=reserved_recovery_calls,
    )

    validate_redaction_source(source)
    settings = LlmProxySettings(
        _env_file=settings_file,
        max_retries=0,
        detection_use_thinking=detection_use_thinking,
        verification_use_thinking=False,
    )
    if progress is not None:
        progress(
            {
                "event": "RUN_SETTINGS",
                "detection_use_thinking": settings.detection_use_thinking,
                "verification_use_thinking": settings.verification_use_thinking,
                "prompt_profile": "baseline",
                "request_deadline_seconds": settings.request_deadline_seconds,
            }
        )
    async with diagnostic_client_class()(settings) as client:
        try:
            redacted, summary = await execute_core(
                source, meta, plan, client, budget, progress, recovery_policy=policy
            )
        except CoreRunError as error:
            error.report["detection_use_thinking"] = settings.detection_use_thinking
            if window_number is not None:
                error.report.update(
                    scope="prepared_window",
                    prepared_window_number=window_number,
                    outputs_published=False,
                )
            error.report["verification_use_thinking"] = (
                settings.verification_use_thinking
            )
            raise
    # Cancellation/failure above never publishes an intermediate result.
    summary["detection_use_thinking"] = settings.detection_use_thinking
    summary["verification_use_thinking"] = settings.verification_use_thinking
    if window_number is not None:
        return {
            **summary,
            "status": "CORE_WINDOW_VERIFIED",
            "scope": "prepared_window",
            "prepared_window_number": window_number,
            "verification_performed": True,
            "outputs_published": False,
        }
    return publish(work, redacted, summary)


def inspection_prompt(profile):
    from pii_pipeline.llm.prompts import build_detection_prompt

    baseline = build_detection_prompt()
    if profile == "baseline":
        return baseline
    fail("INVALID_PROMPT_PROFILE")


def export_swagger_input(
    work, pipeline, window_number, prompt_profile="baseline", use_thinking=False
):
    """Export this real reviewed window privately; audit encoding without a send."""
    source, _, plan = read_prepared(work, require_review=True)
    positive(window_number, "INVALID_WINDOW_NUMBER")
    if window_number > len(plan["windows"]):
        fail("INVALID_WINDOW_NUMBER")
    attach_pipeline(pipeline)
    import httpx

    from pii_pipeline.core.redaction import validate_redaction_source
    from pii_pipeline.llm.client import LlmProxyClient
    from pii_pipeline.llm.config import LLM_PROXY_MODEL
    from pii_pipeline.llm.prompts import DETECTION_PROMPT_VERSION
    from pii_pipeline.llm.schema import build_detection_response_schema

    validate_redaction_source(source)
    window = plan["windows"][window_number - 1]
    context = source[window["start"] : window["end"]]
    schema = build_detection_response_schema()
    prompt = inspection_prompt(prompt_profile)
    # This serializer needs only the public fixed model. Do not instantiate
    # settings/client, read .env or generate a placeholder Authorization key.
    serialization_context = SimpleNamespace(
        _settings=SimpleNamespace(model=LLM_PROXY_MODEL)
    )
    form = LlmProxyClient._build_form(
        serialization_context,
        context=context,
        json_schema=schema,
        prompt=prompt,
        use_thinking=use_thinking,
    )
    # Construct only an in-memory HTTPX Request, never send it. Its data encoding
    # is the same path used by the client; do not persist the encoded body.
    request = httpx.Request(
        "POST", "https://invalid.example/structured-output", data=form
    )
    decoded = parse_qs(request.content.decode("utf-8"), keep_blank_values=True)
    if (
        set(decoded) != set(form)
        or any(decoded[key] != [value] for key, value in form.items())
        or json.loads(decoded["json_schema"][0]) != schema
        or request.headers["content-type"] != "application/x-www-form-urlencoded"
    ):
        fail("FORM_ROUNDTRIP_FAILED")
    export_id = "input-" + uuid4().hex
    parent = work / "swagger-inputs"
    parent.mkdir(exist_ok=True)
    staged = parent / ("." + export_id)
    staged.mkdir()
    parameters = {
        "method": "POST",
        "endpoint_path": "/structured-output",
        "request_content_type": "application/x-www-form-urlencoded",
        "model": form["model"],
        "use_thinking": use_thinking,
        "prompt_profile": prompt_profile,
        "base_detection_prompt": DETECTION_PROMPT_VERSION,
        "prepared_window_number": window_number,
        "input_characters": len(context),
        "offline_form_roundtrip": "PASSED",
        "network_calls": 0,
        "credentials_exported": False,
    }
    names = ("context.txt", "prompt.txt", "json_schema.json", "parameters.json")
    try:
        write_text(staged / "context.txt", form["context"])
        write_text(staged / "prompt.txt", form["prompt"])
        write_text(staged / "json_schema.json", form["json_schema"])
        write_text(staged / "parameters.json", encoded(parameters))
        staged.rename(parent / export_id)
    finally:
        if staged.exists():
            for name in names:
                (staged / name).unlink(missing_ok=True)
            staged.rmdir()
    return {"status": "SWAGGER_INPUT_READY", "export_id": export_id, **parameters}


async def inspect_detection(
    work,
    pipeline,
    settings_file,
    window_number,
    progress,
    prompt_profile="baseline",
    detection_use_thinking=False,
):
    """One reviewed window, same detection contract; no redaction/output publish."""
    source, _, plan = read_prepared(work, require_review=True)
    positive(window_number, "INVALID_WINDOW_NUMBER")
    if window_number > len(plan["windows"]):
        fail("INVALID_WINDOW_NUMBER")
    attach_pipeline(pipeline)
    from pii_pipeline.core.redaction import validate_redaction_source
    from pii_pipeline.llm.config import LlmProxySettings
    from pii_pipeline.llm.prompts import DETECTION_PROMPT_VERSION

    validate_redaction_source(source)
    window = plan["windows"][window_number - 1]
    prompt = inspection_prompt(prompt_profile)
    profile_metadata = {
        "prompt_profile": prompt_profile,
        "base_detection_prompt": DETECTION_PROMPT_VERSION,
    }
    settings = LlmProxySettings(
        _env_file=settings_file,
        max_retries=0,
        detection_use_thinking=detection_use_thinking,
        verification_use_thinking=False,
    )
    profile_metadata["use_thinking"] = settings.detection_use_thinking
    profile_metadata["request_deadline_seconds"] = settings.request_deadline_seconds
    progress(
        {
            "event": "INSPECT_DETECTION_STARTED",
            "prepared_window_number": window_number,
            **profile_metadata,
        }
    )
    async with diagnostic_client_class()(settings) as client:
        traced = TracedClient(client, max_calls=2, progress=progress)
        try:
            await traced.detect(
                source[window["start"] : window["end"]],
                prompt=prompt,
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - expose only sanitized trace, never messages.
            raise CoreRunError(
                traced.failure_code or "CORE_REJECTED",
                {
                    "stage": "single_window_detection",
                    "prepared_window_number": window_number,
                    **profile_metadata,
                    "retry_count": 0,
                    "proxy_request_count": traced.request_count,
                    "calls": traced.calls,
                },
            ) from None
    return {
        "status": "DETECTION_WINDOW_ACCEPTED",
        "prepared_window_number": window_number,
        **profile_metadata,
        "response_shape": safe_response_shape(client.response_shape or {}),
        "proxy_request_count": traced.request_count,
        "calls": traced.calls,
        "verification_performed": False,
        "outputs_published": False,
    }


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse messages can echo private paths and rejected argument values.
        fail("INVALID_ARGUMENTS")


def parser():
    root = SafeParser(description="Local multi-page PDF -> existing core test bridge")
    sub = root.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    for name in (
        "prepare",
        "prepare-md",
        "review",
        "run-core",
        "inspect-detection",
        "export-swagger",
    ):
        command = sub.add_parser(name)
        command.add_argument("--work-dir", type=Path, required=True)
        command.add_argument("--pipeline-dir", type=Path, default=DEFAULT_PIPELINE)
        if name in ("prepare", "prepare-md"):
            if name == "prepare":
                command.add_argument("--pdf", type=Path, required=True)
                command.add_argument("--page-text-dir", type=Path)
                command.add_argument("--ask-password", action="store_true")
                command.add_argument(
                    "--extractor", choices=("pypdf", "pdfplumber"), default="pypdf"
                )
            else:
                command.add_argument("--markdown", type=Path, required=True)
            command.add_argument("--window-chars", type=int, required=True)
            command.add_argument("--max-windows", type=int, required=True)
            command.add_argument("--overlap-blocks", type=int, default=1)
            command.add_argument(
                "--boundary", choices=("paragraph", "line"), default="paragraph"
            )
        elif name == "review":
            command.add_argument(
                "--confirm-pages-and-boundaries", action="store_true", required=True
            )
            command.add_argument("--blank-pages", type=int, nargs="*", default=[])
        else:
            if name != "export-swagger":
                command.add_argument(
                    "--allow-proxy-upload", action="store_true", required=True
                )
                command.add_argument("--settings-file", type=Path)
            command.add_argument(
                "--use-thinking", choices=("false", "true"), default="false"
            )
            if name in ("inspect-detection", "export-swagger"):
                command.add_argument("--window-number", type=int, required=True)
                command.add_argument(
                    "--prompt-profile",
                    choices=("baseline",),
                    default="baseline",
                )
            else:
                command.add_argument("--max-calls", type=int, required=True)
                command.add_argument(
                    "--max-verification-windows", type=int, required=True
                )
                command.add_argument("--run-deadline-seconds", type=int, required=True)
                command.add_argument("--max-recovery-calls", type=int, default=4)
                command.add_argument(
                    "--max-residual-rounds", type=int, choices=(0, 1, 2), default=1
                )
                command.add_argument("--window-number", type=int)
                command.add_argument("--reserved-recovery-calls", type=int, default=0)
    return root


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        work = private_work_dir(args.work_dir, args.pipeline_dir)
        if args.command == "prepare":
            result = prepare(
                args.pdf,
                work,
                window_chars=args.window_chars,
                overlap_blocks=args.overlap_blocks,
                max_windows=args.max_windows,
                page_text_dir=args.page_text_dir,
                ask_password=args.ask_password,
                boundary=args.boundary,
                extractor=args.extractor,
            )
        elif args.command == "prepare-md":
            result = prepare_md(
                args.markdown,
                work,
                window_chars=args.window_chars,
                overlap_blocks=args.overlap_blocks,
                max_windows=args.max_windows,
                boundary=args.boundary,
            )
        elif args.command == "review":
            result = review(work, args.blank_pages)
        elif args.command == "export-swagger":
            with quiet_libraries():
                result = export_swagger_input(
                    work,
                    args.pipeline_dir,
                    args.window_number,
                    args.prompt_profile,
                    args.use_thinking == "true",
                )
        else:
            terminal = sys.stdout

            def progress(event):
                # Bypass only our own library-output suppression, never print
                # document data, exception text or arbitrary response fields.
                terminal.write(
                    json.dumps(event, ensure_ascii=True, allow_nan=False) + "\n"
                )
                terminal.flush()

            with quiet_libraries():
                settings_file = args.settings_file or args.pipeline_dir / ".env"
                if args.command == "inspect-detection":
                    result = asyncio.run(
                        inspect_detection(
                            work,
                            args.pipeline_dir,
                            settings_file,
                            args.window_number,
                            progress,
                            args.prompt_profile,
                            args.use_thinking == "true",
                        )
                    )
                else:
                    budget = RunBudget(
                        args.max_calls,
                        args.max_verification_windows,
                        args.run_deadline_seconds,
                    )
                    result = asyncio.run(
                        run_live(
                            work,
                            args.pipeline_dir,
                            settings_file,
                            budget,
                            progress,
                            args.use_thinking == "true",
                            args.max_recovery_calls,
                            args.max_residual_rounds,
                            args.window_number,
                            args.reserved_recovery_calls,
                        )
                    )
        print(json.dumps(result, ensure_ascii=True, allow_nan=False))
        return 0
    except (KeyboardInterrupt, asyncio.CancelledError):
        print('{"status":"CANCELLED"}')
        return 130
    except TestInputError as error:
        report = error.report if isinstance(error, CoreRunError) else {}
        print(json.dumps({"status": "STOPPED", "error_code": str(error), **report}))
        return 1
    except Exception:  # noqa: BLE001 - sanitize IO/config/library failures at the CLI.
        print('{"status":"STOPPED","error_code":"INPUT_CONFIG_OR_IO_ERROR"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
