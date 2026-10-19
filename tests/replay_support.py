"""Record and replay the LLM proxy so refactoring can prove nothing changed.

A recording keeps, per proxy call, fingerprints of the request (whole body and
its context, prompt and schema fields) and the proxy's reply. Replaying feeds
the same replies back and fails as soon as the code under test sends a request
that differs from the recorded one, so changed prompts, contexts, schemas or
call order are caught before any output is compared.

Outputs are compared after normalisation: per-request IDs, the timestamp and
the multipart boundary are random, everything else must match byte for byte.
"""

import asyncio
import base64
import hashlib
import inspect
import json
import logging
import re
from contextlib import contextmanager
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs

import httpx

from pii_pipeline.llm_client import LlmProxyClient
from pii_pipeline.llm_config import LlmProxySettings
from pii_pipeline.llm_processing import LlmDocumentProcessor
from pii_pipeline.llm_recovery import (
    RecoveryPolicy,
    process_markdown_with_recovery_async,
)
from pii_pipeline.llm_windows import make_text_window
from pii_pipeline.service import ServiceSettings, create_service_app
from pii_pipeline.thai_rules import detect_thai_rule_pii
from pii_pipeline.verification import make_detection_checker

TOKEN = "r" * 40
SERVICE_DEADLINE_SECONDS = 1200


def _sha(text: str | bytes) -> str:
    data = text.encode("utf-8") if isinstance(text, str) else text
    return hashlib.sha256(data).hexdigest()


def request_form(request: httpx.Request) -> dict[str, str]:
    return {
        key: values[0] for key, values in parse_qs(request.content.decode()).items()
    }


def request_role(form: dict[str, str]) -> str:
    """First schema property: candidates, decisions or has_pii."""
    return next(iter(json.loads(form["json_schema"])["properties"]))


def fingerprint(request: httpx.Request) -> dict[str, str]:
    form = request_form(request)
    return {
        "role": request_role(form),
        "body_sha256": _sha(request.content),
        "context_sha256": _sha(form.get("context", "")),
        "prompt_sha256": _sha(form.get("prompt", "")),
        "schema_sha256": _sha(form.get("json_schema", "")),
    }


# An attempt the client's own deadline cut while the proxy had not answered.
# Its timing cannot be replayed, so a recording that holds one is not replayable.
CANCELLED = "cancelled"


class RecordingTransport(httpx.AsyncBaseTransport):
    """Pass each request to ``send`` and keep its fingerprint and reply."""

    def __init__(self, send):
        self._send = send
        self.calls: list[dict] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        call = fingerprint(request)
        try:
            response = self._send(request)
            if inspect.isawaitable(response):
                response = await response
        except httpx.TransportError as error:
            self.calls.append({**call, "error": type(error).__name__})
            raise
        except asyncio.CancelledError:
            self.calls.append({**call, "error": CANCELLED})
            raise
        body = await response.aread()
        content_type = response.headers.get("content-type", "")
        self.calls.append(
            {
                **call,
                "status": response.status_code,
                "content_type": content_type,
                "body": body.decode("utf-8", errors="surrogateescape"),
            }
        )
        return httpx.Response(
            response.status_code, headers={"content-type": content_type}, content=body
        )


class ReplayTransport(httpx.AsyncBaseTransport):
    """Serve recorded replies; any request that differs is a mismatch."""

    def __init__(self, calls: list[dict]):
        self._calls = calls
        self.used = 0
        self.mismatches: list[str] = []

    @property
    def finished(self) -> bool:
        return self.used == len(self._calls)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        actual = fingerprint(request)
        if self.used >= len(self._calls):
            self.mismatches.append(
                f"call {self.used + 1}: extra {actual['role']} request"
            )
            raise httpx.ConnectError("replay exhausted", request=request)
        expected = self._calls[self.used]
        self.used += 1
        if actual["body_sha256"] != expected["body_sha256"]:
            fields = [
                name
                for name in ("role", "context_sha256", "prompt_sha256", "schema_sha256")
                if actual[name] != expected[name]
            ] or ["other form fields"]
            self.mismatches.append(
                f"call {self.used} ({expected['role']}): request differs in {', '.join(fields)}"
            )
            raise httpx.ConnectError("replay mismatch", request=request)
        if expected.get("error") == CANCELLED:
            self.mismatches.append(
                f"call {self.used} ({expected['role']}): cut by a deadline when "
                "recorded; not replayable"
            )
            raise httpx.ConnectError("replay cannot cut by time", request=request)
        if "error" in expected:
            raise getattr(httpx, expected["error"])("replayed", request=request)
        return httpx.Response(
            expected["status"],
            headers={"content-type": expected["content_type"]},
            content=expected["body"].encode("utf-8", errors="surrogateescape"),
        )


def llm_settings() -> LlmProxySettings:
    # Backoff only waits; it never changes a request, so replays skip it.
    return LlmProxySettings(
        base_url="https://proxy.example",
        api_key="synthetic-key",
        retry_backoff_seconds=0.001,
        retry_backoff_cap_seconds=0.001,
        _env_file=None,
    )


def service_settings() -> ServiceSettings:
    return ServiceSettings(
        api_token=TOKEN,
        allow_unencrypted_test_manifest=True,
        # The goldens were recorded with the manifest part in the response.
        return_manifest=True,
        request_deadline_seconds=SERVICE_DEADLINE_SECONDS,
        _env_file=None,
    )


class _LogCapture(logging.Handler):
    """Request lines logged by one asyncio task (other pages may run alongside)."""

    def __init__(self, task):
        super().__init__(logging.INFO)
        self.task = task
        self.lines: list[str] = []

    def emit(self, record):
        message = record.getMessage()
        if message.startswith("redact ") and asyncio.current_task() is self.task:
            self.lines.append(f"{record.levelname} {message}")


@contextmanager
def captured_request_log():
    handler = _LogCapture(asyncio.current_task())
    package_logger = logging.getLogger("pii_pipeline")
    package_logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        package_logger.removeHandler(handler)


# attempt_seconds holds wall-clock times; replays compare everything else.
_VOLATILE_LOG = re.compile(r"document_id=\S+ |seconds=[0-9.]+ |attempt_seconds=\S+ ")


def normalize_log(line: str) -> str:
    return _VOLATILE_LOG.sub("", line)


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _multipart(response: httpx.Response) -> dict[str, bytes]:
    message = BytesParser(policy=policy.HTTP).parsebytes(
        b"Content-Type: "
        + response.headers["content-type"].encode()
        + b"\r\n\r\n"
        + response.content
    )
    return {
        part.get_param("name", header="content-disposition"): part.get_payload(
            decode=True
        )
        for part in message.iter_parts()
    }


def normalize_response(response: httpx.Response) -> dict:
    """Byte-exact view of a service response with random IDs and time replaced."""
    if response.status_code != 200:
        body = response.json()
        if "document_id" in body:
            body["document_id"] = "<document_id>"
        return {
            "status": response.status_code,
            "content_type": response.headers.get("content-type"),
            "json": body,
        }
    parts = _multipart(response)
    metadata = json.loads(parts["metadata"])
    volatile = {
        metadata["document_id"]: "<document_id>",
        metadata["delivery_id"]: "<delivery_id>",
        metadata["created_at"]: "<timestamp>",
    }

    def stable(text: str) -> str:
        for value, label in volatile.items():
            text = text.replace(value, label)
        return text

    envelope = json.loads(parts["pii_manifest"])
    return {
        "status": 200,
        "content_type": response.headers["content-type"].split(";")[0],
        "part_names": list(parts),
        "redacted_md": parts["redacted_md"].decode("utf-8"),
        "metadata": stable(parts["metadata"].decode("utf-8")),
        "envelope_keys": list(envelope),
        "envelope_protected": _b64decode(envelope["protected"]).decode("utf-8"),
        "envelope_aad_is_metadata": _b64decode(envelope["aad"]) == parts["metadata"],
        "manifest": stable(_b64decode(envelope["ciphertext"]).decode("utf-8")),
    }


async def run_service(
    source: str, transport, *, body=None, headers=None, llm=None, deadline=None
) -> dict:
    """POST one page to the real service app; LLM traffic goes to ``transport``.

    ``llm`` and ``deadline`` are for recording real pages through the real
    proxy; requests do not depend on them, so replays use the defaults.
    """
    settings = service_settings()
    if deadline is not None:
        settings = settings.model_copy(update={"request_deadline_seconds": deadline})
    app = create_service_app(settings, llm or llm_settings(), llm_transport=transport)
    request_headers = {
        "content-type": "text/markdown; charset=utf-8",
        "authorization": f"Bearer {TOKEN}",
    }
    request_headers.update(headers or {})
    with captured_request_log() as lines:
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://service.local"
            ) as caller,
        ):
            response = await caller.post(
                "/redact",
                content=source.encode("utf-8") if body is None else body,
                headers=request_headers,
            )
    return {
        "response": normalize_response(response),
        "log": [normalize_log(x) for x in lines],
    }


def _whole(text):
    return [make_text_window(text, 0, len(text))]


async def run_pipeline(source: str, transport) -> dict:
    """The service's recovery pipeline called directly, with its progress events."""
    events: list[dict] = []
    async with LlmProxyClient(llm_settings(), transport=transport) as client:
        processor = LlmDocumentProcessor(client, _whole, _whole)
        try:
            result = await process_markdown_with_recovery_async(
                source,
                processor,
                rule_detectors=(detect_thai_rule_pii,),
                rules_has_pii=make_detection_checker([detect_thai_rule_pii]),
                policy=RecoveryPolicy(deadline_seconds=SERVICE_DEADLINE_SECONDS),
                progress=events.append,
            )
        except Exception as error:  # noqa: BLE001 - the failure itself is the output.
            outcome = {"error": f"{type(error).__name__}: {error}"}
        else:
            outcome = {
                "redacted_md": result.redacted_markdown,
                "entries": [
                    [e.placeholder, e.pii_type, e.occurrence_index, e.original_value]
                    for e in result.entries
                ],
            }
    return {**outcome, "events": events}


def cancelled_calls(calls: list[dict]) -> int:
    """Attempts cut by a deadline while recording; such pages cannot replay."""
    return sum(call.get("error") == CANCELLED for call in calls)
