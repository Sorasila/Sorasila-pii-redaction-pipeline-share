import asyncio
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs

import pytest
from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import pdf_to_pipeline as bridge

bridge.attach_pipeline(bridge.DEFAULT_PIPELINE)
import httpx

from pii_pipeline.llm.client import LlmProxyClient
from pii_pipeline.llm.config import LlmProxySettings


def pdf(path, pages):
    writer = canvas.Canvas(str(path))
    for text, image in pages:
        if text:
            writer.drawString(40, 700, text)
        if image:
            writer.drawImage(ImageReader(Image.new("RGB", (20, 20), "black")), 40, 600)
        writer.showPage()
    writer.save()


def setup_case(tmp_path, texts=None, *, cap=110, overlap=1, boundary="paragraph"):
    texts = texts or [
        "ชื่อ นายสมชาย ใจดี\n\nคดีหมายเลขดำที่ 123/2569\n",
        "ชื่อ นายสมหญิง ใจดี\n\nเลขที่ดิน 12345\n",
    ]
    input_pdf = tmp_path / "synthetic.pdf"
    pdf(input_pdf, [(f"Synthetic page {i}", False) for i in range(len(texts))])
    page_dir = tmp_path / "pages"
    page_dir.mkdir()
    for number, text in enumerate(texts, 1):
        bridge.write_text(page_dir / f"{number:04d}.txt", text)
    work = tmp_path / "work"
    bridge.prepare(
        input_pdf,
        work,
        window_chars=cap,
        overlap_blocks=overlap,
        max_windows=30,
        page_text_dir=page_dir,
        boundary=boundary,
    )
    return work


def settings():
    return LlmProxySettings(
        base_url="https://proxy.example",
        api_key="synthetic-key",
        _env_file=None,
        max_retries=0,
        detection_use_thinking=True,
    )


def response(output):
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": "qwen/qwen3.6-27b",
            "structured_output": output,
        },
    )


def handler(request):
    form = parse_qs(request.content.decode())
    source = form["context"][0]
    schema = json.loads(form["json_schema"][0])
    if "decisions" in schema["properties"]:
        return response(
            {
                "decisions": [
                    {"occurrence_id": item["occurrence_id"], "pii_type": "NAME"}
                    for item in json.loads(source)["occurrences"]
                ]
            }
        )
    if "candidates" in schema["properties"]:
        candidates = []
        for value in ("นายสมชาย ใจดี", "นายสมหญิง ใจดี"):
            if value in source:
                candidates.append({"pii_type": "NAME", "value": value})
        return response({"candidates": candidates})
    return response({"has_pii": False, "findings": []})


@pytest.mark.parametrize("cap", [1, 2])
def test_real_diagnostic_counts_selection_against_physical_request_cap(cap):
    events = []
    sent = []

    def wire(request):
        form = parse_qs(request.content.decode())
        sent.append(form)
        if "candidates" in json.loads(form["json_schema"][0])["properties"]:
            return response({"candidates": [{"pii_type": "NAME", "value": "Alpha"}]})
        return response(
            {
                "decisions": [
                    {"occurrence_id": 1, "pii_type": "NAME"},
                    {"occurrence_id": 2, "pii_type": "NOT_PII"},
                ]
            }
        )

    async def run():
        async with bridge.diagnostic_client_class()(
            settings(), transport=httpx.MockTransport(wire)
        ) as client:
            traced = bridge.TracedClient(client, cap, events.append)
            if cap == 1:
                with pytest.raises(bridge.TestInputError, match="CALL_CAP_EXCEEDED"):
                    await traced.detect("Name: Alpha; Product: Alpha", prompt="Extract")
                assert traced.failure_code == "CALL_CAP_EXCEEDED"
            else:
                matches = await traced.detect(
                    "Name: Alpha; Product: Alpha", prompt="Extract"
                )
                assert len(matches) == 1
            assert traced.request_count == cap
            assert traced.calls[0]["proxy_requests"] == cap
            assert len(traced.calls) == 1

    asyncio.run(run())
    assert len(sent) == cap
    requests = [event for event in events if event["event"] == "PROXY_REQUEST_STARTED"]
    assert [item["role"] for item in requests] == ["detect", "select"][:cap]
    assert "Alpha" not in repr(events)


@pytest.mark.parametrize(
    "error_type,kind",
    [
        (httpx.ReadTimeout, "READ_TIMEOUT"),
        (httpx.ConnectTimeout, "CONNECT_TIMEOUT"),
        (httpx.WriteTimeout, "WRITE_TIMEOUT"),
        (httpx.PoolTimeout, "POOL_TIMEOUT"),
        (httpx.ConnectError, "CONNECT_ERROR"),
        (httpx.ReadError, "READ_ERROR"),
        (httpx.WriteError, "WRITE_ERROR"),
        (httpx.RemoteProtocolError, "PROTOCOL_ERROR"),
        (RuntimeError, "OTHER_TRANSPORT_ERROR"),
    ],
)
def test_transport_diagnostics_keep_kind_and_budgets_without_private_data(
    tmp_path, error_type, kind
):
    work = setup_case(tmp_path)
    bridge.review(work, [])
    source, meta, plan = bridge.read_prepared(work, require_review=True)
    events = []
    sent = []

    def broken(request):
        sent.append(1)
        error = error_type("Private failure text synthetic-key https://private.invalid")
        error.__cause__ = ValueError("Private cause text")
        raise error

    async def run():
        from pii_pipeline.recovery.process import RecoveryPolicy

        async with bridge.diagnostic_client_class()(
            settings(), transport=httpx.MockTransport(broken)
        ) as client:
            with pytest.raises(bridge.CoreRunError) as captured:
                await bridge.execute_core(
                    source,
                    meta,
                    plan,
                    client,
                    bridge.RunBudget(40, 20, 30),
                    events.append,
                    # One call only: the failed detection is the whole run.
                    recovery_policy=RecoveryPolicy(
                        max_role_calls=1, window_repair_attempts=0
                    ),
                )
            return captured.value

    error = asyncio.run(run())
    # Recovery keeps going after a recoverable failure; the one-call budget then
    # stops the run at verification. Fatal transport errors stop it at once.
    # Either way the transport failure stays in calls[0].
    fatal = kind in {"PROTOCOL_ERROR", "OTHER_TRANSPORT_ERROR"}
    assert str(error) == (
        "PROXY_TRANSPORT_ERROR" if fatal else "LLM_VERIFICATION_REJECTED"
    )
    assert error.report["calls"][0]["status"] == "PROXY_TRANSPORT_ERROR"
    assert error.report["calls"][0]["transport_kind"] == kind
    assert error.report["proxy_request_count"] == 1
    assert len(error.report["calls"]) == 1
    assert "http_status" not in error.report["calls"][0]
    request = next(e for e in events if e["event"] == "PROXY_REQUEST_STARTED")
    assert request["request_timeouts_seconds"]["read"] == 300
    assert set(request["request_timeouts_seconds"]) == {
        "connect",
        "read",
        "write",
        "pool",
    }
    diagnostics = json.dumps({"events": events, "report": error.report})
    for private in ("Private", "synthetic-key", "private.invalid", "นายสมชาย"):
        assert private not in diagnostics
    assert sent == [1]
    assert not (work / "results").exists()


def test_timeout_diagnostics_reject_strings_nonfinite_and_bool():
    assert bridge.safe_timeout_diagnostics(
        {"connect": "Private value", "read": float("inf"), "write": True, "pool": 10}
    ) == {"pool": 10}
    assert bridge.safe_timeout_diagnostics(
        {"connect": -1, "read": float("nan"), "write": 0, "pool": 1.5, "key": "Private"}
    ) == {"pool": 1.5}


def test_real_pdf_extraction_all_pages(tmp_path):
    source_pdf = tmp_path / "synthetic.pdf"
    pdf(source_pdf, [("First page", False), ("Second page", False)])
    work = tmp_path / "work"
    report = bridge.prepare(
        source_pdf, work, window_chars=100, overlap_blocks=1, max_windows=10
    )
    assert report["pages_total"] == 2
    source, meta, plan = bridge.read_prepared(work, require_review=False)
    assert source == "First page\n\n\nSecond page\n"
    assert [source[p["start"] : p["end"]] for p in meta["pages"]] == [
        "First page\n",
        "Second page\n",
    ]
    assert not plan["reviewed"]


def test_nfc_and_newlines_preserved(tmp_path):
    work = setup_case(tmp_path, ["Name e\u0301\r\n\r\n", "Thai ก้\r\n"])
    source, meta, _ = bridge.read_prepared(work, require_review=False)
    assert "é\r\n\r\n" in source
    assert "e\u0301" in bridge.read_text(work / "source.raw.md")
    assert meta["pages"][1]["start"] == meta["pages"][0]["end"] + 2


@pytest.mark.parametrize("image", [False, True])
def test_blank_or_scan_page_blocks_review(tmp_path, image):
    source_pdf = tmp_path / "synthetic.pdf"
    pdf(source_pdf, [("First page", False), (None, image)])
    work = tmp_path / "work"
    report = bridge.prepare(
        source_pdf, work, window_chars=100, overlap_blocks=1, max_windows=10
    )
    assert report["pages_needing_ocr_or_blank_review"] == 1
    with pytest.raises(bridge.TestInputError, match="OCR_REQUIRED"):
        bridge.review(work, [])
    assert not bridge.load_json(work / "pages.json")["pages"][0]["reviewed"]
    # Only a human can distinguish a genuinely blank page from a scan.
    bridge.review(work, [2])
    bridge.read_prepared(work, require_review=True)


def test_mixed_page_still_requires_human_review(tmp_path):
    source_pdf = tmp_path / "synthetic.pdf"
    pdf(source_pdf, [("Synthetic text and image", True)])
    work = tmp_path / "work"
    bridge.prepare(source_pdf, work, window_chars=100, overlap_blocks=1, max_windows=10)
    with pytest.raises(bridge.TestInputError, match="PAGE_REVIEW_REQUIRED"):
        bridge.read_prepared(work, require_review=True)


@pytest.mark.parametrize("kind", ["encrypted", "malformed"])
def test_pdf_errors_sanitized_in_cli(tmp_path, capsys, kind):
    source_pdf = tmp_path / "synthetic-private.pdf"
    if kind == "encrypted":
        pdf(source_pdf, [("Sensitive synthetic value", False)])
        writer = PdfWriter()
        writer.append(PdfReader(source_pdf))
        writer.encrypt("synthetic-password")
        writer.write(source_pdf)
    else:
        source_pdf.write_bytes(b"not a PDF Sensitive synthetic value")
    code = bridge.main(
        [
            "prepare",
            "--pdf",
            str(source_pdf),
            "--work-dir",
            str(tmp_path / "work"),
            "--window-chars",
            "100",
            "--max-windows",
            "10",
        ]
    )
    output = capsys.readouterr()
    assert code == 1
    assert "synthetic-password" not in output.out + output.err
    assert "Sensitive synthetic value" not in output.out + output.err
    assert str(source_pdf) not in output.out + output.err
    assert not (tmp_path / "work").exists()


def test_ocr_import_requires_every_page(tmp_path):
    source_pdf = tmp_path / "synthetic.pdf"
    pdf(source_pdf, [(None, True), (None, True)])
    pages = tmp_path / "pages"
    pages.mkdir()
    bridge.write_text(pages / "0001.txt", "Synthetic OCR\n")
    with pytest.raises(
        bridge.TestInputError, match="PAGE_TEXT_FILES_MUST_MATCH_ALL_PAGES"
    ):
        bridge.prepare(
            source_pdf,
            tmp_path / "work",
            window_chars=100,
            overlap_blocks=1,
            max_windows=10,
            page_text_dir=pages,
        )
    bridge.write_text(pages / "0002.txt", "More synthetic OCR\n")
    bridge.prepare(
        source_pdf,
        tmp_path / "work",
        window_chars=100,
        overlap_blocks=1,
        max_windows=10,
        page_text_dir=pages,
    )


def test_plan_preserves_characters_and_overlap():
    source = "alpha\n\nbeta\n\ngamma\n\ndelta"
    ranges = bridge.plan_ranges(source, 15, 1, 10)
    bridge.validate_ranges(source, ranges, 15, 10)
    assert any(ranges[i]["start"] < ranges[i - 1]["end"] for i in range(1, len(ranges)))
    covered = set()
    for r in ranges:
        covered.update(range(r["start"], r["end"]))
    assert covered == set(range(len(source)))


def test_long_block_not_blindly_split(tmp_path):
    work = setup_case(tmp_path, ["x" * 150], cap=100)
    plan = bridge.load_json(work / "detection-windows.json")
    assert plan["windows"] == []
    assert plan["planning_error"] == "BLOCK_EXCEEDS_WINDOW"
    with pytest.raises(bridge.TestInputError, match="WINDOW_PLAN_REQUIRED"):
        bridge.review(work, [])


@pytest.mark.parametrize(
    "ranges",
    [
        [],
        [{"start": 1, "end": 10}],
        [{"start": 0, "end": 10}, {"start": 11, "end": 20}],
        [{"start": True, "end": 20}],
        [{"start": 0, "end": 21}],
        [{"start": 0, "end": 20}, {"start": 0, "end": 20}],
    ],
)
def test_bad_windows_rejected(ranges):
    with pytest.raises(bridge.TestInputError):
        bridge.validate_ranges("x" * 20, ranges, 20, 10)


@pytest.mark.parametrize(
    "file,change",
    [
        ("source.md", lambda text: text + "tampered"),
        ("source.raw.md", lambda text: text + "tampered"),
        ("pages.json", lambda text: text.replace('"page": 1', '"page": 99')),
        (
            "detection-windows.json",
            lambda text: text.replace('"start": 0', '"start": 1'),
        ),
    ],
)
def test_tampering_blocks_live_before_settings(tmp_path, monkeypatch, file, change):
    work = setup_case(tmp_path)
    bridge.review(work, [])
    target = work / file
    target.write_text(change(bridge.read_text(target)), encoding="utf-8")
    monkeypatch.setattr(
        bridge,
        "attach_pipeline",
        lambda path: pytest.fail("Must not import/configure client"),
    )
    with pytest.raises(bridge.TestInputError):
        asyncio.run(
            bridge.run_live(
                work,
                bridge.DEFAULT_PIPELINE,
                tmp_path / "missing.env",
                bridge.RunBudget(40, 20, 30),
            )
        )


def test_work_paths_and_existing_preparation(tmp_path):
    for path in (bridge.HERE, bridge.HERE / "data", bridge.DEFAULT_PIPELINE / "data"):
        with pytest.raises(
            bridge.TestInputError, match="WORK_DIR_MUST_BE_OUTSIDE_CODE"
        ):
            bridge.private_work_dir(path, bridge.DEFAULT_PIPELINE)
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").write_text("gitdir: elsewhere")
    with pytest.raises(bridge.TestInputError, match="WORK_DIR_MUST_BE_OUTSIDE_GIT"):
        bridge.private_work_dir(root / "data", bridge.DEFAULT_PIPELINE)
    work = setup_case(tmp_path)
    with pytest.raises(bridge.TestInputError, match="WORK_DIR_ALREADY_EXISTS"):
        bridge.prepare(
            tmp_path / "missing.pdf",
            work,
            window_chars=100,
            overlap_blocks=1,
            max_windows=10,
        )


async def run_case(work, callback=handler, *, budget=None, recovery_policy=None):
    from pii_pipeline.recovery.process import RecoveryPolicy

    source, meta, plan = bridge.read_prepared(work, require_review=True)
    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(callback)
    ) as client:
        return await bridge.execute_core(
            source,
            meta,
            plan,
            client,
            budget or bridge.RunBudget(40, 20, 30),
            recovery_policy=recovery_policy or RecoveryPolicy(),
        )


def test_recovery_core_retains_good_value_and_repairs_copy_error(tmp_path):
    from pii_pipeline.recovery.process import RecoveryPolicy

    work = setup_case(tmp_path, ["Name Alice phone 123"], cap=200)
    bridge.review(work, [])
    calls = []

    def wire(request):
        form = parse_qs(request.content.decode())
        role = next(iter(json.loads(form["json_schema"][0])["properties"]))
        calls.append(role)
        if role == "candidates":
            values = [
                {"pii_type": "NAME", "value": "Alicee" if len(calls) == 1 else "Alice"}
            ]
            if len(calls) == 1:
                values.append({"pii_type": "PHONE", "value": "123"})
            return response({"candidates": values})
        return response({"has_pii": False, "findings": []})

    redacted, summary = asyncio.run(
        run_case(work, wire, recovery_policy=RecoveryPolicy())
    )
    assert "Alice" not in redacted and "123" not in redacted
    assert summary["entries_by_type"] == {"NAME": 1, "PHONE": 1}
    assert summary["recovery"]["recovery_calls"] == 1
    assert summary["calls"][0]["status"] == "DETECTION_ISSUES"
    assert calls == ["candidates", "candidates", "has_pii"]
    assert "Alicee" not in json.dumps(summary)
    assert not (work / "results").exists()


def test_recovery_still_blocks_failed_final_verification(tmp_path):
    from pii_pipeline.recovery.process import RecoveryPolicy

    work = setup_case(tmp_path, ["Name Alice"], cap=200)
    bridge.review(work, [])
    calls = []

    def wire(request):
        role = next(
            iter(
                json.loads(parse_qs(request.content.decode())["json_schema"][0])[
                    "properties"
                ]
            )
        )
        calls.append(role)
        if role == "candidates":
            return response({"candidates": [{"pii_type": "NAME", "value": "Alice"}]})
        raise httpx.ReadTimeout("Sensitive synthetic failure")

    with pytest.raises(bridge.CoreRunError):
        asyncio.run(run_case(work, wire, recovery_policy=RecoveryPolicy()))
    assert calls == ["candidates", "has_pii", "has_pii"]
    assert not (work / "results").exists()


@pytest.mark.parametrize("changed", ["boundary", "type"])
def test_repair_merge_rejection_reports_reason_without_pii_or_output(tmp_path, changed):
    from pii_pipeline.recovery.process import RecoveryPolicy

    work = setup_case(tmp_path, ["Alice Smith"], cap=200)
    bridge.review(work, [])
    source, meta, plan = bridge.read_prepared(work, require_review=True)
    roles, events = [], []

    def wire(request):
        form = parse_qs(request.content.decode())
        role = next(iter(json.loads(form["json_schema"][0])["properties"]))
        roles.append(role)
        assert role == "candidates"
        initial = len(roles) == 1
        kind = "ORGANIZATION" if not initial and changed == "type" else "NAME"
        value = "Alice" if initial and changed == "boundary" else "Alice Smith"
        missing = ["Absent One", "Absent Two"] if initial else ["Absent Three"]
        return response(
            {
                "candidates": [
                    {"pii_type": kind, "value": value},
                    *[{"pii_type": "NAME", "value": item} for item in missing],
                ]
            }
        )

    async def run():
        async with bridge.diagnostic_client_class()(
            settings(), transport=httpx.MockTransport(wire)
        ) as client:
            return await bridge.execute_core(
                source,
                meta,
                plan,
                client,
                bridge.RunBudget(8, 4, 30),
                events.append,
                recovery_policy=RecoveryPolicy(conflict_selection_attempts=0),
            )

    with pytest.raises(bridge.CoreRunError, match="DETECTION_MERGE_REJECTED") as caught:
        asyncio.run(run())
    report = caught.value.report
    assert report["reason_code"] == "source_span_conflict"
    assert report["stage"] == "detection_merge_or_redaction"
    assert report["proxy_request_count"] == 2 and report["verification_windows"] == 0
    assert [call["issue_count"] for call in report["calls"]] == [2, 1]
    assert report["recovery"]["merge_diagnostics"] == {
        "window_number": 1,
        "attempt": 2,
        "recovery": True,
        "retained_matches": 1,
        "incoming_matches": 1,
    }
    assert events[-1]["event"] == "DETECTION_WINDOW_REJECTED"
    assert roles == ["candidates", "candidates"]
    assert not (work / "results").exists()
    diagnostics = json.dumps({"events": events, "report": report})
    for private in (
        "Alice",
        "Smith",
        "Absent",
        "synthetic-key",
        "https://proxy.example",
    ):
        assert private not in diagnostics


def test_recovery_counts_every_selection_request_at_physical_cap(tmp_path):
    from pii_pipeline.recovery.process import RecoveryPolicy

    work = setup_case(tmp_path, ["Alice Alice"], cap=200)
    bridge.review(work, [])
    source, meta, plan = bridge.read_prepared(work, require_review=True)
    calls = []

    def wire(request):
        calls.append(1)
        return response({"candidates": [{"pii_type": "NAME", "value": "Alice"}]})

    async def run():
        async with bridge.diagnostic_client_class()(
            settings(), transport=httpx.MockTransport(wire)
        ) as client:
            return await bridge.execute_core(
                source,
                meta,
                plan,
                client,
                bridge.RunBudget(2, 5, 30),
                recovery_policy=RecoveryPolicy(),
            )

    with pytest.raises(bridge.CoreRunError, match="CALL_CAP_EXCEEDED") as caught:
        asyncio.run(run())
    assert len(calls) == 2 and caught.value.report["proxy_request_count"] == 2
    assert not (work / "results").exists()


def test_forced_rule_conflict_preserves_case_label_without_selection_request(
    tmp_path,
):
    from pii_pipeline.recovery.process import RecoveryPolicy

    work = setup_case(tmp_path, ["คดีหมายเลขดำที่ 123/2569"], cap=200)
    bridge.review(work, [])
    source, meta, plan = bridge.read_prepared(work, require_review=True)
    roles, events = [], []

    def wire(request):
        form = parse_qs(request.content.decode())
        role = next(iter(json.loads(form["json_schema"][0])["properties"]))
        roles.append(role)
        context = form["context"][0]
        if role == "candidates":
            return response(
                {"candidates": [{"pii_type": "CASE_NUMBER", "value": context}]}
            )
        # The mandatory rule span leaves one legal option, resolved locally.
        assert role == "has_pii"
        assert context == "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1]"
        return response({"has_pii": False, "findings": []})

    async def run():
        async with bridge.diagnostic_client_class()(
            settings(), transport=httpx.MockTransport(wire)
        ) as client:
            return await bridge.execute_core(
                source,
                meta,
                plan,
                client,
                # Exactly extraction + verification; the old selection needed 3.
                bridge.RunBudget(2, 4, 30),
                events.append,
                recovery_policy=RecoveryPolicy(),
            )

    redacted, report = asyncio.run(run())
    assert redacted == "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1]"
    assert report["entries_by_type"] == {"CASE_NUMBER": 1}
    assert report["recovery"]["conflict_selection_calls"] == 0
    assert report["recovery"]["recovery_calls"] == 0
    assert roles == ["candidates", "has_pii"]
    forced = [e for e in events if e["event"] == "CONFLICT_SELECTION_FORCED"]
    assert forced and forced[0]["scope"] == "document"
    assert report["proxy_request_count"] == 2
    assert not (work / "results").exists()
    assert "123/2569" not in json.dumps({"events": events, "report": report})


def test_live_single_window_runs_recovery_and_verification_without_publishing(
    tmp_path, monkeypatch
):
    from pii_pipeline.llm import config as llm_config

    work = setup_case(tmp_path, ["Name Alice", "Name Bob"], cap=25, overlap=0)
    bridge.review(work, [])
    calls = []

    def wire(request):
        form = parse_qs(request.content.decode())
        role = next(iter(json.loads(form["json_schema"][0])["properties"]))
        calls.append(role)
        return (
            response({"candidates": []})
            if role == "candidates"
            else response({"has_pii": False, "findings": []})
        )

    diagnostic = bridge.diagnostic_client_class()
    monkeypatch.setattr(
        bridge,
        "diagnostic_client_class",
        lambda: lambda config: diagnostic(config, transport=httpx.MockTransport(wire)),
    )
    monkeypatch.setattr(llm_config, "LlmProxySettings", lambda **kwargs: settings())
    monkeypatch.setattr(
        bridge, "publish", lambda *args: pytest.fail("Isolated scope must not publish")
    )
    result = asyncio.run(
        bridge.run_live(
            work,
            bridge.DEFAULT_PIPELINE,
            tmp_path / "unused.env",
            bridge.RunBudget(8, 4, 30),
            window_number=1,
        )
    )
    assert result["status"] == "CORE_WINDOW_VERIFIED"
    assert result["scope"] == "prepared_window" and result["verification_performed"]
    assert not result["outputs_published"] and result["detection_windows"] == 1
    assert calls == ["candidates", "has_pii"]


def test_core_cli_passes_window_and_recovery_limits(tmp_path, monkeypatch, capsys):
    work = setup_case(tmp_path)
    seen = []

    async def fake_run(*args):
        seen.append(args[-4:])
        return {"status": "synthetic"}

    monkeypatch.setattr(bridge, "run_live", fake_run)
    command = [
        "run-core",
        "--work-dir",
        str(work),
        "--allow-proxy-upload",
        "--max-calls",
        "8",
        "--max-verification-windows",
        "4",
        "--run-deadline-seconds",
        "1200",
        "--max-recovery-calls",
        "2",
        "--max-residual-rounds",
        "1",
        "--window-number",
        "10",
    ]
    assert bridge.main(command) == 0
    assert bridge.main([*command, "--reserved-recovery-calls", "1"]) == 0
    # Default reserve 0 keeps the previous shared first-come allocation.
    assert seen == [(2, 1, 10, 0), (2, 1, 10, 1)]


def test_live_reserved_recovery_calls_reach_policy(tmp_path, monkeypatch):
    from pii_pipeline.llm import config as llm_config
    from pii_pipeline.recovery import process as llm_recovery

    work = setup_case(tmp_path, ["Name Alice"], cap=25, overlap=0)
    bridge.review(work, [])
    policies = []
    original = llm_recovery.process_markdown_with_recovery_async

    async def capture(*args, policy, **kwargs):
        policies.append(policy)
        return await original(*args, policy=policy, **kwargs)

    def wire(request):
        form = parse_qs(request.content.decode())
        role = next(iter(json.loads(form["json_schema"][0])["properties"]))
        return (
            response({"candidates": []})
            if role == "candidates"
            else response({"has_pii": False, "findings": []})
        )

    diagnostic = bridge.diagnostic_client_class()
    monkeypatch.setattr(
        bridge,
        "diagnostic_client_class",
        lambda: lambda config: diagnostic(config, transport=httpx.MockTransport(wire)),
    )
    monkeypatch.setattr(llm_config, "LlmProxySettings", lambda **kwargs: settings())
    monkeypatch.setattr(llm_recovery, "process_markdown_with_recovery_async", capture)
    asyncio.run(
        bridge.run_live(
            work,
            bridge.DEFAULT_PIPELINE,
            tmp_path / "unused.env",
            bridge.RunBudget(8, 4, 30),
            max_recovery_calls=3,
            window_number=1,
            reserved_recovery_calls=2,
        )
    )
    assert [(p.max_recovery_calls, p.reserved_recovery_calls) for p in policies] == [
        (3, 2)
    ]


def test_actual_client_core_multiple_windows_global_counters(tmp_path):
    work = setup_case(tmp_path, cap=75)
    bridge.review(work, [])
    redacted, summary = asyncio.run(run_case(work))
    assert "[PII_NAME_1]" in redacted and "[PII_NAME_2]" in redacted
    assert "นายสมชาย" not in redacted and "นายสมหญิง" not in redacted
    assert "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1]" in redacted
    assert "เลขที่ดิน [PII_LAND_PARCEL_NUMBER_1]" in redacted
    assert summary["entries_by_type"] == {
        "CASE_NUMBER": 1,
        "LAND_PARCEL_NUMBER": 1,
        "NAME": 2,
    }
    assert summary["detection_windows"] > 1 and summary["verification_windows"] > 1
    assert summary["full_window_coverage"] and not summary["manifest_exported"]
    assert summary["human_accuracy_evaluation"] == "NOT_PERFORMED"
    assert "นายสมชาย" not in json.dumps(summary, ensure_ascii=False)
    published = bridge.publish(work, redacted, summary)
    destination = work / "results" / published["run_id"]
    assert sorted(p.name for p in destination.iterdir()) == [
        "redacted.md",
        "summary.json",
    ]
    assert bridge.read_text(destination / "redacted.md") == redacted


def test_verification_receives_fresh_redacted_source(tmp_path):
    work = setup_case(tmp_path, cap=75)
    bridge.review(work, [])
    inputs = []

    def capture(request):
        form = parse_qs(request.content.decode())
        if "has_pii" in json.loads(form["json_schema"][0])["properties"]:
            inputs.append(form["context"][0])
        return handler(request)

    redacted, _ = asyncio.run(run_case(work, capture))
    assert inputs and all(text in redacted for text in inputs)
    assert all("นายสมชาย" not in text and "นายสมหญิง" not in text for text in inputs)
    assert any("[PII_NAME_" in text for text in inputs)


# With recovery a failed detection is repaired or cleared by the final
# verification (tested in tests/test_llm_recovery.py); a failed verification
# with no retry budget must stop the run without publishing anything.
@pytest.mark.parametrize("failure", ["504", "timeout", "invalid", "residual"])
def test_failed_verification_never_publishes_without_retry_budget(tmp_path, failure):
    from pii_pipeline.recovery.process import RecoveryPolicy

    stage = "verify"
    work = setup_case(tmp_path, cap=75)
    bridge.review(work, [])
    calls = []
    verified = []

    def broken(request):
        form = parse_qs(request.content.decode())
        role = (
            "detect"
            if "candidates" in json.loads(form["json_schema"][0])["properties"]
            else "verify"
        )
        calls.append(role)
        if role != stage:
            return handler(request)
        verified.append(form["context"][0])
        if failure == "504":
            return httpx.Response(504, text="Sensitive synthetic failure")
        if failure == "timeout":
            raise httpx.ReadTimeout("Sensitive synthetic failure")
        if failure == "invalid":
            return response({"unknown": "Sensitive synthetic failure"})
        if failure == "anchor":
            return response(
                {
                    "candidates": [
                        {"pii_type": "NAME", "value": "invented", "anchor": "invented"}
                    ]
                }
            )
        if stage == "detect":
            return response({"candidates": "invalid"})
        return response({"has_pii": True, "findings": [{"pii_type": "NAME"}]})

    no_retries = RecoveryPolicy(
        window_repair_attempts=0,
        verification_retry_attempts=0,
        max_residual_rounds=0,
        blank_response_retries=0,
    )
    with pytest.raises(bridge.TestInputError) as captured:
        asyncio.run(run_case(work, broken, recovery_policy=no_retries))
    assert "Sensitive" not in str(captured.value)
    # No window is sent twice; a failed reply stops at its first window, a
    # residual finding is reported by every verification window.
    assert len(verified) == len(set(verified))
    assert len(verified) == 1 or failure == "residual"
    assert not (work / "results").exists()


@pytest.mark.parametrize(
    "budget",
    [
        bridge.RunBudget(1, 10, 30),
        bridge.RunBudget(True, 10, 30),
        bridge.RunBudget(30, 0, 30),
        bridge.RunBudget(30, 10, -1),
    ],
)
def test_invalid_budget_no_calls(tmp_path, budget):
    work = setup_case(tmp_path)
    bridge.review(work, [])
    with pytest.raises(bridge.TestInputError):
        asyncio.run(
            run_case(work, lambda req: pytest.fail("No network"), budget=budget)
        )


def test_verification_call_cap_blocks_whole_role(tmp_path):
    work = setup_case(tmp_path, cap=75)
    bridge.review(work, [])
    _, _, plan = bridge.read_prepared(work, require_review=True)
    calls = []

    def capture(request):
        form = parse_qs(request.content.decode())
        assert "candidates" in json.loads(form["json_schema"][0])["properties"]
        calls.append(1)
        return handler(request)

    with pytest.raises(bridge.TestInputError, match="CALL_CAP_EXCEEDED"):
        asyncio.run(
            run_case(
                work, capture, budget=bridge.RunBudget(len(plan["windows"]) + 1, 20, 30)
            )
        )
    assert len(calls) == len(plan["windows"])
    assert not (work / "results").exists()


def test_external_cancellation_and_whole_deadline(tmp_path):
    work = setup_case(tmp_path)
    bridge.review(work, [])

    async def test():
        async def slow(request):
            await asyncio.sleep(5)
            return handler(request)

        task = asyncio.create_task(run_case(work, slow))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(bridge.TestInputError, match="WHOLE_RUN_TIMEOUT"):
            await run_case(work, slow, budget=bridge.RunBudget(40, 20, 1))

    asyncio.run(test())
    assert not (work / "results").exists()


def test_atomic_publish_rolls_back_on_write_error(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    original = bridge.write_text

    def broken(path, text):
        if path.name == "summary.json":
            raise OSError("Sensitive synthetic failure")
        original(path, text)

    monkeypatch.setattr(bridge, "write_text", broken)
    with pytest.raises(OSError):
        bridge.publish(work, "Sensitive synthetic value", {})
    assert list((work / "results").iterdir()) == []


def test_cli_errors_no_paths_values_or_keys(capsys):
    assert (
        bridge.main(
            ["prepare", "--pdf", "private-path-secret", "--unexpected", "sensitive"]
        )
        == 1
    )
    output = capsys.readouterr()
    assert (
        output.out.strip() == '{"status": "STOPPED", "error_code": "INVALID_ARGUMENTS"}'
    )
    assert output.err == ""


def test_help_and_import_do_not_load_settings(monkeypatch, capsys):
    monkeypatch.setattr(
        bridge, "attach_pipeline", lambda path: pytest.fail("No pipeline access")
    )
    with pytest.raises(SystemExit) as captured:
        bridge.main(["--help"])
    assert captured.value.code == 0
    assert "prepare" in capsys.readouterr().out
    spec = importlib.util.spec_from_file_location(
        "bridge_import_only", HERE / "pdf_to_pipeline.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module.VERSION == bridge.VERSION


def test_unreviewed_pages_block_client_creation(tmp_path, monkeypatch):
    work = setup_case(tmp_path)
    monkeypatch.setattr(
        bridge, "attach_pipeline", lambda path: pytest.fail("No client configuration")
    )
    with pytest.raises(bridge.TestInputError, match="PAGE_REVIEW_REQUIRED"):
        asyncio.run(
            bridge.run_live(
                work,
                bridge.DEFAULT_PIPELINE,
                tmp_path / "missing.env",
                bridge.RunBudget(40, 20, 30),
            )
        )


def test_cannot_declare_text_page_blank(tmp_path):
    work = setup_case(tmp_path)
    with pytest.raises(bridge.TestInputError, match="INVALID_BLANK_PAGE"):
        bridge.review(work, [1])


def test_reserved_placeholder_rejected_before_settings(tmp_path, monkeypatch):
    work = setup_case(tmp_path, ["Synthetic [PII_NAME_1] source"])
    bridge.review(work, [])
    from pii_pipeline.llm.config import LlmProxySettings

    monkeypatch.setattr(
        LlmProxySettings,
        "__init__",
        lambda *args, **kwargs: pytest.fail("No secrets read"),
    )
    with pytest.raises(ValueError, match="placeholder"):
        asyncio.run(
            bridge.run_live(
                work,
                bridge.DEFAULT_PIPELINE,
                tmp_path / "missing.env",
                bridge.RunBudget(40, 20, 30),
            )
        )


def test_verification_expansion_not_split_mid_field(tmp_path):
    work = setup_case(tmp_path, ["เลขที่ดิน 1"], cap=20)
    bridge.review(work, [])
    calls = []

    def capture(request):
        calls.append(request)
        return handler(request)

    with pytest.raises(bridge.TestInputError, match="BLOCK_EXCEEDS_WINDOW"):
        asyncio.run(run_case(work, capture))
    assert len(calls) == 1  # detection only; no verification after a bad plan
    assert not (work / "results").exists()


def test_overlapping_name_duplicates_do_not_add_entries(tmp_path):
    work = setup_case(tmp_path, ["ชื่อ นายสมชาย ใจดี\n\nชื่อ นายสมหญิง ใจดี\n\nEnd"], cap=42)
    bridge.review(work, [])
    source, _, plan = bridge.read_prepared(work, require_review=True)
    assert (
        sum("นายสมหญิง ใจดี" in source[w["start"] : w["end"]] for w in plan["windows"])
        == 2
    )
    redacted, summary = asyncio.run(run_case(work))
    assert summary["entries_by_type"] == {"NAME": 2}
    assert redacted.count("[PII_NAME_2]") == 1


def test_verification_window_cap_blocks_before_any_verify(tmp_path):
    work = setup_case(tmp_path, cap=75)
    bridge.review(work, [])
    calls = []

    def capture(request):
        form = parse_qs(request.content.decode())
        assert "candidates" in json.loads(form["json_schema"][0])["properties"]
        calls.append(1)
        return handler(request)

    with pytest.raises(bridge.TestInputError, match="WINDOW_CAP_EXCEEDED"):
        asyncio.run(run_case(work, capture, budget=bridge.RunBudget(40, 1, 30)))
    assert calls


def test_whitespace_only_window_rejected():
    with pytest.raises(bridge.TestInputError, match="EMPTY_WINDOW"):
        bridge.validate_ranges(
            "  text", [{"start": 0, "end": 2}, {"start": 2, "end": 6}], 10, 10
        )


def test_opt_in_line_policy_preserves_crlf_and_fresh_coverage(tmp_path):
    text = "".join(f"Synthetic {index}\r\n" for index in range(6))
    work = setup_case(tmp_path, [text], cap=40, boundary="line")
    bridge.review(work, [])
    source, _, plan = bridge.read_prepared(work, require_review=True)
    for window in plan["windows"]:
        assert window["start"] == 0 or source[: window["start"]].endswith("\r\n")
        assert source[: window["end"]].endswith("\r\n")
    redacted, summary = asyncio.run(run_case(work))
    assert redacted == text and summary["entries_by_type"] == {}
    assert summary["detection_windows"] > 1


@pytest.mark.parametrize("policy", ["guessed", None])
def test_invalid_boundary_policy_rejected(policy):
    with pytest.raises(bridge.TestInputError, match="INVALID_BOUNDARY_POLICY"):
        bridge.plan_ranges("synthetic", 100, 1, 10, policy)


def test_real_cli_help_works_with_ascii_console():
    environment = dict(os.environ, PYTHONIOENCODING="ascii")
    result = subprocess.run(
        [sys.executable, str(HERE / "pdf_to_pipeline.py"), "--help"],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    assert result.returncode == 0
    assert "prepare" in result.stdout and result.stderr == ""


def test_paragraph_policy_recognizes_crlf_blank_lines():
    source = "alpha\r\n\r\nbeta\r\n\r\ngamma"
    ranges = bridge.plan_ranges(source, 20, 1, 10)
    bridge.validate_ranges(source, ranges, 20, 10)
    assert len(ranges) == 2
    assert ranges[1]["start"] == len("alpha\r\n\r\n")


def test_whole_document_over_ingress_limit_uses_core_not_http(tmp_path):
    filler = "Synthetic unrelated paragraph 0123456789\n\n" * 15
    work = setup_case(
        tmp_path,
        ["ชื่อ นายสมชาย ใจดี\n\n" + filler, filler + "ชื่อ นายสมหญิง ใจดี\n"],
        cap=180,
    )
    bridge.review(work, [])
    redacted, summary = asyncio.run(run_case(work))
    assert summary["source_characters"] > 1000 and summary["pages_total"] == 2
    assert summary["entries_by_type"] == {"NAME": 2}
    assert "[PII_NAME_1]" in redacted and "[PII_NAME_2]" in redacted
    assert summary["test_budgets"]["max_calls"] == 40


def test_alternate_extractor_reads_all_pages_and_records_provenance(tmp_path):
    source_pdf = tmp_path / "synthetic.pdf"
    pdf(source_pdf, [("First page", False), ("Second page", False)])
    work = tmp_path / "work"
    report = bridge.prepare(
        source_pdf,
        work,
        window_chars=100,
        overlap_blocks=1,
        max_windows=10,
        extractor="pdfplumber",
    )
    assert report["conversion"] == "pdfplumber-plain"
    source, meta, _ = bridge.read_prepared(work, require_review=False)
    assert source == "First page\n\nSecond page"
    assert len(meta["pages"]) == 2
    assert meta["conversion"] == "pdfplumber-plain"
    bridge.review(work, [])


def test_alternate_extractor_scan_page_still_requires_ocr(tmp_path):
    source_pdf = tmp_path / "synthetic.pdf"
    pdf(source_pdf, [("First page", False), (None, True)])
    work = tmp_path / "work"
    report = bridge.prepare(
        source_pdf,
        work,
        window_chars=100,
        overlap_blocks=1,
        max_windows=10,
        extractor="pdfplumber",
    )
    assert report["pages_needing_ocr_or_blank_review"] == 1
    with pytest.raises(bridge.TestInputError, match="OCR_REQUIRED"):
        bridge.review(work, [])


@pytest.mark.parametrize("extractor", ["pypdf", "pdfplumber"])
def test_encrypted_pdf_prompt_passed_to_selected_extractor(
    tmp_path, monkeypatch, extractor
):
    source_pdf = tmp_path / "synthetic.pdf"
    pdf(source_pdf, [("Synthetic protected text", False)])
    writer = PdfWriter()
    writer.append(PdfReader(source_pdf))
    writer.encrypt("synthetic-password")
    writer.write(source_pdf)
    monkeypatch.setattr(bridge.getpass, "getpass", lambda label: "synthetic-password")
    work = tmp_path / "work"
    report = bridge.prepare(
        source_pdf,
        work,
        window_chars=100,
        overlap_blocks=1,
        max_windows=10,
        extractor=extractor,
        ask_password=True,
    )
    assert report["conversion"] == extractor + "-plain"
    assert "Synthetic protected text" in bridge.read_text(work / "source.md")
    assert "synthetic-password" not in bridge.read_text(work / "pages.json")


def test_invalid_extractor_rejected_before_reading_pdf(tmp_path):
    with pytest.raises(bridge.TestInputError, match="INVALID_EXTRACTOR"):
        bridge.extract_pdf(tmp_path / "nonexistent.pdf", None, False, "untrusted")


def test_page_text_import_remains_the_source_with_alternate_selected(tmp_path):
    source_pdf = tmp_path / "synthetic.pdf"
    pdf(source_pdf, [("Bad embedded synthetic text", False)])
    page_dir = tmp_path / "pages"
    page_dir.mkdir()
    bridge.write_text(page_dir / "0001.txt", "Synthetic team OCR text")
    work = tmp_path / "work"
    report = bridge.prepare(
        source_pdf,
        work,
        window_chars=100,
        overlap_blocks=1,
        max_windows=10,
        page_text_dir=page_dir,
        extractor="pdfplumber",
    )
    assert report["conversion"] == "page-text-import"
    assert bridge.read_text(work / "source.md") == "Synthetic team OCR text"


def run_traced_core(tmp_path, wire, events, texts=("Name Alice",)):
    from pii_pipeline.recovery.process import RecoveryPolicy

    work = setup_case(tmp_path, list(texts), cap=200)
    bridge.review(work, [])
    source, meta, plan = bridge.read_prepared(work, require_review=True)

    async def run():
        async with bridge.diagnostic_client_class()(
            settings(), transport=httpx.MockTransport(wire)
        ) as client:
            return await bridge.execute_core(
                source,
                meta,
                plan,
                client,
                bridge.RunBudget(8, 4, 30),
                events.append,
                recovery_policy=RecoveryPolicy(),
            )

    return asyncio.run(run())


def wire_role(request):
    form = parse_qs(request.content.decode())
    return next(iter(json.loads(form["json_schema"][0])["properties"]))


def test_unresolved_residual_reports_residual_stage_types_and_request_timings(
    tmp_path,
):
    events = []

    def wire(request):
        if wire_role(request) == "candidates":
            return response({"candidates": []})
        return response({"has_pii": True, "findings": [{"pii_type": "NAME"}]})

    with pytest.raises(bridge.CoreRunError, match="RESIDUAL_NOT_RESOLVED") as caught:
        run_traced_core(tmp_path, wire, events)
    report = caught.value.report
    assert report["stage"] == "residual_recovery"
    verify_calls = [call for call in report["calls"] if call["role"] == "verify"]
    assert verify_calls and verify_calls[0]["finding_types"] == ["NAME"]
    for call in report["calls"]:
        assert [t["outcome"] for t in call["proxy_request_timings"]] == ["HTTP_200"]
        assert call["proxy_request_timings"][0]["elapsed_seconds"] >= 0
    finished = [e for e in events if e["event"] == "PROXY_REQUEST_FINISHED"]
    assert len(finished) == report["proxy_request_count"]
    assert [e["proxy_request_number"] for e in finished] == list(
        range(1, len(finished) + 1)
    )
    assert "Alice" not in json.dumps({"events": events, "report": report})


def test_request_timing_records_transport_kind_and_clean_verification_types(
    tmp_path,
):
    events, detections = [], []

    def wire(request):
        if wire_role(request) == "candidates":
            detections.append(1)
            if len(detections) == 1:
                raise httpx.ReadTimeout("Synthetic private timeout")
            return response({"candidates": [{"pii_type": "NAME", "value": "Alice"}]})
        return response({"has_pii": False, "findings": []})

    redacted, report = run_traced_core(tmp_path, wire, events)
    assert redacted == "Name [PII_NAME_1]"
    first = report["calls"][0]["proxy_request_timings"]
    assert [t["outcome"] for t in first] == ["READ_TIMEOUT"]
    verify_call = next(call for call in report["calls"] if call["role"] == "verify")
    assert verify_call["finding_types"] == []
    assert "Alice" not in json.dumps({"events": events, "report": report})


def test_identifier_rules_redact_without_llm_proposals_and_report_coverage(tmp_path):
    events = []

    def wire(request):
        if wire_role(request) == "candidates":
            return response({"candidates": []})
        return response({"has_pii": False, "findings": []})

    redacted, report = run_traced_core(
        tmp_path,
        wire,
        events,
        texts=("ติดต่อ โทร 081-234-5678 อีเมล a.b@example.com",),
    )
    assert redacted == "ติดต่อ โทร [PII_PHONE_1] อีเมล [PII_EMAIL_1]"
    assert report["entries_by_type"] == {"EMAIL": 1, "PHONE": 1}
    assert {"PHONE", "EMAIL", "ID_NUMBER"} <= set(report["independent_rule_coverage"])
    assert "081-234-5678" not in json.dumps({"events": events, "report": report})
