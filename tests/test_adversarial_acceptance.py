from pii_pipeline.core.models import PiiMatch

"""Frozen semantic counterexamples and injection/OCR acceptance-harness guards."""

import os
from urllib.parse import parse_qs

import httpx
import pytest
from wire_fixtures import decisions_for_plan

import smoke_llm
from pii_pipeline.core.redaction import redact
from pii_pipeline.llm.client import LlmProxyClient
from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm.response import (
    DetectionResponseError,
    parse_detection_candidates,
    parse_detection_response,
)
from pii_pipeline.selection.occurrences import plan_detection_occurrences
from smoke_llm import SMOKE_CASES, VERIFICATION_SMOKE_CASES, run_smoke


@pytest.fixture(autouse=True)
def isolate_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(name)


def settings() -> LlmProxySettings:
    return LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-adversarial-secret",
        max_retries=0,
        detection_use_thinking=True,
        _env_file=None,
    )


def success(output: dict[str, object]) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": LLM_PROXY_MODEL,
            "structured_output": output,
        },
    )


def oracle_candidates(case_id: str) -> list[dict[str, str]]:
    case = SMOKE_CASES[case_id]
    candidates = []
    for match in case.expected_matches:
        start = case.text.rfind("\n", 0, match.start) + 1
        end = case.text.find("\n", match.end)
        if end < 0:
            end = len(case.text)
        anchor = case.text[start:end]
        assert case.text.count(anchor) == 1 and anchor.count(match.value) == 1
        candidates.append({"pii_type": match.pii_type, "value": match.value})
    return candidates


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case_id", "pii_type", "wrong_anchor"),
    [
        ("mixed-contextual-pii", "DATE_OF_BIRTH", "วันที่ออกเอกสาร: วันที่ 1 มกราคม 2569"),
        ("mixed-repeated-identifiers", "LAND_PARCEL_NUMBER", "หน้าสำรวจ 12345"),
    ],
)
async def test_same_value_in_wrong_context_is_rejected_even_with_valid_type_and_count(
    case_id: str, pii_type: str, wrong_anchor: str, capsys: pytest.CaptureFixture[str]
) -> None:
    case = SMOKE_CASES[case_id]
    candidates = oracle_candidates(case_id)
    selected = next(item for item in candidates if item["pii_type"] == pii_type)
    payload = {"candidates": candidates}
    plan = plan_detection_occurrences(
        case.text, parse_detection_candidates(case.text, payload)
    )
    wrong_start = case.text.index(wrong_anchor) + wrong_anchor.index(selected["value"])
    wrong_matches = [
        match
        if match.pii_type != pii_type
        else PiiMatch(
            pii_type,
            selected["value"],
            wrong_start,
            wrong_start + len(selected["value"]),
        )
        for match in case.expected_matches
    ]
    decisions = decisions_for_plan(plan, wrong_matches)
    parsed = parse_detection_response(
        case.text, payload, occurrence_decisions=decisions
    )
    assert len(parsed) == len(case.expected_matches)
    assert sorted(item.pii_type for item in parsed) == sorted(
        item.pii_type for item in case.expected_matches
    )
    assert parsed != list(case.expected_matches)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success(payload if calls == 1 else decisions)

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AssertionError, match="Unexpected smoke matches"):
            await run_smoke(client, case=case)
    assert calls == 2
    output = capsys.readouterr().out
    assert "Match expectations correct: False" in output
    assert "Calling verification" not in output and wrong_anchor not in output


def test_mixed_redaction_keeps_equal_excluded_values_and_separate_occurrences() -> None:
    contextual = SMOKE_CASES["mixed-contextual-pii"]
    redacted = redact(contextual.text, list(contextual.expected_matches))
    assert "วันที่ออกเอกสาร: วันที่ 1 มกราคม 2569" in redacted.redacted_markdown
    assert "วันเดือนปีเกิด: [PII_DATE_OF_BIRTH_1]" in redacted.redacted_markdown
    assert "หน้าสำรวจ 12345" in redacted.redacted_markdown
    assert "เลขที่ดิน [PII_LAND_PARCEL_NUMBER_1]" in redacted.redacted_markdown
    assert "ฝ่ายตรวจสอบเอกสาร (เป็นส่วนงานภายใน ไม่ใช่นิติบุคคล)" in redacted.redacted_markdown
    repeated = SMOKE_CASES["mixed-repeated-identifiers"]
    redacted = redact(repeated.text, list(repeated.expected_matches))
    assert [entry.placeholder for entry in redacted.entries] == [
        "[PII_CASE_NUMBER_1]",
        "[PII_CASE_NUMBER_2]",
        "[PII_TITLE_DEED_NUMBER_1]",
        "[PII_LAND_PARCEL_NUMBER_1]",
    ]
    assert "หน้าสำรวจ 12345" in redacted.redacted_markdown


def test_whitespace_only_name_copy_resolves_to_the_exact_source_span() -> None:
    # Approved 2026-10-06: whitespace differences locate the source text; the
    # redacted span is always the source substring, never the model's copy.
    case = SMOKE_CASES["ocr-whitespace-fields"]
    candidates = oracle_candidates(case.case_id)
    item = next(item for item in candidates if item["pii_type"] == "NAME")
    item["value"] = item["value"].replace("\t\t", " ")
    assert item["value"] not in case.text
    assert parse_detection_response(case.text, {"candidates": candidates}) == list(
        case.expected_matches
    )


@pytest.mark.asyncio
async def test_ocr_value_repair_is_rejected_without_retry_or_redaction(
    capsys: pytest.CaptureFixture[str],
) -> None:
    case_id = "ocr-whitespace-fields"
    case = SMOKE_CASES[case_id]
    candidates = oracle_candidates(case_id)
    # Short values get no character tolerance.
    item = next(item for item in candidates if item["pii_type"] == "ID_NUMBER")
    item["value"] = item["value"].replace("X", "0")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success({"candidates": candidates})

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(DetectionResponseError):
            await run_smoke(client, case=case)
    assert calls == 1
    output = capsys.readouterr().out
    assert "Redaction correct:" not in output
    assert item["value"] not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("name_result", ["partial", "split"])
async def test_source_valid_incomplete_ocr_name_is_rejected_before_redaction(
    name_result: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = SMOKE_CASES["ocr-whitespace-fields"]
    candidates = oracle_candidates(case.case_id)
    name_index = next(
        index for index, item in enumerate(candidates) if item["pii_type"] == "NAME"
    )
    original_name = candidates[name_index]
    replacements = [{"pii_type": "NAME", "value": "นายทดสอบ"}]
    if name_result == "split":
        replacements.append(
            {
                "pii_type": "NAME",
                "value": "ตัวอย่าง",
            }
        )
    candidates[name_index : name_index + 1] = replacements
    payload = {"candidates": candidates}

    # Both counterexamples are exact source substrings, so source validation
    # alone cannot establish that the complete personal name was selected.
    parsed = parse_detection_response(case.text, payload)
    assert parsed != list(case.expected_matches)
    assert [item for item in parsed if item.pii_type != "NAME"] == [
        item for item in case.expected_matches if item.pii_type != "NAME"
    ]
    assert [(item.start, item.end) for item in parsed if item.pii_type == "NAME"] == (
        [(48, 56)] if name_result == "partial" else [(48, 56), (58, 66)]
    )
    expected_name = next(
        item for item in case.expected_matches if item.pii_type == "NAME"
    )
    assert (expected_name.start, expected_name.end) == (48, 66)
    calls = 0
    redaction_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success(payload)

    def forbidden_redaction(*args: object, **kwargs: object) -> None:
        nonlocal redaction_calls
        redaction_calls += 1
        raise AssertionError("Redaction must wait for the trusted oracle")

    monkeypatch.setattr(smoke_llm, "redact", forbidden_redaction)
    configured = settings()
    assert configured.max_retries == 0
    async with LlmProxyClient(
        configured, transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AssertionError, match="Unexpected smoke matches"):
            await run_smoke(client, case=case)

    assert calls == 1
    assert redaction_calls == 0
    output = capsys.readouterr().out
    assert "Match expectations correct: False" in output
    assert "Expected span: 48 66" in output
    assert "Detected span: 48 56" in output
    assert "Redaction correct:" not in output
    assert "Calling verification..." not in output
    assert "Calling residual verification..." not in output
    for sensitive in (
        case.text,
        original_name["value"],
        "นายทดสอบ",
        "ตัวอย่าง",
        "synthetic-adversarial-secret",
        "llm-proxy.example",
    ):
        assert sensitive not in output


def test_ocr_oracle_preserves_field_whitespace_and_original_values() -> None:
    case = SMOKE_CASES["ocr-whitespace-fields"]
    matches = parse_detection_response(
        case.text, {"candidates": oracle_candidates(case.case_id)}
    )
    assert matches == list(case.expected_matches)
    result = redact(case.text, matches)
    assert result.redacted_markdown == (
        "โฉนดที่ดิน\tเลขที่\t[PII_TITLE_DEED_NUMBER_1]\n"
        "เลขที่ดิน\n  [PII_LAND_PARCEL_NUMBER_1]\n"
        "ชื่อ\t[PII_NAME_1]\n"
        "เลขบัตรประชาชน: [PII_ID_NUMBER_1]"
    )
    assert (
        next(
            entry.original_value
            for entry in result.entries
            if entry.pii_type == "ID_NUMBER"
        )
        == "1-2345-6789X-12-3"
    )
    assert (
        next(
            entry.original_value for entry in result.entries if entry.pii_type == "NAME"
        )
        == "นายทดสอบ\t\tตัวอย่าง"
    )


@pytest.mark.asyncio
async def test_injected_empty_candidates_cannot_hide_the_person() -> None:
    case = SMOKE_CASES["injection-thai-name"]
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        form = parse_qs(request.content.decode("utf-8"))
        assert form["context"] == [case.text]
        assert "Ignore the trusted policy" not in form["prompt"][0]
        return success({"candidates": []})

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AssertionError, match="Unexpected smoke matches"):
            await run_smoke(client, case=case)
    assert calls == 1
    redacted = redact(case.text, list(case.expected_matches)).redacted_markdown
    assert redacted.splitlines()[0] == case.text.splitlines()[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["follow-injection", "missing-type", "duplicate-occurrence", "extra-field"],
)
async def test_mixed_injection_verification_failures_never_count_as_clean_or_success(
    failure: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    case_id = "injection-residual-mixed"
    case = VERIFICATION_SMOKE_CASES[case_id]
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        form = parse_qs(request.content.decode("utf-8"))
        assert form["context"] == [case.text]
        assert "Ignore the trusted policy" not in form["prompt"][0]
        payload: dict[str, object] = {
            "has_pii": True,
            "findings": [{"pii_type": "NAME"}, {"pii_type": "CASE_NUMBER"}],
        }
        if failure == "follow-injection":
            payload = {"has_pii": False, "findings": []}
        elif failure == "missing-type":
            payload["findings"] = [{"pii_type": "NAME"}]
        elif failure == "duplicate-occurrence":
            payload["findings"] = [
                {"pii_type": "NAME"},
                {"pii_type": "NAME"},
                {"pii_type": "CASE_NUMBER"},
            ]
        else:
            payload["debug"] = "private-injection-canary"
        return success(payload)

    configured = settings()
    client = LlmProxyClient(configured, transport=httpx.MockTransport(handler))
    monkeypatch.setattr(smoke_llm, "LlmProxySettings", lambda **kwargs: configured)
    monkeypatch.setattr(smoke_llm, "LlmProxyClient", lambda config: client)
    with pytest.raises(SystemExit) as caught:
        await smoke_llm.main(["--case", case_id])
    assert caught.value.code == 1 and calls == 1
    output = capsys.readouterr().out
    assert "Residual PII detected:" not in output
    assert "private-injection-canary" not in output
    assert case.text not in output and "synthetic-adversarial-secret" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_id",
    ["residual-mixed-repeated", "ocr-residual-mixed", "injection-residual-mixed"],
)
async def test_mixed_verification_accepts_reversed_order_but_one_finding_per_type(
    case_id: str, capsys: pytest.CaptureFixture[str]
) -> None:
    case = VERIFICATION_SMOKE_CASES[case_id]
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success(
            {
                "has_pii": True,
                "findings": [
                    {"pii_type": item} for item in reversed(case.expected_types)
                ],
            }
        )

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        await smoke_llm.run_verification_smoke(client, case=case)
    assert calls == 1
    output = capsys.readouterr().out
    assert "Residual findings: 2" in output
    assert output.count("Residual location scope: window") == 2
    assert case.text not in output
