"""Exercise the live-smoke path offline, with synthetic data and mock transport."""

import json
import os
import ssl
from urllib.parse import parse_qs

import httpx
import pytest
from wire_fixtures import (
    decisions_for_plan,
    golden_selection_transport,  # noqa: F401
)

from pii_pipeline.llm_occurrences import plan_detection_occurrences
from pii_pipeline.llm_response import parse_detection_candidates

pytestmark = pytest.mark.usefixtures("golden_selection_transport")

from pii_pipeline.detection import normalize_unicode
from pii_pipeline.llm_client import LlmProxyClient
from pii_pipeline.llm_config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm_proxy import LlmProxyHttpError, LlmProxyTransportError
from pii_pipeline.llm_response import (
    DetectionResponseError,
    VerificationResponseError,
    parse_detection_response,
)
from pii_pipeline.models import PiiMatch, RedactionResult
from pii_pipeline.redaction import redact
from smoke_llm import (
    SMOKE_CASES,
    main,
    parse_smoke_options,
    run_residual_control,
    run_smoke,
    show_error_types,
    show_execution_settings,
)


@pytest.fixture(autouse=True)
def isolate_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(name)


def settings() -> LlmProxySettings:
    return LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-secret",
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


def fixture_anchor(source: str, match: PiiMatch) -> str:
    """Use trusted expected spans only to construct mock responses, not detection."""
    start = source.rfind("\n", 0, match.start) + 1
    end = source.find("\n", match.end)
    if end < 0:
        end = len(source)
    choices = [source[start:end]]
    if end < len(source):
        choices.append(source[start : end + 1])
    if start > 0:
        choices.append(source[start - 1 : end])
    for anchor in choices:
        position = source.find(anchor)
        if source.find(anchor, position + 1) < 0:
            assert anchor.find(match.value) >= 0
            assert anchor.find(match.value, anchor.find(match.value) + 1) < 0
            return anchor
    pytest.fail("Synthetic fixture needs a unique exact anchor")


def test_reported_birthday_prose_span_omits_only_the_thai_date_introducer() -> None:
    case = SMOKE_CASES["birthday-prose"]
    expected = case.expected_matches[0]
    assert (expected.start, expected.end) == (62, 89)
    observed_start, observed_end = 69, 89
    source_value = case.text[observed_start:observed_end]
    assert case.text[expected.start : observed_start] == "วันที่ "
    assert observed_start - expected.start == len("วันที่ ") == 7
    assert expected.value == f"วันที่ {source_value}"
    assert case.text.count("\n", 0, observed_start) + 1 == 2
    matches = parse_detection_response(
        case.text,
        {
            "candidates": [
                {
                    "pii_type": "DATE_OF_BIRTH",
                    "value": source_value,
                }
            ]
        },
        occurrence_decisions={
            "decisions": [
                {"occurrence_id": 1, "pii_type": "NOT_PII"},
                {"occurrence_id": 2, "pii_type": "DATE_OF_BIRTH"},
            ]
        },
    )
    assert matches == [
        PiiMatch("DATE_OF_BIRTH", source_value, observed_start, observed_end)
    ]
    assert matches != list(case.expected_matches)


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", tuple(SMOKE_CASES))
async def test_smoke_uses_anchored_detection_and_redacted_only_clean_verification(
    case_id: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = SMOKE_CASES[case_id]
    forms: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode("utf-8"))
        forms.append(form)
        if len(forms) == 1:
            item_schema = json.loads(form["json_schema"][0])["properties"][
                "candidates"
            ]["items"]
            assert set(item_schema["properties"]) == {"pii_type", "value"}
            return success(
                {
                    "candidates": [
                        {
                            "pii_type": match.pii_type,
                            "value": match.value,
                        }
                        for match in reversed(case.expected_matches)
                    ]
                }
            )
        if len(forms) == 2:
            return success({"has_pii": False, "findings": []})
        assert len(forms) == 3
        return success(
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME"}],
            }
        )

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        await run_smoke(client, case=case)

    assert [form["context"][0] for form in forms] == [
        case.text,
        case.expected_redacted_text,
        "Name: [PII_NAME_1], Reviewer: Bob",
    ]
    assert [form["use_thinking"][0] for form in forms] == ["true", "false", "false"]
    output = capsys.readouterr().out
    assert f"Smoke case: {case_id}" in output
    assert f"Expected matches: {len(case.expected_matches)}" in output
    assert "Match expectations correct: True" in output
    assert "Redaction correct: True" in output
    assert f"Matches: {len(case.expected_matches)}" in output
    for match in case.expected_matches:
        assert f"{match.pii_type} {match.start} {match.end} True" in output
    assert "Verification has PII: False" in output
    assert "Residual PII detected: True" in output
    for stage in ("Detection", "Verification", "Residual verification"):
        assert f"{stage} elapsed seconds:" in output
    sensitive_values = [match.value for match in case.expected_matches]
    for sensitive in [*sensitive_values, "Bob", "synthetic-secret", "candidates"]:
        assert sensitive not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", tuple(SMOKE_CASES))
async def test_smoke_stops_before_verification_on_invalid_detection(
    case_id: str,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success({"candidates": [{"pii_type": "NAME", "value": "Alice"}]})

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(DetectionResponseError):
            await run_smoke(client, case=SMOKE_CASES[case_id])

    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_id", ["thai-case-numbers", "thai-title-deeds", "thai-land-parcels"]
)
async def test_numeric_smoke_rejects_source_valid_whole_field_values_before_redaction(
    case_id: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = SMOKE_CASES[case_id]
    lines = case.text.splitlines()
    assert len(lines) == len(case.expected_matches)
    calls = 0

    def forbidden_redaction(*args, **kwargs):
        pytest.fail("Incorrect value boundaries reached redaction")

    monkeypatch.setattr("smoke_llm.redact", forbidden_redaction)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert calls == 1, "Incorrect value boundaries reached verification"
        # Reproduce the live failure: valid exact source anchors/values, wrong scope.
        return success(
            {
                "candidates": [
                    {"pii_type": match.pii_type, "value": line}
                    for match, line in zip(case.expected_matches, lines, strict=True)
                ]
            }
        )

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AssertionError, match="Unexpected smoke matches"):
            await run_smoke(client, case=case)

    assert calls == 1
    output = capsys.readouterr().out
    assert "Match expectations correct: False" in output
    assert "Type matches expected: True" in output
    assert "Value matches expected: False" in output
    assert "Start matches expected: False" in output
    assert "Calling verification" not in output
    assert "Redaction correct" not in output
    for line, match in zip(lines, case.expected_matches, strict=True):
        assert line not in output
        assert match.value not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", ["birthday-prose", "birthday-context"])
async def test_birthday_smoke_rejects_document_date_false_positive_before_verification(
    case_id: str,
) -> None:
    case = SMOKE_CASES[case_id]
    value = case.expected_matches[0].value
    proposals = {"candidates": [{"pii_type": "DATE_OF_BIRTH", "value": value}]}
    plan = plan_detection_occurrences(
        case.text, parse_detection_candidates(case.text, proposals)
    )
    decisions = {
        "decisions": [
            {"occurrence_id": item.occurrence_id, "pii_type": "DATE_OF_BIRTH"}
            for item in plan.occurrences
        ]
    }
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success(proposals if calls == 1 else decisions)

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AssertionError, match="Unexpected smoke matches"):
            await run_smoke(client, case=case)

    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "difference", ["occurrence", "leading_date", "type", "missing", "extra"]
)
async def test_failed_birthday_smoke_reports_safe_match_diagnostics_and_stops(
    difference: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = SMOKE_CASES["birthday-prose"]
    expected = case.expected_matches[0]
    value = expected.value
    anchor = fixture_anchor(case.text, expected)
    pii_type = expected.pii_type
    if difference == "occurrence":
        anchor = case.text.split("\n")[0]
    elif difference == "leading_date":
        value = value.removeprefix("วันที่ ")
    elif difference == "type":
        pii_type = "NAME"
    candidates = [{"pii_type": pii_type, "value": value}]
    if difference == "missing":
        candidates = []
    elif difference == "extra":
        candidates.insert(
            0,
            {
                "pii_type": expected.pii_type,
                "value": expected.value,
            },
        )
    payload = {"candidates": candidates}
    plan = plan_detection_occurrences(
        case.text, parse_detection_candidates(case.text, payload)
    )
    if difference == "occurrence":
        selected_start = case.text.index(value)
    else:
        selected_start = case.text.index(value, case.text.index("\n") + 1)
    wanted = (
        []
        if difference == "missing"
        else [PiiMatch(pii_type, value, selected_start, selected_start + len(value))]
    )
    if difference == "extra":
        wanted.append(
            PiiMatch(
                pii_type,
                value,
                case.text.index(value),
                case.text.index(value) + len(value),
            )
        )
    decisions = decisions_for_plan(plan, wanted)
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

    output = capsys.readouterr().out
    assert calls == (2 if plan.occurrences else 1)
    assert "Match expectations correct: False" in output
    assert "Match diagnostic: 1" in output
    assert f"Expected span: {expected.start} {expected.end}" in output
    if difference == "occurrence":
        assert "Type matches expected: True" in output
        assert "Value matches expected: True" in output
        assert "Start matches expected: False" in output
        assert "Expected source line: 2" in output
        assert "Detected source line: 1" in output
    elif difference == "leading_date":
        assert "Type matches expected: True" in output
        assert "Value matches expected: False" in output
        assert "Start matches expected: False" in output
        assert "End matches expected: True" in output
        assert "Detected source line: 2" in output
    elif difference == "type":
        assert "Type matches expected: False" in output
        assert "Value matches expected: True" in output
        assert "Start matches expected: True" in output
        assert "End matches expected: True" in output
    elif difference == "missing":
        assert "Detected match missing: True" in output
    elif difference == "extra":
        assert "Match diagnostic: 2" in output
        assert "No expected match at this index: True" in output
    assert "Calling verification..." not in output
    assert "Calling residual verification..." not in output
    assert "Redaction correct:" not in output
    for sensitive in (
        case.text,
        expected.value,
        value,
        anchor,
        "synthetic-secret",
        "candidates",
    ):
        assert sensitive not in output


@pytest.mark.parametrize("case_id", tuple(SMOKE_CASES))
def test_smoke_fixtures_have_exact_nfc_spans_and_expected_redaction(
    case_id: str,
) -> None:
    case = SMOKE_CASES[case_id]
    assert case.text == normalize_unicode(case.text)
    cursor = 0
    for match in case.expected_matches:
        assert 0 <= cursor <= match.start < match.end <= len(case.text)
        assert case.text[match.start : match.end] == match.value
        cursor = match.end

    result = redact(case.text, list(case.expected_matches))
    assert result.redacted_markdown == case.expected_redacted_text
    assert len(result.entries) == len(case.expected_matches)


@pytest.mark.parametrize("case_id", (*SMOKE_CASES, "residual-only"))
def test_cli_selects_only_trusted_smoke_fixtures(case_id: str) -> None:
    options = parse_smoke_options(["--case", case_id])
    assert options.case_id == case_id
    assert options.max_retries == 0


def test_cli_retains_basic_thai_as_default() -> None:
    options = parse_smoke_options([])
    assert options.case_id == "basic-thai"
    assert options.max_retries == 0


@pytest.mark.parametrize("max_retries", [0, 1, 2])
def test_cli_retry_experiment_is_explicit_and_bounded(max_retries: int) -> None:
    options = parse_smoke_options(
        ["--case", "residual-only", "--max-retries", str(max_retries)]
    )
    assert options.case_id == "residual-only"
    assert options.max_retries == max_retries


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arguments",
    [
        ["--case", "not-a-trusted-fixture"],
        ["--max-retries", "-1"],
        ["--max-retries", "3"],
        ["--max-retries", "1.5"],
    ],
)
async def test_invalid_cli_choice_does_not_load_settings_or_construct_client(
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
) -> None:
    calls: list[str] = []

    def unexpected_factory(**kwargs: object) -> None:
        calls.append("factory")
        pytest.fail("Invalid CLI must not load configuration or construct a client")

    monkeypatch.setattr("smoke_llm.LlmProxySettings", unexpected_factory)
    monkeypatch.setattr("smoke_llm.LlmProxyClient", unexpected_factory)
    with pytest.raises(SystemExit) as captured:
        await main(arguments)

    assert captured.value.code == 2
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case_id", "error_type"),
    [("repeated-name", DetectionResponseError), ("mixed-types", AssertionError)],
)
async def test_smoke_rejects_incomplete_detection_before_verification(
    case_id: str,
    error_type: type[Exception],
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 2:
            return success({"decisions": [{"occurrence_id": 1, "pii_type": "NAME"}]})
        return success({"candidates": [{"pii_type": "NAME", "value": "สมชาย ใจดี"}]})

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(error_type):
            await run_smoke(client, case=SMOKE_CASES[case_id])

    assert calls == (2 if case_id == "repeated-name" else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_kind", ["residual_pii", "invalid_response"])
async def test_smoke_stops_on_failed_clean_verification(failure_kind: str) -> None:
    calls = 0
    case = SMOKE_CASES["mixed-types"]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return success(
                {
                    "candidates": [
                        {
                            "pii_type": match.pii_type,
                            "value": match.value,
                        }
                        for match in case.expected_matches
                    ]
                }
            )
        assert calls == 2
        if failure_kind == "invalid_response":
            return success({"has_pii": False, "findings": None})
        return success({"has_pii": True, "findings": [{"pii_type": "NAME"}]})

    error_type = (
        AssertionError if failure_kind == "residual_pii" else VerificationResponseError
    )
    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(error_type):
            await run_smoke(client, case=case)

    assert calls == 2


@pytest.mark.asyncio
async def test_residual_only_makes_one_verification_call_and_reports_elapsed_time(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    forms: list[dict[str, list[str]]] = []
    times = iter((100.0, 112.5))
    monkeypatch.setattr("smoke_llm.perf_counter", lambda: next(times))

    def handler(request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode("utf-8"))
        forms.append(form)
        return success(
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME"}],
            }
        )

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        await run_residual_control(client)

    assert len(forms) == 1
    assert forms[0]["context"] == ["Name: [PII_NAME_1], Reviewer: Bob"]
    assert forms[0]["use_thinking"] == ["false"]
    assert set(json.loads(forms[0]["json_schema"][0])["properties"]) == {
        "has_pii",
        "findings",
    }
    output = capsys.readouterr().out
    assert "Residual verification elapsed seconds: 12.50" in output
    assert "Residual PII detected: True" in output
    assert "Residual findings: 1" in output
    assert "Residual location scope: window" in output
    assert "Calling detection" not in output
    for sensitive in ("Bob", "synthetic-secret", "llm-proxy.example", "has_pii"):
        assert sensitive not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_kind", ["missed", "invalid", "timeout"])
async def test_residual_failure_reports_elapsed_time_without_success(
    failure_kind: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0
    times = iter((1.0, 4.0))
    monkeypatch.setattr("smoke_llm.perf_counter", lambda: next(times))

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if failure_kind == "timeout":
            raise httpx.ReadTimeout("synthetic-secret Bob", request=request)
        if failure_kind == "invalid":
            return success({"has_pii": True, "findings": []})
        return success({"has_pii": False, "findings": []})

    error_types = {
        "missed": AssertionError,
        "invalid": VerificationResponseError,
        "timeout": LlmProxyTransportError,
    }
    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(error_types[failure_kind]):
            await run_residual_control(client)

    assert calls == 1
    output = capsys.readouterr().out
    assert "Residual verification elapsed seconds: 3.00" in output
    assert "Residual PII detected:" not in output
    assert "Residual findings:" not in output
    assert "synthetic-secret" not in output
    assert "Bob" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response,reason_code",
    [
        ({"has_pii": True, "findings": []}, "has_pii_findings_mismatch"),
        (
            {
                "has_pii": True,
                "findings": [
                    {"pii_type": "NAME", "start": 0, "end": 1, "value": "Bob"}
                ],
            },
            "invalid_finding_shape",
        ),
        (
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME", "start": True, "end": 1}],
            },
            "invalid_finding_shape",
        ),
        (
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME", "start": 0, "end": 1234567890123}],
            },
            "invalid_finding_shape",
        ),
        (
            {
                "has_pii": True,
                "findings": [{"pii_type": "synthetic-secret"}],
            },
            "invalid_pii_type",
        ),
        (
            {"has_pii": False, "findings": [], "synthetic-secret": "Bob"},
            "invalid_response_shape",
        ),
    ],
)
async def test_residual_only_cli_reports_allowlisted_verification_reason_without_retry(
    response: dict[str, object],
    reason_code: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success(response)

    def configured_settings(**kwargs: object) -> LlmProxySettings:
        assert kwargs == {"max_retries": 0, "detection_use_thinking": True}
        return settings()

    monkeypatch.setattr("smoke_llm.LlmProxySettings", configured_settings)
    monkeypatch.setattr(
        "smoke_llm.LlmProxyClient",
        lambda configured: LlmProxyClient(
            configured,
            transport=httpx.MockTransport(handler),
        ),
    )
    with pytest.raises(SystemExit) as captured:
        await main(["--case", "residual-only"])

    assert captured.value.code == 1
    assert calls == 1
    output = capsys.readouterr().out
    assert "Error type: VerificationResponseError" in output
    assert f"Verification response reason: {reason_code}" in output
    assert "Calling detection..." not in output
    assert "Calling verification..." not in output
    assert "Residual PII detected:" not in output
    assert "Residual findings:" not in output
    for sensitive in (
        "Bob",
        "synthetic-secret",
        "1234567890123",
        "llm-proxy.example",
        "LLM verification response is invalid",
    ):
        assert sensitive not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", ["residual-only", "repeated-name"])
@pytest.mark.parametrize("status_code", [401, 403, 429, 504])
async def test_smoke_cli_reports_safe_http_status_on_residual_failure_without_retry(
    case_id: str,
    status_code: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0
    case = SMOKE_CASES["repeated-name"]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        form = parse_qs(request.content.decode("utf-8"))
        if case_id == "repeated-name" and calls == 1:
            assert form["context"] == [case.text]
            return success(
                {
                    "candidates": [
                        {
                            "pii_type": match.pii_type,
                            "value": match.value,
                        }
                        for match in case.expected_matches
                    ]
                }
            )
        if case_id == "repeated-name" and calls == 2:
            assert form["context"] == [case.expected_redacted_text]
            return success({"has_pii": False, "findings": []})
        assert form["context"] == ["Name: [PII_NAME_1], Reviewer: Bob"]
        return httpx.Response(
            status_code,
            headers={"X-Internal-Debug": "synthetic-secret"},
            text="Bob synthetic-secret https://llm-proxy.example",
        )

    def configured_settings(**kwargs: object) -> LlmProxySettings:
        assert kwargs == {"max_retries": 0, "detection_use_thinking": True}
        return settings()

    monkeypatch.setattr("smoke_llm.LlmProxySettings", configured_settings)
    monkeypatch.setattr(
        "smoke_llm.LlmProxyClient",
        lambda configured: LlmProxyClient(
            configured, transport=httpx.MockTransport(handler)
        ),
    )
    with pytest.raises(SystemExit) as captured:
        await main(["--case", case_id])

    assert captured.value.code == 1
    assert calls == (1 if case_id == "residual-only" else 3)
    output = capsys.readouterr().out
    assert "Error type: LlmProxyHttpError" in output
    assert f"HTTP status: {status_code}" in output
    assert "Residual verification elapsed seconds:" in output
    assert "Residual PII detected:" not in output
    assert "Residual findings:" not in output
    assert "Error type: LlmProxyTransportError" not in output
    if case_id == "repeated-name":
        assert "Match expectations correct: True" in output
        assert "Redaction correct: True" in output
        assert "Verification has PII: False" in output
        assert "Findings: 0" in output
    else:
        assert "Calling detection..." not in output
        assert "Calling verification..." not in output
    for sensitive in (
        "Bob",
        "สมชาย ใจดี",
        "synthetic-secret",
        "llm-proxy.example",
        "X-Internal-Debug",
        "LLM proxy request was not successful",
    ):
        assert sensitive not in output


def test_smoke_http_status_diagnostic_does_not_echo_untrusted_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    show_error_types(
        LlmProxyHttpError("Bob synthetic-secret", status_code="Bob synthetic-secret")
    )

    output = capsys.readouterr().out
    assert "Error type: LlmProxyHttpError" in output
    assert "HTTP status: unavailable" in output
    assert "Bob" not in output
    assert "synthetic-secret" not in output


@pytest.mark.asyncio
async def test_full_smoke_keeps_completed_stage_results_on_residual_timeout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0
    case = SMOKE_CASES["mixed-types"]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return success(
                {
                    "candidates": [
                        {
                            "pii_type": match.pii_type,
                            "value": match.value,
                        }
                        for match in case.expected_matches
                    ]
                }
            )
        if calls == 2:
            return success({"has_pii": False, "findings": []})
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(LlmProxyTransportError):
            await run_smoke(client, case=case)

    assert calls == 3
    output = capsys.readouterr().out
    assert "Verification has PII: False" in output
    assert "Findings: 0" in output
    assert "Residual verification elapsed seconds:" in output
    assert "Residual PII detected:" not in output
    assert output.index("Findings: 0") < output.index("Calling residual verification")


@pytest.mark.parametrize(
    "case_id,logical_calls", [("residual-only", 1), ("mixed-types", 4)]
)
@pytest.mark.parametrize("max_retries", [0, 1, 2])
def test_execution_diagnostics_use_effective_limits_without_secrets(
    case_id: str,
    logical_calls: int,
    max_retries: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configured = settings().model_copy(
        update={
            "max_retries": max_retries,
            "connect_timeout_seconds": 4.0,
            "read_timeout_seconds": 12.0,
            "write_timeout_seconds": 3.0,
            "pool_timeout_seconds": 2.0,
            "request_deadline_seconds": 30.0,
            "verify_tls": False,
            "verification_use_thinking": True,
        }
    )
    show_execution_settings(configured, case_id=case_id)
    output = capsys.readouterr().out
    for name, value in (
        ("Connect", 4.0),
        ("Read", 12.0),
        ("Write", 3.0),
        ("Pool", 2.0),
    ):
        assert f"{name} timeout seconds: {value}" in output
    assert "Request deadline seconds: 30.0" in output
    assert "Detection prompt version: pii-detection-v18" in output
    assert "Verification prompt version: pii-verification-v11" in output
    assert "Verification thinking: True" in output
    assert "TLS verification: False" in output
    assert "Warning: TLS server identity is not verified." in output
    assert f"Max retries per call: {max_retries}" in output
    assert f"Max attempts per call: {1 + max_retries}" in output
    assert (
        f"Max HTTP attempts for this smoke: {logical_calls * (1 + max_retries)}"
        in output
    )
    assert ("retry may duplicate proxy work" in output) is bool(max_retries)
    assert "synthetic-secret" not in output
    assert "llm-proxy.example" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("max_retries", [0, 1])
async def test_main_residual_experiment_is_opt_in_and_sanitizes_timeout(
    max_retries: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0
    configured_retries: list[int] = []
    delays: list[float] = []

    def configured_settings(**kwargs: object) -> LlmProxySettings:
        assert kwargs == {"max_retries": max_retries, "detection_use_thinking": True}
        configured_retries.append(max_retries)
        return settings().model_copy(update=kwargs)

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        form = parse_qs(request.content.decode("utf-8"))
        assert form["context"] == ["Name: [PII_NAME_1], Reviewer: Bob"]
        if calls == 1:
            raise httpx.ReadTimeout(
                "synthetic-secret Bob", request=request
            ) from ssl.SSLWantReadError("synthetic pending I/O")
        return success(
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME"}],
            }
        )

    def configured_client(configured: LlmProxySettings) -> LlmProxyClient:
        return LlmProxyClient(
            configured, transport=httpx.MockTransport(handler), sleep=fake_sleep
        )

    monkeypatch.setattr("smoke_llm.LlmProxySettings", configured_settings)
    monkeypatch.setattr("smoke_llm.LlmProxyClient", configured_client)
    arguments = ["--case", "residual-only"]
    if max_retries:
        arguments.extend(["--max-retries", str(max_retries)])
        await main(arguments)
    else:
        with pytest.raises(SystemExit) as captured:
            await main(arguments)
        assert captured.value.code == 1

    assert configured_retries == [max_retries]
    assert calls == 1 + max_retries
    assert delays == ([1.0] if max_retries else [])
    output = capsys.readouterr().out
    assert "Smoke case: residual-only" in output
    assert "Residual verification elapsed seconds:" in output
    assert ("Residual PII detected: True" in output) is bool(max_retries)
    assert ("Error type: LlmProxyTransportError" in output) is (not max_retries)
    assert "Calling detection" not in output
    assert "synthetic-secret" not in output
    assert "Bob" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("eventually_succeeds", [True, False])
async def test_full_smoke_retries_only_failed_residual_call_at_most_twice(
    eventually_succeeds: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = SMOKE_CASES["repeated-name"]
    residual_text = "Name: [PII_NAME_1], Reviewer: Bob"
    calls: list[str] = []
    delays: list[float] = []
    redactions = 0

    def configured_settings(**kwargs: object) -> LlmProxySettings:
        assert kwargs == {"max_retries": 2, "detection_use_thinking": True}
        return settings().model_copy(update=kwargs)

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    def counted_redact(text: str, matches: list[PiiMatch]) -> RedactionResult:
        nonlocal redactions
        redactions += 1
        return redact(text, matches)

    def handler(request: httpx.Request) -> httpx.Response:
        context = parse_qs(request.content.decode("utf-8"))["context"][0]
        if context == case.text:
            calls.append("detection")
            return success(
                {
                    "candidates": [
                        {
                            "pii_type": match.pii_type,
                            "value": match.value,
                        }
                        for match in case.expected_matches
                    ]
                }
            )
        if context == case.expected_redacted_text:
            calls.append("clean-verification")
            return success({"has_pii": False, "findings": []})

        assert context == residual_text
        calls.append("residual-verification")
        if calls.count("residual-verification") < 3 or not eventually_succeeds:
            return httpx.Response(504, text="Bob synthetic-secret internal error")
        return success(
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME"}],
            }
        )

    def configured_client(configured: LlmProxySettings) -> LlmProxyClient:
        return LlmProxyClient(
            configured, transport=httpx.MockTransport(handler), sleep=fake_sleep
        )

    monkeypatch.setattr("smoke_llm.LlmProxySettings", configured_settings)
    monkeypatch.setattr("smoke_llm.LlmProxyClient", configured_client)
    monkeypatch.setattr("smoke_llm.redact", counted_redact)
    arguments = ["--case", "repeated-name", "--max-retries", "2"]
    if eventually_succeeds:
        await main(arguments)
    else:
        with pytest.raises(SystemExit) as captured:
            await main(arguments)
        assert captured.value.code == 1

    assert calls == [
        "detection",
        "clean-verification",
        "residual-verification",
        "residual-verification",
        "residual-verification",
    ]
    assert delays == [1.0, 2.0]
    assert redactions == 1
    output = capsys.readouterr().out
    assert "Max retries per call: 2" in output
    assert "Max attempts per call: 3" in output
    assert "Max HTTP attempts for this smoke: 12" in output
    assert "Match expectations correct: True" in output
    assert "Redaction correct: True" in output
    assert "Verification has PII: False" in output
    assert "Findings: 0" in output
    assert ("Residual PII detected: True" in output) is eventually_succeeds
    assert ("Residual findings: 1" in output) is eventually_succeeds
    assert ("Error type: LlmProxyHttpError" in output) is (not eventually_succeeds)
    assert ("HTTP status: 504" in output) is (not eventually_succeeds)
    for sensitive in ("Bob", "สมชาย ใจดี", "synthetic-secret", "internal error"):
        assert sensitive not in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_kind,reason_code",
    [
        ("shape", "invalid_response_shape"),
        ("candidate_shape", "invalid_candidate_shape"),
        ("pii_type", "invalid_pii_type"),
        ("value", "invalid_value"),
        ("anchor", "invalid_candidate_shape"),
        ("anchor_not_found", "invalid_candidate_shape"),
        ("anchor_not_unique", "invalid_candidate_shape"),
        ("value_not_found", "value_not_found"),
        ("value_not_unique", "invalid_candidate_shape"),
        ("overlap", "overlapping_matches"),
    ],
)
async def test_mixed_types_cli_reports_safe_detection_reason_without_retry_or_redaction(
    failure_kind: str,
    reason_code: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = SMOKE_CASES["mixed-types"]
    candidates: list[dict[str, object]] = [
        {
            "pii_type": match.pii_type,
            "value": match.value,
        }
        for match in case.expected_matches
    ]
    response: dict[str, object] = {"candidates": candidates}
    if failure_kind == "shape":
        response["synthetic-secret"] = "Bob"
    elif failure_kind == "candidate_shape":
        candidates[0]["synthetic-secret"] = "Bob"
    elif failure_kind == "pii_type":
        candidates[0]["pii_type"] = "synthetic-secret"
    elif failure_kind == "value":
        candidates[0]["value"] = {"synthetic-secret": "Bob"}
    elif failure_kind == "anchor":
        candidates[0]["anchor"] = ["synthetic-secret Bob"]
    elif failure_kind == "anchor_not_found":
        candidates[0]["anchor"] = "synthetic-secret Bob"
    elif failure_kind == "anchor_not_unique":
        assert case.text.count(": ") > 1
        candidates[0]["anchor"] = ": "
    elif failure_kind == "value_not_found":
        candidates[0]["value"] = "synthetic-secret Bob"
    elif failure_kind == "value_not_unique":
        assert case.text.count(": ") > 1
        candidates[0]["value"] = ": "
        candidates[0]["anchor"] = case.text
    else:
        assert failure_kind == "overlap"
        candidates.append(
            {"pii_type": "NAME", "value": case.expected_matches[0].value[:-1]}
        )

    calls = 0
    redactions = 0
    delays: list[float] = []

    def configured_settings(**kwargs: object) -> LlmProxySettings:
        assert kwargs == {"max_retries": 2, "detection_use_thinking": True}
        return settings().model_copy(update=kwargs)

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert parse_qs(request.content.decode("utf-8"))["context"] == [case.text]
        return success(response)

    def counted_redact(text: str, matches: list[PiiMatch]) -> RedactionResult:
        nonlocal redactions
        redactions += 1
        return redact(text, matches)

    def configured_client(configured: LlmProxySettings) -> LlmProxyClient:
        return LlmProxyClient(
            configured, transport=httpx.MockTransport(handler), sleep=fake_sleep
        )

    monkeypatch.setattr("smoke_llm.LlmProxySettings", configured_settings)
    monkeypatch.setattr("smoke_llm.LlmProxyClient", configured_client)
    monkeypatch.setattr("smoke_llm.redact", counted_redact)
    with pytest.raises(SystemExit) as captured:
        await main(["--case", "mixed-types", "--max-retries", "2"])

    assert captured.value.code == 1
    assert calls == 1
    assert redactions == 0
    assert delays == []
    output = capsys.readouterr().out
    assert "Max retries per call: 2" in output
    assert "Max HTTP attempts for this smoke: 12" in output
    assert "Detection elapsed seconds:" in output
    assert "Error type: DetectionResponseError" in output
    assert f"Detection response reason: {reason_code}" in output
    assert "Match expectations correct:" not in output
    assert "Redaction correct:" not in output
    assert "Calling verification..." not in output
    assert "Calling residual verification..." not in output
    for sensitive in (
        "synthetic-secret",
        "Bob",
        "llm-proxy.example",
        "LLM detection response is invalid",
        *(match.value for match in case.expected_matches),
    ):
        assert sensitive not in output


def test_smoke_detection_reason_diagnostic_does_not_echo_untrusted_reason(
    capsys: pytest.CaptureFixture[str],
) -> None:
    show_error_types(
        DetectionResponseError(
            "Bob synthetic-secret", reason_code="Bob synthetic-secret"
        )
    )
    output = capsys.readouterr().out
    assert "Error type: DetectionResponseError" in output
    assert "Detection response reason: invalid_response" in output
    assert "Bob" not in output
    assert "synthetic-secret" not in output


def test_mixed_smoke_unique_values_are_valid_minimal_anchors() -> None:
    case = SMOKE_CASES["mixed-types"]
    assert all(case.text.count(match.value) == 1 for match in case.expected_matches)
    response = {
        "candidates": [
            {"pii_type": match.pii_type, "value": match.value}
            for match in case.expected_matches
        ]
    }
    assert parse_detection_response(case.text, response) == list(case.expected_matches)


def test_organization_only_reuses_exact_mixed_line_and_keeps_a_local_oracle() -> None:
    mixed = SMOKE_CASES["mixed-types"]
    case = SMOKE_CASES["organization-only"]
    expected = case.expected_matches[0]
    mixed_expected = mixed.expected_matches[3]
    assert case.text == mixed.text.split("\n")[3]
    assert normalize_unicode(case.text) == case.text
    assert len(case.text) == 37
    assert expected.pii_type == mixed_expected.pii_type == "ORGANIZATION"
    assert expected.value == mixed_expected.value
    assert len(expected.value) == 26
    assert (expected.start, expected.end) == (11, 37)
    assert (mixed_expected.start, mixed_expected.end) == (80, 106)
    assert case.text[expected.start : expected.end] == expected.value
    assert case.text.count(expected.value) == 1
    assert case.expected_redacted_text == "นิติบุคคล: [PII_ORGANIZATION_1]"
    assert expected.value not in repr(case)
    options = parse_smoke_options(["--case", "organization-only", "--max-retries", "2"])
    assert options.case_id == "organization-only"
    assert options.max_retries == 2
    assert parse_detection_response(
        case.text,
        {
            "candidates": [
                {
                    "pii_type": expected.pii_type,
                    "value": expected.value,
                }
            ]
        },
    ) == list(case.expected_matches)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case_id,candidate_index", [("mixed-types", 4), ("organization-only", 1)]
)
@pytest.mark.parametrize(
    "difference", ["character", "space_position", "compatibility", "format_character"]
)
async def test_organization_copy_comparisons_do_not_repair_or_retry_invalid_values(
    case_id: str,
    candidate_index: int,
    difference: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = SMOKE_CASES[case_id]
    expected = case.expected_matches[candidate_index - 1]
    # Invented failures for regression, not a reconstruction of the live response.
    if difference == "character":
        changed_value = expected.value.replace("ทดสอบ", "ทดสอป")
    elif difference == "space_position":
        changed_value = expected.value.replace("บริษัท ", "บริษัท").replace(
            " จำกัด", "  จำกัด"
        )
    elif difference == "compatibility":
        changed_value = expected.value.replace("ำ", "\u0e4dา")
    else:
        assert difference == "format_character"
        changed_value = expected.value.replace("บริษัท", "บริษัท\u200b")
    # Near copies within max(2, length // 15) edits now resolve to the source
    # span (approved 2026-10-06); three more interior substitutions keep
    # these 24-character values beyond that budget.
    changed_value = (
        changed_value.replace("ตัว", "ตีว")
        .replace("อย่าง", "อย้าง")
        .replace("ทดสอ", "ทดสโ")
    )
    assert len(expected.value) == 26
    assert len(changed_value) == (
        26 if difference in {"character", "space_position"} else 27
    )
    assert changed_value not in case.text
    assert " ".join(changed_value.split()) not in " ".join(case.text.split())
    candidates = [
        {"pii_type": match.pii_type, "value": match.value}
        for match in case.expected_matches
    ]
    candidates[candidate_index - 1].update(value=changed_value)
    calls = 0
    delays: list[float] = []

    def configured_settings(**kwargs: object) -> LlmProxySettings:
        assert kwargs == {"max_retries": 2, "detection_use_thinking": True}
        return settings().model_copy(update=kwargs)

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert calls == 1
        assert parse_qs(request.content.decode("utf-8"))["context"] == [case.text]
        return success({"candidates": candidates})

    def configured_client(configured: LlmProxySettings) -> LlmProxyClient:
        return LlmProxyClient(
            configured, transport=httpx.MockTransport(handler), sleep=fake_sleep
        )

    def unexpected_redact(*args: object, **kwargs: object) -> RedactionResult:
        pytest.fail("Invalid organization must stop before any redaction")

    monkeypatch.setattr("smoke_llm.LlmProxySettings", configured_settings)
    monkeypatch.setattr("smoke_llm.LlmProxyClient", configured_client)
    monkeypatch.setattr("smoke_llm.redact", unexpected_redact)
    with pytest.raises(SystemExit) as captured:
        await main(["--case", case_id, "--max-retries", "2"])
    assert captured.value.code == 1
    assert calls == 1
    assert delays == []
    output = capsys.readouterr().out
    assert "Detection response reason: value_not_found" in output
    assert f"Detection candidate index: {candidate_index}" in output
    assert "Detection candidate type: ORGANIZATION" in output
    assert f"Detection source length: {len(case.text)}" in output
    assert f"Detection value length: {len(changed_value)}" in output
    assert "Value exists in source: False" in output
    assert "Value found after removing all whitespace: False" in output
    assert "Value found with NFKC comparison: False" in output
    assert "Value found after removing Unicode format characters: False" in output
    assert (
        f"Value contains Unicode format characters: {difference == 'format_character'}"
        in output
    )
    assert "Expected matches:" not in output
    assert "Redaction correct:" not in output
    assert "Calling verification..." not in output
    assert "Calling residual verification..." not in output
    for sensitive in (changed_value, expected.value, case.text, "synthetic-secret"):
        assert sensitive not in output


@pytest.mark.asyncio
async def test_organization_only_cli_completes_all_stages_with_an_exact_minimal_anchor(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = SMOKE_CASES["organization-only"]
    expected = case.expected_matches[0]
    contexts: list[str] = []
    delays: list[float] = []

    def configured_settings(**kwargs: object) -> LlmProxySettings:
        assert kwargs == {"max_retries": 2, "detection_use_thinking": True}
        return settings().model_copy(update=kwargs)

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode("utf-8"))
        text = form["context"][0]
        contexts.append(text)
        if len(contexts) == 1:
            return success(
                {
                    "candidates": [
                        {
                            "pii_type": "ORGANIZATION",
                            "value": expected.value,
                        }
                    ]
                }
            )
        if len(contexts) == 2:
            return success({"has_pii": False, "findings": []})
        assert len(contexts) == 3
        return success(
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME"}],
            }
        )

    def configured_client(configured: LlmProxySettings) -> LlmProxyClient:
        return LlmProxyClient(
            configured, transport=httpx.MockTransport(handler), sleep=fake_sleep
        )

    monkeypatch.setattr("smoke_llm.LlmProxySettings", configured_settings)
    monkeypatch.setattr("smoke_llm.LlmProxyClient", configured_client)
    await main(["--case", "organization-only", "--max-retries", "2"])
    assert contexts == [
        case.text,
        case.expected_redacted_text,
        "Name: [PII_NAME_1], Reviewer: Bob",
    ]
    assert delays == []
    output = capsys.readouterr().out
    assert "Detection prompt version: pii-detection-v18" in output
    assert "Verification prompt version: pii-verification-v11" in output
    assert "Max retries per call: 2" in output
    assert "Max HTTP attempts for this smoke: 12" in output
    assert "Smoke case: organization-only" in output
    assert "Expected matches: 1" in output
    assert "Detected matches: 1" in output
    assert "Match expectations correct: True" in output
    assert "Redaction correct: True" in output
    assert "ORGANIZATION 11 37 True" in output
    assert "Verification has PII: False" in output
    assert "Findings: 0" in output
    assert "Residual PII detected: True" in output
    assert "Residual findings: 1" in output
    for sensitive in (case.text, expected.value, "Bob", "synthetic-secret"):
        assert sensitive not in output


def test_smoke_detection_details_do_not_echo_untrusted_fields_or_metadata(
    capsys: pytest.CaptureFixture[str],
) -> None:
    show_error_types(
        DetectionResponseError(
            "Bob synthetic-secret",
            reason_code="value_not_found",
            details={
                "pii_type": "synthetic-secret",
                "candidate_index": True,
                "source_length": 123,
                "anchor_length": 1_000_001,
                "value_found_in_source": "Bob",
                "synthetic-secret": "Bob",
            },
        )
    )
    output = capsys.readouterr().out
    assert "Detection response reason: value_not_found" in output
    assert "Detection source length: 123" in output
    assert "Detection candidate type:" not in output
    assert "Detection candidate index:" not in output
    assert "Value exists in source:" not in output
    assert "synthetic-secret" not in output
    assert "Bob" not in output
    assert "1000001" not in output
