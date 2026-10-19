"""Acceptance-harness guards; mocked classifications do not establish accuracy."""

import json
import os
from urllib.parse import parse_qs

import httpx
import pytest
from fake_llm import whole

import smoke_llm
from pii_pipeline.llm_client import LlmProxyClient
from pii_pipeline.llm_config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm_processing import LlmDocumentProcessor
from pii_pipeline.llm_prompts import build_verification_prompt
from pii_pipeline.llm_recovery import (
    RecoveryPolicy,
    process_markdown_with_recovery_async,
)
from pii_pipeline.llm_response import parse_detection_response
from pii_pipeline.thai_rules import detect_thai_labeled_numbers
from pii_pipeline.verification import make_detection_checker
from smoke_llm import SMOKE_CASES, VERIFICATION_SMOKE_CASES, run_smoke

NEGATIVE_FALSE_POSITIVES = {
    "negative-document-dates": ("DATE_OF_BIRTH", "1 มกราคม 2569"),
    "negative-organizational-units": ("ORGANIZATION", "ฝ่ายตรวจสอบเอกสาร"),
    "negative-land-references": ("LAND_PARCEL_NUMBER", "12345"),
}


@pytest.fixture(autouse=True)
def isolate_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(name)


def settings() -> LlmProxySettings:
    return LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-acceptance-secret",
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


def patch_cli_client(monkeypatch: pytest.MonkeyPatch, client: LlmProxyClient) -> None:
    configured = settings()
    monkeypatch.setattr(smoke_llm, "LlmProxySettings", lambda **kwargs: configured)
    monkeypatch.setattr(smoke_llm, "LlmProxyClient", lambda config: client)


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", NEGATIVE_FALSE_POSITIVES)
async def test_negative_oracle_rejects_source_valid_false_positive_before_verification(
    case_id: str, capsys: pytest.CaptureFixture[str]
) -> None:
    case = SMOKE_CASES[case_id]
    pii_type, value = NEGATIVE_FALSE_POSITIVES[case_id]
    payload = {"candidates": [{"pii_type": pii_type, "value": value}]}
    assert len(parse_detection_response(case.text, payload)) == 1
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert calls == 1
        return success(payload)

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AssertionError, match="Unexpected smoke matches"):
            await run_smoke(client, case=case)

    assert calls == 1
    output = capsys.readouterr().out
    assert "Match expectations correct: False" in output
    assert "Calling verification" not in output
    assert value not in output and case.text not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", NEGATIVE_FALSE_POSITIVES)
async def test_negative_clean_false_positive_stops_before_residual_control(
    case_id: str,
) -> None:
    case = SMOKE_CASES[case_id]
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        form = parse_qs(request.content.decode("utf-8"))
        assert form["context"] == [case.text]
        if calls == 1:
            return success({"candidates": []})
        assert calls == 2
        return success({"has_pii": True, "findings": [{"pii_type": "NAME"}]})

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AssertionError, match="Unexpected residual PII"):
            await run_smoke(client, case=case)
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", tuple(VERIFICATION_SMOKE_CASES))
async def test_thai_residual_cli_uses_one_independent_verification_call(
    case_id: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    case = VERIFICATION_SMOKE_CASES[case_id]
    forms: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode("utf-8"))
        forms.append(form)
        assert form["context"] == [case.text]
        assert form["prompt"] == [build_verification_prompt()]
        assert form["use_thinking"] == ["false"]
        schema = json.loads(form["json_schema"][0])
        assert set(schema["properties"]) == {"has_pii", "findings"}
        return success(
            {
                "has_pii": True,
                "findings": [{"pii_type": item} for item in case.expected_types],
            }
        )

    client = LlmProxyClient(settings(), transport=httpx.MockTransport(handler))
    patch_cli_client(monkeypatch, client)
    await smoke_llm.main(["--case", case_id])
    assert len(forms) == 1
    output = capsys.readouterr().out
    assert "Max HTTP attempts for this smoke: 1" in output
    assert "Residual PII detected: True" in output
    assert "Residual location scope: window" in output
    for pii_type in case.expected_types:
        assert f"Residual type: {pii_type}" in output
    assert "Calling detection" not in output
    assert case.text not in output
    assert "synthetic-acceptance-secret" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["missed", "wrong-type", "extra-type", "legacy", "duplicate", "504", "timeout"],
)
async def test_thai_residual_cli_does_not_accept_miss_or_retry_failure(
    failure: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if failure == "504":
            return httpx.Response(504, text="private-response-canary")
        if failure == "timeout":
            raise httpx.ReadTimeout("private-error-canary", request=request)
        payload: dict[str, object] = {
            "has_pii": True,
            "findings": [{"pii_type": "NAME"}],
        }
        if failure == "missed":
            payload = {"has_pii": False, "findings": []}
        elif failure == "wrong-type":
            payload["findings"] = [{"pii_type": "ADDRESS"}]
        elif failure == "extra-type":
            payload["findings"] = [{"pii_type": "NAME"}, {"pii_type": "ADDRESS"}]
        elif failure == "legacy":
            payload["findings"] = [{"pii_type": "NAME", "start": 0, "end": 1}]
        elif failure == "duplicate":
            payload["findings"] = [{"pii_type": "NAME"}, {"pii_type": "NAME"}]
        return success(payload)

    client = LlmProxyClient(settings(), transport=httpx.MockTransport(handler))
    patch_cli_client(monkeypatch, client)
    with pytest.raises(SystemExit) as caught:
        await smoke_llm.main(["--case", "thai-residual-name"])
    assert caught.value.code == 1 and calls == 1
    output = capsys.readouterr().out
    assert "Residual verification elapsed seconds:" in output
    assert "Residual PII detected:" not in output
    assert "private-response-canary" not in output
    assert "private-error-canary" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", NEGATIVE_FALSE_POSITIVES)
async def test_negative_hybrid_path_preserves_source_and_emits_no_entries(
    case_id: str,
) -> None:
    case = SMOKE_CASES[case_id]
    forms: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode("utf-8"))
        forms.append(form)
        assert form["context"] == [case.text]
        if len(forms) == 1:
            return success({"candidates": []})
        assert len(forms) == 2
        return success({"has_pii": False, "findings": []})

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        result = await process_markdown_with_recovery_async(
            case.text,
            LlmDocumentProcessor(client, whole, whole),
            rule_detectors=(detect_thai_labeled_numbers,),
            rules_has_pii=make_detection_checker([detect_thai_labeled_numbers]),
            policy=RecoveryPolicy(),
        )
    assert result.redacted_markdown == case.text
    assert not result.entries
    assert len(forms) == 2
