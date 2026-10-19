"""Guard failures remain one-call failures and emit only closed diagnostics."""

import os

import httpx
import pytest

import smoke_llm
from pii_pipeline.llm.client import LlmProxyClient
from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm.proxy import LlmProxyResponseError


@pytest.fixture(autouse=True)
def isolate_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(name)


@pytest.mark.asyncio
@pytest.mark.parametrize("max_retries", [0, 2])
@pytest.mark.parametrize(
    "reason",
    [
        "unexpected_content_type",
        "invalid_json",
        "invalid_envelope",
        "unsuccessful_envelope",
        "unexpected_model",
        "invalid_structured_output",
    ],
)
async def test_invalid_proxy_response_cli_stops_without_retry_or_sensitive_output(
    reason: str,
    max_retries: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sensitive = "Synthetic response person and secret canary"
    body: object = {
        "status": "success",
        "model": LLM_PROXY_MODEL,
        "structured_output": {"candidates": []},
        "debug": sensitive,
    }
    if reason == "invalid_envelope":
        body = [sensitive]
    elif reason == "unsuccessful_envelope":
        body["status"] = sensitive
    elif reason == "unexpected_model":
        body["model"] = sensitive
    elif reason == "invalid_structured_output":
        body["structured_output"] = sensitive
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if reason == "unexpected_content_type":
            return httpx.Response(
                200, headers={"Content-Type": "text/html"}, text=sensitive
            )
        if reason == "invalid_json":
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, text=sensitive
            )
        return httpx.Response(200, json=body)

    def configured_client(configured: LlmProxySettings) -> LlmProxyClient:
        return LlmProxyClient(configured, transport=httpx.MockTransport(handler))

    configured = LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-diagnostic-secret",
        max_retries=max_retries,
        _env_file=None,
    )
    monkeypatch.setattr(smoke_llm, "LlmProxySettings", lambda **kwargs: configured)
    monkeypatch.setattr(smoke_llm, "LlmProxyClient", configured_client)
    with pytest.raises(SystemExit) as captured:
        await smoke_llm.main(
            ["--case", "ocr-whitespace-fields", "--max-retries", str(max_retries)]
        )
    assert captured.value.code == 1 and calls == 1
    output = capsys.readouterr().out
    assert "Error type: LlmProxyResponseError" in output
    assert f"Proxy response reason: {reason}" in output
    assert "Calling verification" not in output and "Redaction correct:" not in output
    for secret in (sensitive, "synthetic-diagnostic-secret", "llm-proxy.example"):
        assert secret not in output


@pytest.mark.parametrize("unsafe_reason", ["Synthetic private reason", [], None, 42])
def test_manual_diagnostic_rechecks_allowlist_even_if_error_is_tampered(
    unsafe_reason: object, capsys: pytest.CaptureFixture[str]
) -> None:
    error = LlmProxyResponseError("Synthetic private error message")
    error._reason_code = unsafe_reason
    smoke_llm.show_error_types(error)
    assert capsys.readouterr().out == (
        "Error type: LlmProxyResponseError\nProxy response reason: invalid_response\n"
    )
