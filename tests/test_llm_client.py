import asyncio
import json
import os
import ssl
import traceback
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from pii_pipeline.llm.client import LlmProxyClient
from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm.proxy import (
    LlmProxyConfigurationError,
    LlmProxyHttpError,
    LlmProxyRequestError,
    LlmProxyResponseError,
    LlmProxyTimeoutError,
    LlmProxyTransportError,
)
from pii_pipeline.llm.response import DetectionResponseError, VerificationResponseError
from pii_pipeline.llm.schema import (
    build_detection_response_schema,
    build_verification_response_schema,
)


@pytest.fixture(autouse=True)
def isolate_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(name)


def make_settings(**overrides: object) -> LlmProxySettings:
    return LlmProxySettings(
        base_url="https://llm-proxy.example/service",
        api_key="synthetic-secret",
        _env_file=None,
        **overrides,
    )


def success(output: dict[str, object] | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": LLM_PROXY_MODEL,
            "structured_output": {"candidates": []} if output is None else output,
        },
    )


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.delays: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.delays.append(delay)
        self.now += delay


async def request_output(
    client: LlmProxyClient, **overrides: object
) -> dict[str, object]:
    arguments = {
        "context": "ชื่อ: ตัวอย่าง ทดสอบ",
        "json_schema": build_detection_response_schema(),
        "prompt": "Extract PII from the supplied data without rewriting it.",
        "use_thinking": False,
    }
    arguments.update(overrides)
    return await client.structured_output(**arguments)


@pytest.mark.asyncio
async def test_detect_form_preserves_unicode_newlines_and_literal_escape_markers() -> (
    None
):
    source = "Name: Alice\nLiteral marker: \\n\nภาษาไทย: Café"
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        form = parse_qs(request.content.decode("utf-8"))
        assert form["context"] == [source]
        assert form["context"][0].count("\n") == 2
        assert r"\n" in form["context"][0]
        return success({"candidates": [{"pii_type": "NAME", "value": "Alice"}]})

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        matches = await client.detect(source, prompt="Extract exact PII source spans.")
    assert calls == 1
    assert len(matches) == 1
    assert (matches[0].start, matches[0].end) == (6, 11)
    assert source[matches[0].start : matches[0].end] == matches[0].value


@pytest.mark.asyncio
async def test_client_sends_exact_form_bearer_and_phase_timeouts() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return success()

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        assert await request_output(client) == {"candidates": []}

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == "https://llm-proxy.example/service/structured-output"
    assert request.headers["authorization"] == "Bearer synthetic-secret"
    assert request.headers["accept"] == "application/json"
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    form = parse_qs(request.content.decode("utf-8"))
    assert set(form) == {"context", "json_schema", "prompt", "model", "use_thinking"}
    assert form["context"] == ["ชื่อ: ตัวอย่าง ทดสอบ"]
    assert json.loads(form["json_schema"][0]) == build_detection_response_schema()
    assert form["model"] == [LLM_PROXY_MODEL]
    assert form["use_thinking"] == ["false"]
    assert request.extensions["timeout"] == {
        "connect": 10,
        "read": 300,
        "write": 30,
        "pool": 10,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
async def test_client_retries_selected_server_error_then_succeeds(
    status_code: int,
) -> None:
    clock = FakeClock()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status_code) if calls == 1 else success()

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        assert await request_output(client) == {"candidates": []}

    assert calls == 2
    assert clock.delays == [1]


@pytest.mark.asyncio
async def test_client_stops_after_initial_attempt_and_two_retries() -> None:
    clock = FakeClock()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response((502, 503, 504)[calls - 1], text="Synthetic Person")

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        with pytest.raises(LlmProxyHttpError) as captured_error:
            await request_output(client)

    assert calls == 3
    assert clock.delays == [1, 2]
    assert captured_error.value.status_code == 504
    assert "Synthetic Person" not in str(captured_error.value)


@pytest.mark.asyncio
async def test_client_obeys_disabled_retry_policy() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async with LlmProxyClient(
        make_settings(max_retries=0), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(LlmProxyHttpError) as captured_error:
            await request_output(client)

    assert calls == 1
    assert captured_error.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status_code", [201, 202, 301, 307, 400, 401, 403, 408, 429, 501]
)
async def test_client_does_not_retry_other_statuses_or_follow_redirects(
    status_code: int,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            status_code, headers={"Location": "https://other-host.example"}
        )

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(LlmProxyHttpError) as captured_error:
            await request_output(client)

    assert calls == 1
    assert captured_error.value.status_code == status_code


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type",
    [
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
        httpx.ConnectError,
        httpx.ReadError,
        httpx.WriteError,
    ],
)
async def test_client_retries_timeout_or_network_failure_then_succeeds(
    error_type: type[httpx.TransportError],
) -> None:
    clock = FakeClock()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise error_type("synthetic failure", request=request)
        return success()

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        assert await request_output(client) == {"candidates": []}

    assert calls == 2
    assert clock.delays == [1]


@pytest.mark.asyncio
@pytest.mark.parametrize("want_type", [ssl.SSLWantReadError, ssl.SSLWantWriteError])
@pytest.mark.parametrize("chain_attribute", ["__cause__", "__context__"])
async def test_client_retries_read_timeout_with_nonblocking_ssl_signal(
    want_type: type[ssl.SSLError],
    chain_attribute: str,
) -> None:
    clock = FakeClock()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            waiting = want_type("synthetic pending I/O")
            cancelled = asyncio.CancelledError()
            setattr(cancelled, chain_attribute, waiting)
            timeout = TimeoutError("synthetic timeout")
            setattr(timeout, chain_attribute, cancelled)
            raise httpx.ReadTimeout("synthetic wrapper", request=request) from timeout
        return success()

    async with LlmProxyClient(
        make_settings(max_retries=1),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        assert await request_output(client) == {"candidates": []}

    assert calls == 2
    assert clock.delays == [1]


@pytest.mark.asyncio
async def test_client_nonblocking_ssl_signal_does_not_hide_certificate_failure() -> (
    None
):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        waiting = ssl.SSLWantReadError("synthetic pending I/O")
        waiting.__cause__ = ssl.SSLCertVerificationError(
            "synthetic certificate failure"
        )
        raise httpx.ReadTimeout("synthetic wrapper", request=request) from waiting

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(LlmProxyTransportError):
            await request_output(client)

    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type",
    [
        httpx.RemoteProtocolError,
        httpx.LocalProtocolError,
        httpx.ProxyError,
        RuntimeError,
    ],
)
async def test_client_sanitizes_and_does_not_retry_other_transport_failures(
    error_type: type[Exception], caplog: pytest.LogCaptureFixture
) -> None:
    calls = 0
    sensitive_message = "synthetic-secret Synthetic Person"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise error_type(sensitive_message)

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(LlmProxyTransportError) as captured:
            await request_output(client, context="Synthetic Person")

    rendered = "".join(traceback.format_exception(captured.value))
    assert sensitive_message not in rendered
    assert "synthetic-secret" not in caplog.text
    assert "Synthetic Person" not in caplog.text
    assert captured.value.__suppress_context__ is True
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tls_error_type", "chain_attribute"),
    [
        (ssl.SSLCertVerificationError, "__cause__"),
        (ssl.SSLError, "__cause__"),
        (ssl.SSLCertVerificationError, "__context__"),
    ],
)
async def test_client_does_not_retry_certificate_error_wrapped_by_transport(
    tls_error_type: type[ssl.SSLError], chain_attribute: str
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        certificate_error = tls_error_type("synthetic certificate failure")
        intermediate = OSError("synthetic wrapper")
        setattr(intermediate, chain_attribute, certificate_error)
        raise httpx.ConnectError("synthetic wrapper", request=request) from intermediate

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(LlmProxyTransportError):
            await request_output(client)

    assert calls == 1


@pytest.mark.asyncio
async def test_client_sanitizes_exhausted_transport_failure() -> None:
    clock = FakeClock()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("synthetic-secret Synthetic Person", request=request)

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        with pytest.raises(LlmProxyTransportError) as captured:
            await request_output(client)

    assert calls == 3
    assert clock.delays == [1, 2]
    assert "synthetic-secret" not in "".join(traceback.format_exception(captured.value))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not-json"),
        httpx.Response(
            200, headers={"Content-Type": "application/json"}, text="not-json"
        ),
        httpx.Response(200, json={"status": "failed"}),
        httpx.Response(200, json={"status": "success", "model": "wrong-model"}),
    ],
)
async def test_client_does_not_retry_invalid_response(response: httpx.Response) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return response

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(LlmProxyResponseError):
            await request_output(client)

    assert calls == 1


@pytest.mark.asyncio
async def test_client_deadline_counts_attempt_time_and_clamps_next_phase_timeouts() -> (
    None
):
    clock = FakeClock()
    timeouts: list[dict[str, float]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"])
        if len(timeouts) == 1:
            clock.now += 595
            return httpx.Response(503)
        return success()

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        assert await request_output(client) == {"candidates": []}

    assert clock.delays == [1]
    assert timeouts[1] == {"connect": 4, "read": 4, "write": 4, "pool": 4}


@pytest.mark.asyncio
async def test_client_does_not_sleep_or_retry_when_backoff_would_exhaust_deadline() -> (
    None
):
    clock = FakeClock()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        clock.now += 599.5
        return httpx.Response(503)

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        with pytest.raises(LlmProxyTimeoutError):
            await request_output(client)

    assert calls == 1
    assert clock.delays == []


@pytest.mark.asyncio
async def test_client_rejects_success_received_after_deadline() -> None:
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        clock.now += 600
        return success()

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        with pytest.raises(LlmProxyTimeoutError):
            await request_output(client)


@pytest.mark.asyncio
async def test_expired_deadline_during_transport_error_suppresses_sensitive_context() -> (
    None
):
    clock = FakeClock()

    def handler(request: httpx.Request) -> httpx.Response:
        clock.now += 600
        raise httpx.ReadTimeout("synthetic-secret Synthetic Person", request=request)

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        with pytest.raises(LlmProxyTimeoutError) as captured:
            await request_output(client)

    rendered = "".join(traceback.format_exception(captured.value))
    assert "synthetic-secret" not in rendered
    assert "Synthetic Person" not in rendered
    assert clock.delays == []


@pytest.mark.asyncio
async def test_client_checks_deadline_again_after_backoff() -> None:
    clock = FakeClock()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async def delayed_sleep(delay: float) -> None:
        clock.now += 600

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=delayed_sleep,
    ) as client:
        with pytest.raises(LlmProxyTimeoutError):
            await request_output(client)

    assert calls == 1


@pytest.mark.asyncio
async def test_client_deadline_cancels_in_flight_request_without_real_sleep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_timeout = asyncio.timeout
    budgets: list[float] = []
    was_cancelled = False

    def expire_immediately(delay: float) -> asyncio.Timeout:
        budgets.append(delay)
        return real_timeout(0)

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal was_cancelled
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            was_cancelled = True
            raise
        return success()

    monkeypatch.setattr(asyncio, "timeout", expire_immediately)
    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler), clock=FakeClock()
    ) as client:
        with pytest.raises(LlmProxyTimeoutError):
            await request_output(client)

    assert budgets == [600]
    assert was_cancelled is True


@pytest.mark.asyncio
async def test_client_deadline_cancels_backoff_without_real_sleep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_timeout = asyncio.timeout
    calls = 0
    sleep_was_cancelled = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async def blocked_sleep(delay: float) -> None:
        nonlocal sleep_was_cancelled
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            sleep_was_cancelled = True
            raise

    monkeypatch.setattr(asyncio, "timeout", lambda delay: real_timeout(0))
    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=FakeClock(),
        sleep=blocked_sleep,
    ) as client:
        with pytest.raises(LlmProxyTimeoutError):
            await request_output(client)

    assert calls == 1
    assert sleep_was_cancelled is True


@pytest.mark.asyncio
async def test_client_propagates_external_cancellation_without_retry() -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise asyncio.CancelledError

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(asyncio.CancelledError):
            await request_output(client)

    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"context": None},
        {"context": " "},
        {"context": "Cafe\u0301"},
        {"json_schema": []},
        {"json_schema": {"invalid": object()}},
        {"json_schema": {"invalid": float("nan")}},
        {"prompt": " "},
        {"use_thinking": "false"},
    ],
)
async def test_client_rejects_invalid_input_before_network(
    overrides: dict[str, object],
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success()

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(LlmProxyRequestError):
            await request_output(client, **overrides)

    assert calls == 0


@pytest.mark.asyncio
async def test_client_does_not_apply_ingress_character_limit_to_llm_context() -> None:
    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(lambda request: success())
    ) as client:
        assert await request_output(client, context="ก" * 2001) == {"candidates": []}


@pytest.mark.asyncio
async def test_client_detection_and_verification_use_separate_schemas_and_settings() -> (
    None
):
    forms: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        forms.append(parse_qs(request.content.decode("utf-8")))
        if len(forms) == 1:
            return success({"candidates": [{"pii_type": "NAME", "value": "Alice"}]})
        return success({"has_pii": False, "findings": []})

    async with LlmProxyClient(
        make_settings(detection_use_thinking=False, verification_use_thinking=True),
        transport=httpx.MockTransport(handler),
    ) as client:
        matches = await client.detect("Alice", prompt="Extract PII from data.")
        verification = await client.verify("[PII_NAME_1]", prompt="Check residual PII.")

    assert len(matches) == 1
    assert matches[0].value == "Alice"
    assert (matches[0].start, matches[0].end) == (0, 5)
    assert verification.has_pii is False
    assert json.loads(forms[0]["json_schema"][0]) == build_detection_response_schema()
    assert (
        json.loads(forms[1]["json_schema"][0]) == build_verification_response_schema()
    )
    assert forms[0]["use_thinking"] == ["false"]
    assert forms[1]["use_thinking"] == ["true"]
    assert forms[1]["context"] == ["[PII_NAME_1]"]


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["detect", "verify"])
async def test_client_role_parser_rejects_invalid_structured_output_without_retry(
    operation: str,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success({"invalid": "Synthetic Person"})

    error_type = (
        DetectionResponseError if operation == "detect" else VerificationResponseError
    )
    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(error_type):
            await getattr(client, operation)("Synthetic Person", prompt="Inspect data.")

    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output",
    [
        {"candidates": [{"pii_type": "NAME", "value": "Bobby"}]},
        {"candidates": [{"pii_type": "NAME", "value": "Alice", "anchor": "Alice"}]},
        {"candidates": [{"pii_type": "NAME", "value": "Alice", "start": 0, "end": 5}]},
        {"candidates": [{"value": "Alice"}]},
    ],
)
async def test_client_detection_rejects_invalid_candidates_without_retry(
    output: dict[str, object],
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success(output)

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(DetectionResponseError):
            await client.detect("Alice", prompt="Extract PII from data.")

    assert calls == 1


@pytest.mark.asyncio
async def test_client_verification_returns_residual_pii_findings() -> None:
    output = {"has_pii": True, "findings": [{"pii_type": "NAME"}]}
    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(lambda request: success(output))
    ) as client:
        result = await client.verify("Alice", prompt="Find residual PII in data.")

    assert result.has_pii is True
    assert len(result.findings) == 1
    assert result.findings[0].pii_type == "NAME"
    assert (result.findings[0].start, result.findings[0].end) == (0, 5)
    assert result.findings[0].location_scope == "window"


@pytest.mark.asyncio
async def test_client_verification_rejects_echoed_pii_value() -> None:
    output = {
        "has_pii": True,
        "findings": [{"pii_type": "NAME", "value": "Alice"}],
    }
    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(lambda request: success(output))
    ) as client:
        with pytest.raises(VerificationResponseError):
            await client.verify("Alice", prompt="Find residual PII in data.")


@pytest.mark.asyncio
async def test_client_verification_rejects_legacy_offsets_without_retry() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return success(
            {
                "has_pii": True,
                "findings": [{"pii_type": "CASE_NUMBER", "start": 15, "end": 29}],
            }
        )

    async with LlmProxyClient(
        make_settings(max_retries=2), transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(VerificationResponseError) as captured:
            await client.verify(
                "คดีหมายเลขดำที่ 123456789/2569", prompt="Check residual PII."
            )

    assert calls == 1
    assert captured.value.reason_code == "invalid_finding_shape"


@pytest.mark.asyncio
async def test_role_parser_cannot_return_success_after_consuming_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()

    def slow_parser(source: str, response: object) -> list[object]:
        clock.now += 600
        return []

    monkeypatch.setattr(
        "pii_pipeline.llm.client.parse_detection_candidates", slow_parser
    )
    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(lambda request: success()),
        clock=clock,
    ) as client:
        with pytest.raises(LlmProxyTimeoutError):
            await client.detect("Alice", prompt="Extract PII from data.")


class TrackingStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.was_read = False
        self.was_closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.was_read = True
        yield b"Synthetic Person"

    async def aclose(self) -> None:
        self.was_closed = True


@pytest.mark.asyncio
async def test_client_closes_error_response_without_reading_body() -> None:
    stream = TrackingStream()

    async with LlmProxyClient(
        make_settings(max_retries=0),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(503, stream=stream)
        ),
    ) as client:
        with pytest.raises(LlmProxyHttpError) as captured_error:
            await request_output(client)

    assert stream.was_read is False
    assert stream.was_closed is True
    assert captured_error.value.status_code == 503


@pytest.mark.asyncio
async def test_client_closes_stream_after_body_read_failure_before_retry() -> None:
    clock = FakeClock()
    attempts = 0
    closed = False

    class FailingStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            raise httpx.ReadTimeout("synthetic-secret Synthetic Person")
            yield b""  # An async generator models the response byte-stream interface.

        async def aclose(self) -> None:
            nonlocal closed
            closed = True

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                stream=FailingStream(),
            )
        assert closed is True
        return success()

    async with LlmProxyClient(
        make_settings(),
        transport=httpx.MockTransport(handler),
        clock=clock,
        sleep=clock.sleep,
    ) as client:
        assert await request_output(client) == {"candidates": []}

    assert attempts == 2
    assert clock.delays == [1]


@pytest.mark.asyncio
async def test_client_closes_owned_transport_when_context_exits() -> None:
    was_closed = False

    class TrackingTransport(httpx.MockTransport):
        async def aclose(self) -> None:
            nonlocal was_closed
            was_closed = True
            await super().aclose()

    async with LlmProxyClient(
        make_settings(), transport=TrackingTransport(lambda request: success())
    ) as client:
        assert await request_output(client) == {"candidates": []}
        assert was_closed is False

    assert was_closed is True


@pytest.mark.asyncio
async def test_client_factory_keeps_tls_enabled_and_disables_redirects_and_env_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = httpx.AsyncClient
    captured: dict[str, object] = {}

    def capture_factory(**kwargs: object) -> httpx.AsyncClient:
        captured.update(kwargs)
        return factory(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", capture_factory)
    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(lambda request: success())
    ) as client:
        assert await request_output(client) == {"candidates": []}

    context = captured["verify"]
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False


@pytest.mark.asyncio
async def test_client_loads_explicit_ca_into_verified_ssl_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "synthetic-ca.pem"
    bundle.write_text("mocked certificate", encoding="utf-8")
    context = ssl.create_default_context()
    loaded: list[str] = []

    def load_ca(self: ssl.SSLContext, *, cafile: str) -> None:
        assert self is context
        loaded.append(cafile)

    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", load_ca)
    async with LlmProxyClient(
        make_settings(ca_bundle=bundle),
        transport=httpx.MockTransport(lambda request: success()),
    ) as client:
        assert await request_output(client) == {"candidates": []}

    assert loaded == [str(bundle)]
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.asyncio
async def test_client_success_and_http_failure_logs_do_not_disclose_bodies_or_key(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return success()
        return httpx.Response(403, text="Synthetic Person synthetic-secret")

    async with LlmProxyClient(
        make_settings(), transport=httpx.MockTransport(handler)
    ) as client:
        assert await request_output(client, context="Synthetic Person") == {
            "candidates": []
        }
        with pytest.raises(LlmProxyHttpError):
            await request_output(client, context="Synthetic Person")

    assert "synthetic-secret" not in caplog.text
    assert "Synthetic Person" not in caplog.text
    assert "synthetic-secret" not in repr(client)


def test_client_rejects_invalid_ca_bundle_with_sanitized_configuration_error(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "synthetic-private-location.pem"
    bundle.write_text("not a certificate", encoding="utf-8")

    with pytest.raises(LlmProxyConfigurationError) as captured:
        LlmProxyClient(
            make_settings(ca_bundle=bundle),
            transport=httpx.MockTransport(lambda request: success()),
        )

    rendered = "".join(traceback.format_exception(captured.value))
    assert str(bundle) not in rendered
    assert "synthetic-secret" not in rendered


@pytest.mark.asyncio
async def test_client_can_disable_tls_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = httpx.AsyncClient
    captured: dict[str, object] = {}

    def capture_factory(**kwargs: object) -> httpx.AsyncClient:
        captured.update(kwargs)
        return factory(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", capture_factory)

    async with LlmProxyClient(
        make_settings(verify_tls=False),
        transport=httpx.MockTransport(lambda request: success()),
    ) as client:
        assert await request_output(client) == {"candidates": []}

    assert captured["verify"] is False
    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False


@pytest.mark.asyncio
async def test_client_does_not_load_ca_when_tls_verification_disabled(
    tmp_path: Path,
) -> None:
    ca_bundle = tmp_path / "internal-ca.pem"
    ca_bundle.write_text("synthetic non-PEM certificate", encoding="utf-8")

    async with LlmProxyClient(
        make_settings(verify_tls=False, ca_bundle=ca_bundle),
        transport=httpx.MockTransport(lambda request: success()),
    ) as client:
        assert await request_output(client) == {"candidates": []}
