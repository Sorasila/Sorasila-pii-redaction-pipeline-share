import traceback

import httpx
import pytest

from pii_pipeline.llm.config import LLM_PROXY_MODEL
from pii_pipeline.llm.proxy import (
    PROXY_RESPONSE_REASON_CODES,
    LlmProxyHttpError,
    LlmProxyResponseError,
    extract_http_structured_output,
    extract_structured_output,
)


def test_extract_structured_output_accepts_observed_success_envelope() -> None:
    structured_output = {"candidates": []}
    envelope = {
        "status": "success",
        "structured_output": structured_output,
        "schema_used": {"type": "object"},
        "model": LLM_PROXY_MODEL,
    }

    assert extract_structured_output(envelope) is structured_output


def test_extract_structured_output_allows_additional_envelope_metadata() -> None:
    structured_output = {"has_pii": False, "findings": []}
    envelope = {
        "status": "success",
        "structured_output": structured_output,
        "model": LLM_PROXY_MODEL,
        "request_id": "synthetic-request-id",
    }

    assert extract_structured_output(envelope) is structured_output


@pytest.mark.parametrize(
    "envelope,reason_code",
    [
        (None, "invalid_envelope"),
        ([], "invalid_envelope"),
        ({}, "unsuccessful_envelope"),
        (
            {
                "status": "failed",
                "structured_output": {},
                "model": LLM_PROXY_MODEL,
            },
            "unsuccessful_envelope",
        ),
        ({"status": "success", "structured_output": {}}, "unexpected_model"),
        (
            {
                "status": "success",
                "structured_output": {},
                "model": "unapproved-model",
            },
            "unexpected_model",
        ),
        (
            {
                "status": "success",
                "structured_output": None,
                "model": LLM_PROXY_MODEL,
            },
            "invalid_structured_output",
        ),
        (
            {
                "status": "success",
                "structured_output": [],
                "model": LLM_PROXY_MODEL,
            },
            "invalid_structured_output",
        ),
    ],
)
def test_extract_structured_output_rejects_invalid_envelope(
    envelope: object, reason_code: str
) -> None:
    with pytest.raises(LlmProxyResponseError, match="response is invalid") as captured:
        extract_structured_output(envelope)

    assert captured.value.reason_code == reason_code


def test_extract_structured_output_uses_configured_expected_model() -> None:
    envelope = {
        "status": "success",
        "structured_output": {"candidates": []},
        "model": "deployment-alias",
    }

    assert extract_structured_output(
        envelope,
        expected_model="deployment-alias",
    ) == {"candidates": []}


def test_proxy_response_error_does_not_disclose_response_values() -> None:
    sensitive_value = "Synthetic Person"
    envelope = {
        "status": "failed",
        "structured_output": {"value": sensitive_value},
        "model": LLM_PROXY_MODEL,
    }

    with pytest.raises(LlmProxyResponseError) as captured_error:
        extract_structured_output(envelope)

    assert str(captured_error.value) == "LLM proxy response is invalid"
    assert sensitive_value not in str(captured_error.value)
    assert captured_error.value.reason_code == "unsuccessful_envelope"


def test_extract_http_structured_output_accepts_json_200_response() -> None:
    structured_output = {"candidates": []}
    response = httpx.Response(
        200,
        headers={"Content-Type": "application/json; charset=utf-8"},
        json={
            "status": "success",
            "structured_output": structured_output,
            "model": LLM_PROXY_MODEL,
        },
    )

    assert extract_http_structured_output(response) == structured_output


@pytest.mark.parametrize(
    "status_code", [201, 202, 204, 400, 401, 403, 429, 500, 502, 503, 504]
)
def test_extract_http_structured_output_requires_exact_status_200(
    status_code: int,
) -> None:
    response = httpx.Response(
        status_code,
        headers={"Content-Type": "application/json"},
        json={
            "status": "success",
            "structured_output": {"candidates": []},
            "model": LLM_PROXY_MODEL,
        },
    )

    with pytest.raises(
        LlmProxyHttpError, match="request was not successful"
    ) as captured_error:
        extract_http_structured_output(response)

    assert captured_error.value.status_code == status_code


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "text/html", "application/problem+json"],
)
def test_extract_http_structured_output_requires_json_content_type(
    content_type: str | None,
) -> None:
    headers = {} if content_type is None else {"Content-Type": content_type}
    response = httpx.Response(
        200,
        headers=headers,
        content=b'{"status":"success"}',
    )

    with pytest.raises(LlmProxyResponseError, match="response is invalid") as captured:
        extract_http_structured_output(response)

    assert captured.value.reason_code == "unexpected_content_type"


@pytest.mark.parametrize("content", [b"not-json", b"\xff"])
def test_extract_http_structured_output_rejects_invalid_json(content: bytes) -> None:
    response = httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        content=content,
    )

    with pytest.raises(LlmProxyResponseError, match="response is invalid") as captured:
        extract_http_structured_output(response)

    assert captured.value.reason_code == "invalid_json"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_http_error_does_not_disclose_response_body() -> None:
    sensitive_value = "Synthetic Person"
    response = httpx.Response(
        500,
        headers={"Content-Type": "application/json"},
        json={"error": sensitive_value},
    )

    with pytest.raises(LlmProxyHttpError) as captured_error:
        extract_http_structured_output(response)

    assert str(captured_error.value) == "LLM proxy request was not successful"
    assert sensitive_value not in str(captured_error.value)
    assert captured_error.value.status_code == 500


@pytest.mark.parametrize(
    "status_code", [None, True, False, "Bob synthetic-secret", 504.0, 99, 600]
)
def test_http_error_discards_invalid_or_sensitive_status(status_code: object) -> None:
    error = LlmProxyHttpError(
        "LLM proxy request was not successful", status_code=status_code
    )

    assert error.status_code is None
    assert str(error) == "LLM proxy request was not successful"
    assert "Bob" not in repr(error)
    assert "synthetic-secret" not in repr(error)


def test_http_error_preserves_legacy_no_argument_constructor() -> None:
    error = LlmProxyHttpError()

    assert error.args == ()
    assert error.status_code is None


def test_http_error_status_code_is_readonly() -> None:
    error = LlmProxyHttpError("LLM proxy request was not successful", status_code=504)

    with pytest.raises(AttributeError):
        error.status_code = 200  # type: ignore[misc]

    assert error.status_code == 504


def test_extract_http_structured_output_rejects_non_response_object() -> None:
    with pytest.raises(LlmProxyResponseError, match="response is invalid") as captured:
        extract_http_structured_output(object())  # type: ignore[arg-type]

    assert captured.value.reason_code == "invalid_http_response"


def test_proxy_response_reason_codes_are_fixed_and_immutable() -> None:
    assert PROXY_RESPONSE_REASON_CODES == frozenset(
        {
            "invalid_response",
            "invalid_http_response",
            "unexpected_content_type",
            "invalid_json",
            "invalid_envelope",
            "unsuccessful_envelope",
            "unexpected_model",
            "invalid_structured_output",
        }
    )
    assert isinstance(PROXY_RESPONSE_REASON_CODES, frozenset)


@pytest.mark.parametrize("reason_code", sorted(PROXY_RESPONSE_REASON_CODES))
def test_proxy_response_error_keeps_generic_args_and_allowlisted_reason(
    reason_code: str,
) -> None:
    error = LlmProxyResponseError(
        "LLM proxy response is invalid", reason_code=reason_code
    )

    assert error.args == ("LLM proxy response is invalid",)
    assert str(error) == "LLM proxy response is invalid"
    assert error.reason_code == reason_code


@pytest.mark.parametrize(
    "untrusted_reason",
    [
        "Synthetic Person private-response-canary",
        "UNEXPECTED_MODEL",
        " unexpected_model ",
        "",
        None,
        True,
        504,
        1.5,
        b"invalid_json",
        [],
        ["invalid_json"],
        {"value": "private-response-canary"},
        {"invalid_json"},
    ],
)
def test_proxy_response_error_discards_unknown_or_non_string_reason_without_echo(
    untrusted_reason: object,
) -> None:
    error = LlmProxyResponseError(
        "LLM proxy response is invalid", reason_code=untrusted_reason
    )

    assert error.reason_code == "invalid_response"
    assert error.args == ("LLM proxy response is invalid",)
    rendered = (
        repr(error) + repr(vars(error)) + "".join(traceback.format_exception(error))
    )
    assert "Synthetic Person" not in rendered
    assert "private-response-canary" not in rendered


def test_proxy_response_error_preserves_legacy_constructor_and_readonly_reason() -> (
    None
):
    error = LlmProxyResponseError()
    assert error.args == ()
    assert error.reason_code == "invalid_response"
    legacy = LlmProxyResponseError("LLM proxy response is invalid")
    assert legacy.args == ("LLM proxy response is invalid",)
    assert legacy.reason_code == "invalid_response"
    with pytest.raises(AttributeError):
        legacy.reason_code = "invalid_json"  # type: ignore[misc]


@pytest.mark.parametrize(
    "envelope,reason_code",
    [
        ("private-response-canary", "invalid_envelope"),
        (
            {"status": "private-response-canary", "value": "Synthetic Person"},
            "unsuccessful_envelope",
        ),
        (
            {"status": "success", "model": "private-response-canary"},
            "unexpected_model",
        ),
        (
            {
                "status": "success",
                "model": LLM_PROXY_MODEL,
                "structured_output": "private-response-canary",
            },
            "invalid_structured_output",
        ),
    ],
)
def test_proxy_envelope_reasons_never_retain_or_disclose_invalid_content(
    envelope: object,
    reason_code: str,
) -> None:
    with pytest.raises(LlmProxyResponseError) as captured:
        extract_structured_output(envelope)

    error = captured.value
    assert error.args == ("LLM proxy response is invalid",)
    assert error.reason_code == reason_code
    assert error.__cause__ is None
    assert error.__context__ is None
    rendered = (
        repr(error) + repr(vars(error)) + "".join(traceback.format_exception(error))
    )
    for canary in ("private-response-canary", "Synthetic Person"):
        assert canary not in rendered


@pytest.mark.parametrize(
    "content_type", ["text/html; private-header-canary", "application/json"]
)
def test_proxy_http_response_reasons_never_retain_decoder_context_or_headers(
    content_type: str,
) -> None:
    response = httpx.Response(
        200,
        headers={"Content-Type": content_type, "X-Private": "private-header-canary"},
        content=b"Synthetic Person private-body-canary",
        request=httpx.Request(
            "POST", "https://private-url-canary.example/structured-output"
        ),
    )
    with pytest.raises(LlmProxyResponseError) as captured:
        extract_http_structured_output(response)

    error = captured.value
    assert error.reason_code == (
        "invalid_json"
        if content_type == "application/json"
        else "unexpected_content_type"
    )
    assert error.args == ("LLM proxy response is invalid",)
    assert error.__cause__ is None
    assert error.__context__ is None
    rendered = (
        repr(error) + repr(vars(error)) + "".join(traceback.format_exception(error))
    )
    for canary in (
        "Synthetic Person",
        "private-body-canary",
        "private-header-canary",
        "private-url-canary",
    ):
        assert canary not in rendered
