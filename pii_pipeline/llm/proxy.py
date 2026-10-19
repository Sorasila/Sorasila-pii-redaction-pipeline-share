import httpx

from .config import LLM_PROXY_MODEL

RETRYABLE_HTTP_STATUS_CODES = frozenset({500, 502, 503, 504})
PROXY_RESPONSE_REASON_CODES = frozenset(
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


def is_retryable_status_code(status_code: int) -> bool:
    """Allow bounded retries only for the selected transient server responses."""

    return type(status_code) is int and status_code in RETRYABLE_HTTP_STATUS_CODES


class LlmProxyError(Exception):
    pass


class LlmProxyResponseError(LlmProxyError):
    """Keep generic messages and fixed failure codes, never response data."""

    def __init__(self, *args: object, reason_code: object = "invalid_response") -> None:
        super().__init__(*args)
        self._reason_code = (
            reason_code
            if type(reason_code) is str and reason_code in PROXY_RESPONSE_REASON_CODES
            else "invalid_response"
        )

    @property
    def reason_code(self) -> str:
        return self._reason_code


class LlmProxyHttpError(LlmProxyError):
    """Keep generic messages and a validated status number, never response data."""

    def __init__(self, *args: object, status_code: object = None) -> None:
        super().__init__(*args)
        self._status_code = (
            status_code
            if type(status_code) is int and 100 <= status_code <= 599
            else None
        )

    @property
    def status_code(self) -> int | None:
        return self._status_code


class LlmProxyConfigurationError(LlmProxyError):
    pass


class LlmProxyRequestError(LlmProxyError):
    pass


class LlmProxyTransportError(LlmProxyError):
    def __init__(self, *args: object, retryable: bool = False) -> None:
        super().__init__(*args)
        self.retryable = retryable is True


class LlmProxyTimeoutError(LlmProxyError):
    pass


def is_recoverable_proxy_error(error: Exception) -> bool:
    """Never recover configuration/auth/model/TLS or arbitrary external failures."""
    if isinstance(error, LlmProxyTimeoutError):
        return True
    if isinstance(error, LlmProxyTransportError):
        return error.retryable
    if isinstance(error, LlmProxyHttpError):
        return is_retryable_status_code(error.status_code)
    # A failed generation (status other than success) is transient on the test
    # LLM and is retried within the bounded recovery budget (approved 2026-10-06).
    return isinstance(error, LlmProxyResponseError) and error.reason_code in {
        "invalid_json",
        "invalid_structured_output",
        "unsuccessful_envelope",
    }


def extract_structured_output(
    envelope: object,
    *,
    expected_model: str = LLM_PROXY_MODEL,
) -> dict[str, object]:
    """Validate a decoded success envelope and return only structured output."""

    error_message = "LLM proxy response is invalid"

    if not isinstance(envelope, dict):
        raise LlmProxyResponseError(error_message, reason_code="invalid_envelope")

    if envelope.get("status") != "success":
        raise LlmProxyResponseError(error_message, reason_code="unsuccessful_envelope")

    if envelope.get("model") != expected_model:
        raise LlmProxyResponseError(error_message, reason_code="unexpected_model")

    structured_output = envelope.get("structured_output")

    if not isinstance(structured_output, dict):
        raise LlmProxyResponseError(
            error_message, reason_code="invalid_structured_output"
        )

    return structured_output


def extract_http_structured_output(
    response: httpx.Response,
    *,
    expected_model: str = LLM_PROXY_MODEL,
) -> dict[str, object]:
    """Validate a synchronous HTTP response without disclosing its body."""

    if not isinstance(response, httpx.Response):
        raise LlmProxyResponseError(
            "LLM proxy response is invalid", reason_code="invalid_http_response"
        )

    if response.status_code != 200:
        raise LlmProxyHttpError(
            "LLM proxy request was not successful", status_code=response.status_code
        )

    media_type = response.headers.get("content-type", "").split(";", 1)[0]

    if media_type.strip().lower() != "application/json":
        raise LlmProxyResponseError(
            "LLM proxy response is invalid", reason_code="unexpected_content_type"
        )

    try:
        envelope = response.json()
    except (UnicodeDecodeError, ValueError):
        # Raise after leaving the handler so decoder exceptions cannot retain
        # response bytes or parsed text through the exported error's context.
        pass
    else:
        return extract_structured_output(
            envelope,
            expected_model=expected_model,
        )

    raise LlmProxyResponseError(
        "LLM proxy response is invalid", reason_code="invalid_json"
    )
