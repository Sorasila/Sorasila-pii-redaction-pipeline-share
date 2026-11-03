import os

import pytest
from pydantic import ValidationError

from pii_pipeline.llm.config import LlmProxySettings
from pii_pipeline.llm.proxy import is_retryable_status_code


@pytest.fixture(autouse=True)
def isolate_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable_name in list(os.environ):
        if variable_name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(variable_name)


def make_settings(**overrides: object) -> LlmProxySettings:
    return LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-secret",
        _env_file=None,
        **overrides,
    )


def test_execution_policy_defaults_match_notebook_and_bounded_retry_budget() -> None:
    settings = make_settings()

    assert settings.connect_timeout_seconds == 10
    assert settings.write_timeout_seconds == 30
    assert settings.pool_timeout_seconds == 10
    assert settings.max_attempts == 3
    assert settings.retry_delays_seconds == (1, 2)
    assert settings.detection_use_thinking is False
    assert settings.verification_use_thinking is False


def test_execution_policy_can_be_overridden_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_PROXY_BASE_URL", "https://llm-proxy.example")
    monkeypatch.setenv("LLM_PROXY_API_KEY", "synthetic-secret")
    monkeypatch.setenv("LLM_PROXY_READ_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("LLM_PROXY_REQUEST_DEADLINE_SECONDS", "120")
    monkeypatch.setenv("LLM_PROXY_MAX_RETRIES", "1")
    monkeypatch.setenv("LLM_PROXY_DETECTION_USE_THINKING", "false")
    monkeypatch.setenv("LLM_PROXY_VERIFICATION_USE_THINKING", "true")

    settings = LlmProxySettings(_env_file=None)

    assert settings.read_timeout_seconds == 60
    assert settings.request_deadline_seconds == 120
    assert settings.max_attempts == 2
    assert settings.retry_delays_seconds == (1,)
    assert settings.detection_use_thinking is False
    assert settings.verification_use_thinking is True


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("connect_timeout_seconds", 0),
        ("read_timeout_seconds", float("inf")),
        ("request_deadline_seconds", float("nan")),
        ("write_timeout_seconds", True),
        ("pool_timeout_seconds", -1),
        ("retry_backoff_cap_seconds", 0),
    ],
)
def test_execution_policy_rejects_invalid_duration(
    field_name: str,
    invalid_value: object,
) -> None:
    with pytest.raises(ValidationError):
        make_settings(**{field_name: invalid_value})


@pytest.mark.parametrize("invalid_value", [-1, 3, True, 1.5, "garbage"])
def test_execution_policy_rejects_invalid_retry_limit(invalid_value: object) -> None:
    with pytest.raises(ValidationError):
        make_settings(max_retries=invalid_value)


@pytest.mark.parametrize("max_retries", [0, 1, 2])
def test_execution_policy_counts_initial_request_separately_from_retries(
    max_retries: int,
) -> None:
    settings = make_settings(max_retries=max_retries)

    assert settings.max_attempts == 1 + max_retries
    assert len(settings.retry_delays_seconds) == max_retries


def test_retry_backoff_is_exponential_and_capped() -> None:
    settings = make_settings(
        retry_backoff_seconds=3,
        retry_backoff_cap_seconds=5,
    )

    assert settings.retry_delays_seconds == (3, 5)


@pytest.mark.parametrize(
    "overrides",
    [
        {"read_timeout_seconds": 200, "request_deadline_seconds": 100},
        {"retry_backoff_seconds": 10, "retry_backoff_cap_seconds": 5},
    ],
)
def test_execution_policy_rejects_inconsistent_limits(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        make_settings(**overrides)


def test_invalid_execution_policy_does_not_reveal_api_key_in_error_text() -> None:
    with pytest.raises(ValidationError) as captured_error:
        make_settings(request_deadline_seconds=100)

    assert "synthetic-secret" not in str(captured_error.value)


@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
def test_execution_policy_allows_retry_for_selected_server_errors(
    status_code: int,
) -> None:
    assert is_retryable_status_code(status_code) is True


@pytest.mark.parametrize("status_code", [200, 202, 400, 401, 403, 408, 429, 501])
def test_execution_policy_does_not_retry_success_client_or_permanent_errors(
    status_code: int,
) -> None:
    assert is_retryable_status_code(status_code) is False
