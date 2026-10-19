from pathlib import Path

import pytest
from pydantic import ValidationError

from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings


def test_llm_proxy_settings_builds_structured_output_url() -> None:
    settings = LlmProxySettings(
        base_url="https://llm-proxy.example:9001/",
        api_key="synthetic-secret",
        _env_file=None,
    )

    assert settings.structured_output_url == (
        "https://llm-proxy.example:9001/structured-output"
    )
    assert settings.model == LLM_PROXY_MODEL
    assert settings.tls_verify is True


def test_llm_proxy_settings_reads_prefixed_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_PROXY_BASE_URL", "https://llm-proxy.example")
    monkeypatch.setenv("LLM_PROXY_API_KEY", "synthetic-secret")
    monkeypatch.setenv("LLM_PROXY_MODEL", LLM_PROXY_MODEL)

    settings = LlmProxySettings(_env_file=None)

    assert str(settings.base_url) == "https://llm-proxy.example/"
    assert settings.api_key.get_secret_value() == "synthetic-secret"


def test_llm_proxy_settings_reads_local_env_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LLM_PROXY_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_PROXY_API_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(
        "LLM_PROXY_BASE_URL=https://llm-proxy.example:9001\n"
        "LLM_PROXY_API_KEY=synthetic-secret\n"
        f"LLM_PROXY_MODEL={LLM_PROXY_MODEL}\n",
        encoding="utf-8",
    )

    settings = LlmProxySettings(_env_file=env_file)

    assert settings.structured_output_url == (
        "https://llm-proxy.example:9001/structured-output"
    )


def test_llm_proxy_settings_hides_api_key_from_repr() -> None:
    secret = "synthetic-secret"
    settings = LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key=secret,
        _env_file=None,
    )

    assert secret not in repr(settings)
    assert secret not in str(settings)
    assert secret not in settings.model_dump_json()


@pytest.mark.parametrize(
    "base_url",
    [
        "http://llm-proxy.example",
        "https://llm-proxy.example?debug=true",
        "https://llm-proxy.example#fragment",
        "https://synthetic-user@llm-proxy.example",
        "https://synthetic-user:synthetic-secret@llm-proxy.example",
    ],
)
def test_llm_proxy_settings_rejects_unsafe_base_url(base_url: str) -> None:
    with pytest.raises(ValidationError, match="base URL is invalid"):
        LlmProxySettings(
            base_url=base_url,
            api_key="synthetic-secret",
            _env_file=None,
        )


@pytest.mark.parametrize("api_key", ["", "   "])
def test_llm_proxy_settings_rejects_empty_api_key(api_key: str) -> None:
    with pytest.raises(ValidationError, match="API key is invalid"):
        LlmProxySettings(
            base_url="https://llm-proxy.example",
            api_key=api_key,
            _env_file=None,
        )


def test_llm_proxy_settings_requires_base_url_and_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LLM_PROXY_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_PROXY_API_KEY", raising=False)

    with pytest.raises(ValidationError):
        LlmProxySettings(_env_file=None)


def test_llm_proxy_settings_rejects_unapproved_model() -> None:
    with pytest.raises(ValidationError):
        LlmProxySettings(
            base_url="https://llm-proxy.example",
            api_key="synthetic-secret",
            model="different-model",  # type: ignore[arg-type]
            _env_file=None,
        )


def test_llm_proxy_settings_uses_configured_ca_bundle(tmp_path: Path) -> None:
    ca_bundle = tmp_path / "internal-ca.pem"
    ca_bundle.write_text("synthetic certificate", encoding="utf-8")
    settings = LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-secret",
        ca_bundle=ca_bundle,
        _env_file=None,
    )

    assert settings.tls_verify == ca_bundle


def test_llm_proxy_settings_rejects_missing_ca_bundle(tmp_path: Path) -> None:
    missing_bundle = tmp_path / "missing-ca.pem"

    with pytest.raises(ValidationError):
        LlmProxySettings(
            base_url="https://llm-proxy.example",
            api_key="synthetic-secret",
            ca_bundle=missing_bundle,
            _env_file=None,
        )


def test_llm_proxy_settings_are_immutable() -> None:
    settings = LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-secret",
        _env_file=None,
    )

    with pytest.raises(ValidationError):
        settings.model = LLM_PROXY_MODEL  # type: ignore[misc]


def test_llm_proxy_settings_can_disable_tls_verification() -> None:
    settings = LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-secret",
        verify_tls=False,
        _env_file=None,
    )

    assert settings.tls_verify is False


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("false", False),
        ("true", True),
    ],
)
def test_llm_proxy_settings_reads_tls_verification_from_environment(
    monkeypatch: pytest.MonkeyPatch,
    raw_value: str,
    expected: bool,
) -> None:
    monkeypatch.setenv("LLM_PROXY_VERIFY_TLS", raw_value)

    settings = LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-secret",
        ca_bundle=None,
        _env_file=None,
    )

    assert settings.verify_tls is expected
    assert settings.tls_verify is expected


@pytest.mark.parametrize("raw_value", ["", "not-a-boolean", "2"])
def test_llm_proxy_settings_rejects_invalid_tls_flag(
    monkeypatch: pytest.MonkeyPatch,
    raw_value: str,
) -> None:
    monkeypatch.setenv("LLM_PROXY_VERIFY_TLS", raw_value)

    with pytest.raises(ValidationError):
        LlmProxySettings(
            base_url="https://llm-proxy.example",
            api_key="synthetic-secret",
            _env_file=None,
        )


def test_llm_proxy_settings_explicit_tls_override_takes_precedence_over_ca(
    tmp_path: Path,
) -> None:
    ca_bundle = tmp_path / "internal-ca.pem"
    ca_bundle.write_text("synthetic certificate", encoding="utf-8")
    settings = LlmProxySettings(
        base_url="https://llm-proxy.example",
        api_key="synthetic-secret",
        ca_bundle=ca_bundle,
        verify_tls=False,
        _env_file=None,
    )

    assert settings.tls_verify is False
