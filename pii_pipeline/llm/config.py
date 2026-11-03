from pathlib import Path
from typing import Self

from pydantic import (
    AnyHttpUrl,
    Field,
    FilePath,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

LLM_PROXY_MODEL = "qwen/qwen3.6-27b"
STRUCTURED_OUTPUT_PATH = "/structured-output"


class LlmProxySettings(BaseSettings):
    """Validated, immutable configuration for the trusted LLM proxy."""

    model_config = SettingsConfigDict(
        env_prefix="LLM_PROXY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    base_url: AnyHttpUrl
    api_key: SecretStr
    model: str = Field(default=LLM_PROXY_MODEL, min_length=1, pattern=r"\S")
    ca_bundle: FilePath | None = None
    verify_tls: bool = True

    connect_timeout_seconds: float = Field(default=10, gt=0, allow_inf_nan=False)
    # Long on purpose (user decision 2026-11-03): a whole page can keep the
    # model busy for many minutes; wait for it rather than retry early.
    read_timeout_seconds: float = Field(default=1800, gt=0, allow_inf_nan=False)
    write_timeout_seconds: float = Field(default=30, gt=0, allow_inf_nan=False)
    pool_timeout_seconds: float = Field(default=10, gt=0, allow_inf_nan=False)
    request_deadline_seconds: float = Field(default=3600, gt=0, allow_inf_nan=False)
    max_retries: int = Field(default=2, ge=0, le=2)
    retry_backoff_seconds: float = Field(default=1, gt=0, allow_inf_nan=False)
    retry_backoff_cap_seconds: float = Field(default=10, gt=0, allow_inf_nan=False)
    detection_use_thinking: bool = False
    verification_use_thinking: bool = False

    @field_validator(
        "connect_timeout_seconds",
        "read_timeout_seconds",
        "write_timeout_seconds",
        "pool_timeout_seconds",
        "request_deadline_seconds",
        "retry_backoff_seconds",
        "retry_backoff_cap_seconds",
        mode="before",
    )
    @classmethod
    def reject_boolean_duration(cls, value: object) -> object:
        if isinstance(value, bool):
            # Pydantic collects ValueError as a configuration error; TypeError escapes.
            raise ValueError("LLM proxy duration is invalid")  # noqa: TRY004

        return value

    @field_validator("max_retries", mode="before")
    @classmethod
    def validate_retry_limit(cls, value: object) -> object:
        if isinstance(value, (bool, float)):
            # Keep invalid input inside Pydantic's configuration validation boundary.
            raise ValueError("LLM proxy retry limit is invalid")  # noqa: TRY004

        return value

    @model_validator(mode="after")
    def validate_execution_limits(self) -> Self:
        phase_timeouts = (
            self.connect_timeout_seconds,
            self.read_timeout_seconds,
            self.write_timeout_seconds,
            self.pool_timeout_seconds,
        )

        if max(phase_timeouts) > self.request_deadline_seconds:
            raise ValueError("LLM proxy phase timeout exceeds request deadline")

        if self.retry_backoff_seconds > self.retry_backoff_cap_seconds:
            raise ValueError("LLM proxy retry backoff exceeds its cap")

        return self

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if (
            value.scheme != "https"
            or value.query
            or value.fragment
            or value.username
            or value.password
        ):
            raise ValueError("LLM proxy base URL is invalid")

        return value

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("LLM proxy API key is invalid")

        return value

    @property
    def structured_output_url(self) -> str:
        return f"{str(self.base_url).rstrip('/')}{STRUCTURED_OUTPUT_PATH}"

    @property
    def tls_verify(self) -> bool | Path:
        """Describe verification mode; the client converts a CA path to SSLContext."""

        if not self.verify_tls:
            return False

        if self.ca_bundle is None:
            return True

        return Path(self.ca_bundle)

    @property
    def max_attempts(self) -> int:
        """Count the initial call plus the permitted additional retries."""

        return 1 + self.max_retries

    @property
    def retry_delays_seconds(self) -> tuple[float, ...]:
        """Bounded exponential delays; the HTTP client must also apply the deadline."""

        return tuple(
            min(self.retry_backoff_cap_seconds, self.retry_backoff_seconds * 2**index)
            for index in range(self.max_retries)
        )
