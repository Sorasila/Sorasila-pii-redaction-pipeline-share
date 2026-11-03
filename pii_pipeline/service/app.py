"""Deployable composition of the POST /redact adapter.

Run with:  uvicorn pii_pipeline.service:create_service_app --factory

The composition matches the reviewed test runner: the approved Thai rule lane,
the LLM lane with automatic recovery, whole-request windows (one whole page of
at most PII_SERVICE_MAX_SOURCE_CHARACTERS code points goes to the LLM in one
call) and a finite whole-request deadline.

Settings come from the environment (or .env) with the PII_SERVICE_ prefix; the
LLM proxy keeps its own LLM_PROXY_ settings. There is no open default: the
service refuses to start without a caller token and a manifest encryptor.
"""

import base64
import hmac
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..core.verification import make_detection_checker
from ..llm.client import LlmProxyClient
from ..llm.config import LlmProxySettings
from ..llm.processing import LlmDocumentProcessor
from ..llm.windows import TextWindow, make_text_window
from ..recovery.process import RecoveryPolicy
from ..rules.thai import detect_thai_rule_pii
from .docs_login import DocsLogin
from .document_input import DEFAULT_MAX_SOURCE_CHARACTERS
from .http import Authenticator, create_app
from .manifest_store import ManifestStoreSettings, PostgrestManifestStore, is_local_url

logger = logging.getLogger("pii_pipeline.service")

# Marks an envelope whose "ciphertext" is the plaintext manifest. Test only.
UNENCRYPTED_TEST_KID = "UNENCRYPTED-TEST-ONLY"


class ServiceConfigurationError(RuntimeError):
    """The service cannot start safely with the supplied configuration."""


class ServiceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PII_SERVICE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    # Provisional caller authentication until the integration scheme is agreed.
    api_token: SecretStr = Field(min_length=32)
    # Long on purpose (user decision 2026-11-03): a whole page goes to the LLM
    # in one call, so the request waits for it instead of giving up.
    request_deadline_seconds: float = Field(
        default=7200, gt=0, le=86_400, allow_inf_nan=False
    )
    # Largest accepted page in Unicode code points (user decision 2026-11-03).
    max_source_characters: int = Field(
        default=DEFAULT_MAX_SOURCE_CHARACTERS, gt=0, le=1_000_000
    )
    # Encryption design is deferred; this explicit flag is the only way to run
    # without a real encryptor and must never be set in production.
    allow_unencrypted_test_manifest: bool = False
    # Off by default: the response is the redacted Markdown alone, so no PII
    # leaves the service (user decision 2026-10-16). Returning the manifest
    # also returns the metadata, which the manifest is bound to.
    return_manifest: bool = False
    return_metadata: bool = False
    # Swagger UI at /docs for trying the API (test and staging machines).
    enable_docs: bool = False
    # Optional login on the docs page: POST /token turns these into a
    # temporary Bearer token (only with enable_docs; both or neither).
    docs_username: str | None = Field(default=None, min_length=1)
    docs_password: SecretStr | None = Field(default=None, min_length=12)
    docs_token_ttl_seconds: int = Field(default=3600, gt=0, le=86_400)

    @field_validator("api_token")
    @classmethod
    def _reject_example_token(cls, token: SecretStr) -> SecretStr:
        # .env.example placeholders are long enough to pass the length check.
        if token.get_secret_value().startswith("replace-with"):
            raise ValueError("PII_SERVICE_API_TOKEN is still the example value")
        return token


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unencrypted_test_manifest_envelope(
    plaintext: bytes, *, additional_authenticated_data: bytes
) -> bytes:
    """JWE-shaped envelope that does NOT encrypt: ciphertext is the plaintext."""
    protected = json.dumps(
        {
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "kid": UNENCRYPTED_TEST_KID,
            "cty": "application/json",
        }
    ).encode()
    return json.dumps(
        {
            "protected": _b64(protected),
            "encrypted_key": _b64(b"none"),
            "iv": _b64(bytes(12)),
            "ciphertext": _b64(plaintext),
            "tag": _b64(bytes(16)),
            "aad": _b64(additional_authenticated_data),
        }
    ).encode()


def bearer_authenticator(
    token: SecretStr, docs_login: DocsLogin | None = None
) -> Authenticator:
    """The API token, or a temporary docs-login token when that login is on."""
    expected = f"Bearer {token.get_secret_value()}".encode()

    async def authenticate(request: Request) -> bool:
        header = request.headers.get("authorization", "")
        if hmac.compare_digest(header.encode("utf-8", "replace"), expected):
            return True
        scheme, _, value = header.partition(" ")
        return (
            docs_login is not None
            and scheme.lower() == "bearer"
            and docs_login.valid(value.strip())
        )

    return authenticate


def _enable_request_log() -> None:
    """Print the adapter's one-line request outcomes (no document text)."""
    package_logger = logging.getLogger("pii_pipeline")
    if not package_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        package_logger.addHandler(handler)
        package_logger.setLevel(logging.INFO)


def _whole(text: str) -> list[TextWindow]:
    # A request is one whole page, sent to the LLM as one window.
    return [make_text_window(text, 0, len(text))]


def _docs_login(settings: ServiceSettings) -> DocsLogin | None:
    user, password = settings.docs_username, settings.docs_password
    if (user is None) != (password is None):
        raise ServiceConfigurationError(
            "Set both PII_SERVICE_DOCS_USERNAME and PII_SERVICE_DOCS_PASSWORD, or neither"
        )
    if user is None or password is None:
        return None
    if not settings.enable_docs:
        logger.warning("Docs login is off because PII_SERVICE_ENABLE_DOCS is not set")
        return None
    logger.warning("Docs login is on: POST /token issues temporary tokens")
    return DocsLogin(
        user, password, settings.api_token, ttl_seconds=settings.docs_token_ttl_seconds
    )


def create_service_app(
    settings: ServiceSettings | None = None,
    llm_settings: LlmProxySettings | None = None,
    *,
    store_settings: ManifestStoreSettings | None = None,
    llm_transport: httpx.AsyncBaseTransport | None = None,
    store_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build the adapter; the LLM client and store live for the app lifespan.

    Store settings come from the environment only when the service settings
    do (the uvicorn factory); an app built with explicit settings stores
    nothing unless store_settings is given.
    """
    from_environment = settings is None
    settings = settings or ServiceSettings()
    _enable_request_log()
    if store_settings is None and from_environment:
        store_settings = ManifestStoreSettings()
    stores = store_settings is not None and bool(store_settings.url)
    # A manifest is built only when it is returned or stored.
    encryptor = None
    if settings.return_manifest or stores:
        if not settings.allow_unencrypted_test_manifest:
            raise ServiceConfigurationError(
                "No manifest encryptor is configured; encryption design is pending"
            )
        encryptor = unencrypted_test_manifest_envelope
        logger.warning(
            "PII manifests are NOT encrypted (allow_unencrypted_test_manifest); "
            "test use only"
        )
    else:
        logger.info("PII manifests are neither returned nor stored")
    store = None
    if stores:
        if store_settings.token is None:
            raise ServiceConfigurationError("PII_STORE_TOKEN is required")
        # Unencrypted test manifests never leave this machine.
        if not is_local_url(store_settings.url):
            raise ServiceConfigurationError(
                "Unencrypted test manifests may only be stored locally"
            )
        store = PostgrestManifestStore(
            store_settings.url, store_settings.token, transport=store_transport
        )
        logger.warning("PII manifests are stored at the local manifest store")
    docs_login = _docs_login(settings)
    llm_settings = llm_settings or LlmProxySettings()
    client = LlmProxyClient(llm_settings, transport=llm_transport)
    processor = LlmDocumentProcessor(client, _whole, _whole)
    rules = (detect_thai_rule_pii,)
    app = create_app(
        processor=processor,
        policy=RecoveryPolicy(deadline_seconds=settings.request_deadline_seconds),
        rule_detectors=rules,
        rules_has_pii=make_detection_checker(list(rules)),
        encrypt_manifest=encryptor,
        authenticate=bearer_authenticator(settings.api_token, docs_login),
        request_deadline_seconds=settings.request_deadline_seconds,
        max_source_characters=settings.max_source_characters,
        store_manifest=store.put if store else None,
        return_manifest=settings.return_manifest,
        return_metadata=settings.return_metadata or settings.return_manifest,
        enable_docs=settings.enable_docs,
        docs_login=docs_login,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async with client:
            app.state.ready = True
            try:
                yield
            finally:
                app.state.ready = False
                if store is not None:
                    await store.aclose()

    # /readyz answers 503 until the LLM client is open and again on shutdown.
    app.state.ready = False
    app.router.lifespan_context = lifespan
    return app
