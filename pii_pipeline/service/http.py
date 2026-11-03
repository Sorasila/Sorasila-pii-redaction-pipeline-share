"""Synchronous HTTP delivery of a verified package from a raw UTF-8 document.

The caller supplies authentication, role-separated processing components, and
the configured manifest encryptor. This module creates no LLM
client, reads no environment settings, and assumes no deployment timeout.

One POST /redact: authenticate → read the page (``document_input``) →
process (the recovery pipeline; stopped if the caller disconnects) → prepare
and check the
multipart package → store the manifest when a store is configured → respond;
every outcome except a refused token is logged once (``request_log``).
"""

import asyncio
import hashlib
import logging
import math
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from inspect import isawaitable, iscoroutine, iscoroutinefunction
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException

from ..core.detection import Detector
from ..core.models import RedactionResult
from ..core.verification import VerificationChecker
from ..llm.call_stats import collect_call_stats
from ..llm.processing import LlmDocumentProcessor
from ..recovery.process import (
    RecoveryPolicy,
    process_markdown_with_recovery_async,
    valid_rule_lane,
)
from .delivery import (
    PLAIN_CONTENT_TYPE,
    ManifestEncryptor,
    PreparedDelivery,
    prepare_delivery,
)
from .docs_login import DocsLogin
from .document_input import (
    DEFAULT_MAX_SOURCE_CHARACTERS,
    InputRejected,
    read_document,
)
from .request_log import log_outcome, safe_reason

# Docs login events only; request outcomes go to request_log.
logger = logging.getLogger("pii_pipeline.service")

__all__ = [
    "DEFAULT_MAX_SOURCE_CHARACTERS",
    "Authenticator",
    "HttpApiConfigurationError",
    "create_app",
]

_PRIVATE_RESPONSE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}
_MULTIPART_CONTENT_TYPE = re.compile(
    r'multipart/form-data;\s*boundary=(?:[A-Za-z0-9_-]{1,70}|"[A-Za-z0-9_-]{1,70}")'
)

Authenticator = Callable[[Request], Awaitable[bool]]
# Container probes: no authentication, no document, no dependency calls.
HEALTH_PATHS = frozenset({"/healthz", "/readyz"})
# Interactive API docs, only when enabled (enable_docs).
DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/openapi.json"})

# OpenAPI description of POST /redact. The handler reads the raw body itself,
# so the body, the Bearer token and the responses are declared here for the
# docs page; they do not change how requests are checked.
_SAMPLE_PAGE = "ผู้ฟ้องคดี นายสมมุติ ทดลองดี\nโทรศัพท์ 081-000-0000\n"
_TOKEN_OPENAPI = {
    "requestBody": {
        "required": True,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "grant_type": {"type": "string", "enum": ["password"]},
                        "username": {"type": "string"},
                        "password": {"type": "string", "format": "password"},
                    },
                    "required": ["grant_type", "username", "password"],
                }
            }
        },
    },
    "responses": {
        "200": {
            "description": "A temporary Bearer token for POST /redact",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "access_token": {"type": "string"},
                            "token_type": {"type": "string"},
                            "expires_in": {"type": "integer"},
                        },
                    }
                }
            },
        },
        "400": {"description": "invalid_grant: wrong username or password"},
    },
}


def _redact_openapi(max_source_characters: int) -> dict:
    return {
        "requestBody": {
            "required": True,
            "description": (
                f"Raw UTF-8 Markdown or text, at most {max_source_characters} "
                "Unicode code points, not wrapped in JSON."
            ),
            "content": {
                "text/markdown": {"schema": {"type": "string"}, "example": _SAMPLE_PAGE},
                "text/plain": {"schema": {"type": "string"}, "example": _SAMPLE_PAGE},
            },
        },
        "security": [{"bearerAuth": []}],
        "responses": {
            "200": {
                "description": (
                    "Redacted text. By default the body is the redacted Markdown; "
                    "with PII_SERVICE_RETURN_METADATA (or _MANIFEST) it is "
                    "multipart/form-data with redacted_md and metadata (and "
                    "pii_manifest). X-Document-Id matches the request log line."
                ),
                "headers": {
                    "X-Document-Id": {"schema": {"type": "string", "format": "uuid"}}
                },
                "content": {
                    "text/markdown": {"schema": {"type": "string"}},
                    "multipart/form-data": {"schema": {"type": "object"}},
                },
            },
            **{
                str(code): {
                    "description": text,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Error"}
                        }
                    },
                }
                for code, text in (
                    (
                        400,
                        "invalid_request: empty, not UTF-8, or already holds [PII_...] placeholders",
                    ),
                    (401, "authentication_failed: missing or wrong Bearer token"),
                    (
                        413,
                        f"document_too_large: more than {max_source_characters} code points",
                    ),
                    (
                        415,
                        "unsupported_media_type: use text/markdown or text/plain, UTF-8",
                    ),
                    (
                        502,
                        "processing_failed: detection or verification did not succeed",
                    ),
                    (
                        504,
                        "request_timeout: PII_SERVICE_REQUEST_DEADLINE_SECONDS reached",
                    ),
                )
            },
        },
    }


# Stores the prepared delivery's manifest; raising fails the request (502).
ManifestStore = Callable[[PreparedDelivery], Awaitable[None]]


class ClientDisconnected(Exception):
    """The caller closed the connection before the response; work stopped."""

    def __init__(self) -> None:
        super().__init__("Caller closed the connection")


class HttpApiConfigurationError(ValueError):
    """A required dependency or timeout is unsuitable for this adapter."""


def _is_async_callable(callback: object) -> bool:
    return iscoroutinefunction(callback) or iscoroutinefunction(type(callback).__call__)


def _valid_deadline(value: object) -> bool:
    if type(value) not in {float, int}:
        return False
    try:
        return math.isfinite(value) and value > 0
    except OverflowError:
        return False


def _error(
    status_code: int, code: str, document_id: UUID | None = None
) -> JSONResponse:
    payload: dict[str, str] = {"error": code}
    if document_id is not None:
        payload["document_id"] = str(document_id)
    return JSONResponse(
        payload, status_code=status_code, headers=_PRIVATE_RESPONSE_HEADERS
    )


@dataclass(frozen=True, slots=True)
class _Dependencies:
    processor: LlmDocumentProcessor
    policy: RecoveryPolicy
    rule_detectors: tuple[Detector, ...]
    rules_has_pii: VerificationChecker
    encrypt_manifest: ManifestEncryptor | None
    authenticate: Authenticator
    request_deadline_seconds: float
    max_source_characters: int
    store_manifest: ManifestStore | None = None
    return_manifest: bool = True
    return_metadata: bool = True


def _validate_dependencies(deps: _Dependencies) -> None:
    if (
        not isinstance(deps.processor, LlmDocumentProcessor)
        or not isinstance(deps.policy, RecoveryPolicy)
        or not valid_rule_lane(deps.rule_detectors, deps.rules_has_pii)
        or type(deps.return_manifest) is not bool
        or type(deps.return_metadata) is not bool
        # The metadata bytes are the manifest's AAD: never one without the other.
        or (deps.return_manifest and not deps.return_metadata)
        or (
            deps.encrypt_manifest is None
            # Without an encryptor no manifest exists to return or store.
            and (deps.return_manifest or deps.store_manifest is not None)
        )
        or (
            deps.encrypt_manifest is not None
            and (
                not callable(deps.encrypt_manifest)
                or _is_async_callable(deps.encrypt_manifest)
            )
        )
        or not callable(deps.authenticate)
        or not _valid_deadline(deps.request_deadline_seconds)
        or type(deps.max_source_characters) is not int
        or deps.max_source_characters <= 0
        or (
            deps.store_manifest is not None
            and not _is_async_callable(deps.store_manifest)
        )
    ):
        raise HttpApiConfigurationError("HTTP API configuration is invalid")


def _validate_package(
    package: object,
    result: RedactionResult,
    deps: _Dependencies,
    *,
    document_id: UUID,
    delivery_id: UUID,
) -> PreparedDelivery:
    if iscoroutine(package):
        package.close()
    if (
        not isinstance(package, PreparedDelivery)
        or type(package.body) is not bytes
        or not package.body
        or not isinstance(package.content_type, str)
        or not (
            _MULTIPART_CONTENT_TYPE.fullmatch(package.content_type)
            if deps.return_metadata
            else package.content_type == PLAIN_CONTENT_TYPE
            and package.body == result.redacted_markdown.encode("utf-8")
        )
        or type(package.document_id) is not UUID
        or type(package.delivery_id) is not UUID
        or package.document_id != document_id
        or package.delivery_id != delivery_id
        or type(package.redacted_md_sha256) is not str
        or package.redacted_md_sha256
        != hashlib.sha256(result.redacted_markdown.encode("utf-8")).hexdigest()
    ):
        raise ValueError("Delivery package is invalid")
    return package


async def _is_authorized(authenticate: Authenticator, request: Request) -> bool:
    try:
        authorization = authenticate(request)
        if not isawaitable(authorization):
            return False
        authorized = await authorization
    except Exception:  # noqa: BLE001 - authentication is supplied externally.
        return False
    return authorized is True


async def _process(markdown: str, deps: _Dependencies, events: list[dict]):
    return await process_markdown_with_recovery_async(
        markdown,
        deps.processor,
        rule_detectors=deps.rule_detectors,
        rules_has_pii=deps.rules_has_pii,
        policy=deps.policy,
        progress=events.append,
    )


async def _until_disconnected(request: Request) -> None:
    # The body is read by now, so the next ASGI message is http.disconnect:
    # sent when the caller goes away (or, harmlessly, once the response is done).
    while (await request.receive())["type"] != "http.disconnect":
        continue


async def _unless_disconnected(request: Request, work):
    """Await ``work``; cancel it as soon as the caller disconnects.

    Cancelling stops the pipeline at its next await, which closes in-flight
    LLM requests instead of letting a page nobody waits for run to the end.
    """
    task = asyncio.ensure_future(work)
    watcher = asyncio.ensure_future(_until_disconnected(request))
    try:
        await asyncio.wait({task, watcher}, return_when=asyncio.FIRST_COMPLETED)
        if not task.done():
            raise ClientDisconnected
        return task.result()
    finally:
        task.cancel()
        watcher.cancel()
        await asyncio.gather(task, watcher, return_exceptions=True)


def _package(result, deps, *, document_id, delivery_id) -> PreparedDelivery:
    package = prepare_delivery(
        result,
        document_id=document_id,
        delivery_id=delivery_id,
        redacted_at=datetime.now(UTC),
        encrypt_manifest=deps.encrypt_manifest,
        return_manifest=deps.return_manifest,
        return_metadata=deps.return_metadata,
    )
    return _validate_package(
        package, result, deps, document_id=document_id, delivery_id=delivery_id
    )


async def _redact(request: Request, deps: _Dependencies) -> Response:
    document_id = uuid4()
    delivery_id = uuid4()
    loop = asyncio.get_running_loop()
    started = loop.time()
    deadline = started + deps.request_deadline_seconds
    events: list[dict] = []
    with collect_call_stats() as calls:
        try:
            async with asyncio.timeout_at(deadline):
                if not await _is_authorized(deps.authenticate, request):
                    return _error(401, "authentication_failed")
                markdown = await read_document(request, deps.max_source_characters)
                result = await _unless_disconnected(
                    request, _process(markdown, deps, events)
                )
                package = _package(
                    result, deps, document_id=document_id, delivery_id=delivery_id
                )
                if deps.store_manifest is not None:
                    await deps.store_manifest(package)
                if loop.time() >= deadline:
                    raise TimeoutError
        except InputRejected as error:
            log_outcome(
                logging.INFO, document_id, error.status_code, started, events, calls
            )
            return _error(error.status_code, error.code, document_id)
        except ClientDisconnected as error:
            # Nobody receives this response; 499 marks the log line only.
            log_outcome(
                logging.WARNING,
                document_id,
                499,
                started,
                events,
                calls,
                safe_reason(error),
            )
            return _error(499, "client_disconnected", document_id)
        except TimeoutError as error:
            log_outcome(
                logging.WARNING,
                document_id,
                504,
                started,
                events,
                calls,
                safe_reason(error),
            )
            return _error(504, "request_timeout", document_id)
        except Exception as error:  # noqa: BLE001 - external processors/encryptors must fail closed.
            log_outcome(
                logging.WARNING,
                document_id,
                502,
                started,
                events,
                calls,
                safe_reason(error),
            )
            return _error(502, "processing_failed", document_id)
        log_outcome(logging.INFO, document_id, 200, started, events, calls)
        return Response(
            content=package.body,
            headers={
                **_PRIVATE_RESPONSE_HEADERS,
                "Content-Type": package.content_type,
                # Matches the request log line; IDs carry no PII.
                "X-Document-Id": str(document_id),
            },
            status_code=200,
        )


def _add_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def handle_http_error(request: Request, error: HTTPException) -> JSONResponse:
        if error.status_code == 404:
            return _error(404, "not_found")
        if error.status_code == 405:
            response = _error(405, "method_not_allowed")
            response.headers["Allow"] = (
                "GET" if request.url.path in HEALTH_PATHS | DOCS_PATHS else "POST"
            )
            return response
        return _error(error.status_code, "invalid_request")

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        return _error(400, "invalid_request")


async def _issue_docs_token(request: Request, login: DocsLogin) -> JSONResponse:
    """OAuth2 password grant for the docs page; never logs the values."""
    try:
        form = await request.form()
        grant = form.get("grant_type")
        username = form.get("username")
        password = form.get("password")
    except Exception:  # noqa: BLE001 - malformed form bodies are a client error.
        return _error(400, "invalid_request")
    if (
        grant != "password"
        or not isinstance(username, str)
        or not isinstance(password, str)
    ):
        return _error(400, "unsupported_grant_type")
    if not login.check(username, password):
        logger.warning("docs login failed")
        # Slows guessing; the docs page is for test and staging machines only.
        await asyncio.sleep(1)
        return _error(400, "invalid_grant")
    return JSONResponse(
        {
            "access_token": login.issue(),
            "token_type": "bearer",
            "expires_in": login.ttl_seconds,
        },
        headers=_PRIVATE_RESPONSE_HEADERS,
    )


def _describe_security(app: FastAPI, *, login: bool) -> None:
    """Add the Bearer scheme(s) and the error body to the generated schema."""
    build = app.openapi

    def openapi() -> dict:
        if app.openapi_schema is None:
            schema = build()
            components = schema.setdefault("components", {})
            schemes = components.setdefault("securitySchemes", {})
            schemes["bearerAuth"] = {
                "type": "http",
                "scheme": "bearer",
                "description": "PII_SERVICE_API_TOKEN",
            }
            if login:
                # Swagger's Authorize dialog shows username/password fields,
                # calls /token and sends the token it gets as Bearer.
                schemes["docsLogin"] = {
                    "type": "oauth2",
                    "description": "Username and password set in "
                    "PII_SERVICE_DOCS_USERNAME / PII_SERVICE_DOCS_PASSWORD",
                    "flows": {"password": {"tokenUrl": "token", "scopes": {}}},
                }
            components.setdefault("schemas", {})["Error"] = {
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "document_id": {"type": "string", "format": "uuid"},
                },
                "required": ["error"],
            }
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi


def create_app(
    *,
    processor: LlmDocumentProcessor,
    policy: RecoveryPolicy,
    rule_detectors: tuple[Detector, ...],
    rules_has_pii: VerificationChecker,
    encrypt_manifest: ManifestEncryptor | None,
    authenticate: Authenticator,
    request_deadline_seconds: float,
    max_source_characters: int = DEFAULT_MAX_SOURCE_CHARACTERS,
    store_manifest: ManifestStore | None = None,
    return_manifest: bool = True,
    return_metadata: bool = True,
    enable_docs: bool = False,
    docs_login: DocsLogin | None = None,
) -> FastAPI:
    """Create an adapter with required trusted dependencies and a finite deadline.

    POST /redact accepts raw text/plain or text/markdown, up to
    ``max_source_characters`` source Unicode codepoints (one whole page, sent
    to the LLM as one window). It waits for detection, independent verification and
    encrypted three-part multipart preparation before returning one response.
    The synchronous encryptor must finish promptly; the deadline cannot
    interrupt CPU-bound Python code, but an overrun never returns a success.
    With ``store_manifest`` each package is stored before the response; a
    store failure fails the request. ``return_manifest=False`` answers
    redacted_md and metadata only; ``encrypt_manifest=None`` (allowed only
    then, and without a store) builds no manifest at all.
    ``return_metadata=False`` as well answers the redacted Markdown itself
    (``text/markdown``). Every success carries the ``X-Document-Id`` header.
    ``enable_docs`` serves Swagger UI at /docs and the schema at /openapi.json
    (no token needed to open them; trying /redact still needs one).
    ``docs_login`` (only with ``enable_docs``) adds POST /token: a username and
    password give a temporary Bearer token, used from Swagger's Authorize
    dialog; ``authenticate`` must accept those tokens.
    """
    if docs_login is not None and not enable_docs:
        raise HttpApiConfigurationError("HTTP API configuration is invalid")
    deps = _Dependencies(
        processor,
        policy,
        rule_detectors,
        rules_has_pii,
        encrypt_manifest,
        authenticate,
        request_deadline_seconds,
        max_source_characters,
        store_manifest,
        return_manifest,
        return_metadata,
    )
    _validate_dependencies(deps)

    # No default public authentication, guessed LLM budgets, or lifecycle-owned client.
    app = FastAPI(
        title="PII Redaction Service",
        version="1.0",
        description=(
            "Redacts PII in Thai OCR Markdown. Click **Authorize** and either "
            "log in with the docs username and password (when enabled) or enter "
            "the caller token (PII_SERVICE_API_TOKEN), then try POST /redact with "
            "a synthetic page. A request can take minutes while the LLM works. "
            "Never paste real documents into a shared page."
        ),
        docs_url="/docs" if enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if enable_docs else None,
        swagger_ui_parameters={"defaultModelsExpandDepth": -1},
        redirect_slashes=False,
    )
    _add_error_handlers(app)
    # Ready unless the composition that owns the lifecycle says otherwise.
    app.state.ready = True

    @app.post(
        "/redact",
        response_class=Response,
        summary="Redact PII in one page",
        openapi_extra=(
            {
                **_redact_openapi(max_source_characters),
                "security": [{"bearerAuth": []}, {"docsLogin": []}],
            }
            if docs_login
            else _redact_openapi(max_source_characters)
        ),
    )
    async def redact_document(request: Request) -> Response:
        return await _redact(request, deps)

    if docs_login is not None:

        @app.post(
            "/token",
            summary="Get a temporary token (docs login)",
            openapi_extra=_TOKEN_OPENAPI,
        )
        async def docs_token(request: Request) -> JSONResponse:
            return await _issue_docs_token(request, docs_login)

    if enable_docs:
        _describe_security(app, login=docs_login is not None)

    @app.get("/healthz")
    async def liveness() -> JSONResponse:
        """The process answers; says nothing about the LLM proxy or a store."""
        return JSONResponse({"status": "ok"}, headers=_PRIVATE_RESPONSE_HEADERS)

    @app.get("/readyz")
    async def readiness(request: Request) -> JSONResponse:
        """Ready to accept requests: started and not shutting down.

        Checks only this process, never the LLM proxy or a manifest store, so a
        probe adds no load and leaks nothing about them.
        """
        ready = request.app.state.ready is True
        return JSONResponse(
            {"status": "ready" if ready else "not_ready"},
            status_code=200 if ready else 503,
            headers=_PRIVATE_RESPONSE_HEADERS,
        )

    return app
