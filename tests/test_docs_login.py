"""Docs login: username and password give a temporary Bearer token (POST /token)."""

import os

import httpx
import pytest
from pydantic import SecretStr

from pii_pipeline.llm.config import LlmProxySettings
from pii_pipeline.service import ServiceSettings, create_service_app
from pii_pipeline.service.app import ServiceConfigurationError
from pii_pipeline.service.docs_login import DocsLogin

TOKEN = "t" * 40
USER = "dev-team"
PASSWORD = "a-long-docs-password"


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_", "PII_STORE_")):
            monkeypatch.delenv(name)


def service(**settings):
    values = {"enable_docs": True, "docs_username": USER, "docs_password": PASSWORD}
    values.update(settings)
    return create_service_app(
        ServiceSettings(api_token=TOKEN, _env_file=None, **values),
        LlmProxySettings(base_url="https://proxy.example", api_key="k", _env_file=None),
        llm_transport=httpx.MockTransport(lambda request: httpx.Response(500)),
    )


async def call(app, method, path, **kwargs):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://service.local"
    ) as client:
        return await client.request(method, path, **kwargs)


async def login(app, password=PASSWORD, grant="password"):
    return await call(
        app,
        "POST",
        "/token",
        data={"grant_type": grant, "username": USER, "password": password},
    )


async def redact_empty(app, bearer):
    # An empty body: 400 after the token check passes, 401 when it fails;
    # the LLM is never called either way.
    return await call(
        app,
        "POST",
        "/redact",
        content=b" ",
        headers={"content-type": "text/markdown", "authorization": f"Bearer {bearer}"},
    )


@pytest.mark.asyncio
async def test_a_login_token_opens_redact_and_the_api_token_is_never_returned():
    app = service()
    response = await login(app)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 3600
    assert TOKEN not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert (await redact_empty(app, body["access_token"])).status_code == 400
    # The API token itself still works.
    assert (await redact_empty(app, TOKEN)).status_code == 400


@pytest.mark.asyncio
async def test_a_wrong_password_or_grant_gets_no_token(caplog):
    caplog.set_level("WARNING", logger="pii_pipeline.service")
    app = service()
    wrong = await login(app, password="not-the-password")
    assert (wrong.status_code, wrong.json()) == (400, {"error": "invalid_grant"})
    assert "docs login failed" in caplog.text and "not-the-password" not in caplog.text
    grant = await login(app, grant="client_credentials")
    assert grant.json() == {"error": "unsupported_grant_type"}


@pytest.mark.asyncio
async def test_forged_or_expired_tokens_are_refused():
    app = service()
    token = (await login(app)).json()["access_token"]
    prefix, expiry, signature = token.split(".")
    later = str(int(expiry) + 10_000)
    assert (await redact_empty(app, f"{prefix}.{later}.{signature}")).status_code == 401
    assert (await redact_empty(app, f"{prefix}.{expiry}.{'0' * 64}")).status_code == 401
    clock = [1_000_000.0]
    issuer = DocsLogin(
        USER,
        SecretStr(PASSWORD),
        SecretStr(TOKEN),
        ttl_seconds=60,
        clock=lambda: clock[0],
    )
    short = issuer.issue()
    assert issuer.valid(short)
    clock[0] += 61
    assert not issuer.valid(short)
    # A token signed under another API token is refused.
    other = DocsLogin(USER, SecretStr(PASSWORD), SecretStr("o" * 40), ttl_seconds=60)
    assert not issuer.valid(other.issue())


@pytest.mark.asyncio
async def test_login_is_off_without_docs_or_credentials():
    assert (await login(service(enable_docs=False))).status_code == 404
    assert (
        await login(service(docs_username=None, docs_password=None))
    ).status_code == 404


def test_username_and_password_go_together():
    with pytest.raises(ServiceConfigurationError, match="both"):
        service(docs_password=None)


def test_short_passwords_are_refused():
    with pytest.raises(ValueError):
        ServiceSettings(api_token=TOKEN, docs_password="short", _env_file=None)


@pytest.mark.asyncio
async def test_swagger_shows_the_login_in_authorize():
    schema = (await call(service(), "GET", "/openapi.json")).json()
    login_scheme = schema["components"]["securitySchemes"]["docsLogin"]
    assert login_scheme["flows"]["password"]["tokenUrl"] == "token"
    assert {"docsLogin": []} in schema["paths"]["/redact"]["post"]["security"]
    assert "/token" in schema["paths"]
