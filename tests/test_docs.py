"""Swagger UI for trying the API: off by default, on with enable_docs."""

import os

import httpx
import pytest

from pii_pipeline.llm.config import LlmProxySettings
from pii_pipeline.service import ServiceSettings, create_service_app

TOKEN = "t" * 40


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_", "PII_STORE_")):
            monkeypatch.delenv(name)


def service(**settings):
    return create_service_app(
        ServiceSettings(api_token=TOKEN, _env_file=None, **settings),
        LlmProxySettings(base_url="https://proxy.example", api_key="k", _env_file=None),
        llm_transport=httpx.MockTransport(lambda request: httpx.Response(500)),
    )


async def get(app, path, method="GET", **kwargs):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://service.local"
    ) as client:
        return await client.request(method, path, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/docs", "/openapi.json", "/redoc"])
async def test_docs_are_off_by_default(path):
    response = await get(service(), path)
    assert response.status_code == 404
    assert response.json() == {"error": "not_found"}


@pytest.mark.asyncio
async def test_swagger_ui_and_schema_when_enabled():
    app = service(enable_docs=True)
    page = await get(app, "/docs")
    assert page.status_code == 200
    assert "swagger-ui" in page.text
    schema = (await get(app, "/openapi.json")).json()
    redact = schema["paths"]["/redact"]["post"]
    assert redact["security"] == [{"bearerAuth": []}]
    assert set(redact["requestBody"]["content"]) == {"text/markdown", "text/plain"}
    assert {"200", "400", "401", "413", "415", "502", "504"} <= set(redact["responses"])
    assert schema["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"
    assert {"/healthz", "/readyz"} <= set(schema["paths"])
    # ReDoc stays off; the docs never bypass the caller token.
    assert (await get(app, "/redoc")).status_code == 404
    refused = await get(
        app,
        "/redact",
        method="POST",
        content="ผู้ฟ้องคดี นายสมมุติ ทดลองดี".encode(),
        headers={"content-type": "text/markdown"},
    )
    assert refused.status_code == 401


@pytest.mark.asyncio
async def test_docs_accept_get_only():
    response = await get(service(enable_docs=True), "/docs", method="POST")
    assert response.status_code == 405
    assert response.headers["allow"] == "GET"
