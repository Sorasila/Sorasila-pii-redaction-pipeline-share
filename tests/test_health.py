"""Container probes: /healthz (process alive) and /readyz (ready for requests)."""

import os

import httpx
import pytest
from fake_llm import fake_processor

from pii_pipeline.llm.config import LlmProxySettings
from pii_pipeline.recovery.process import RecoveryPolicy
from pii_pipeline.service import ServiceSettings, create_service_app
from pii_pipeline.service.http import create_app

TOKEN = "t" * 40


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_", "PII_STORE_")):
            monkeypatch.delenv(name)


def no_rules(source):
    return []


def clean_rules(text):
    return False


def adapter():
    async def deny(_request):
        return False

    return create_app(
        processor=fake_processor(),
        policy=RecoveryPolicy(),
        rule_detectors=(no_rules,),
        rules_has_pii=clean_rules,
        encrypt_manifest=None,
        authenticate=deny,  # probes never ask for a caller token
        request_deadline_seconds=1.0,
        return_manifest=False,
        return_metadata=False,
    )


async def get(app, method, path):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://service.local"
    ) as client:
        return await client.request(method, path)


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", [("/healthz", "ok"), ("/readyz", "ready")])
async def test_probes_answer_without_a_token_or_a_document(path, body):
    response = await get(adapter(), "GET", path)
    assert response.status_code == 200
    assert response.json() == {"status": body}
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/healthz", "/readyz"])
async def test_probes_accept_get_only(path):
    response = await get(adapter(), "POST", path)
    assert response.status_code == 405
    assert response.headers["allow"] == "GET"
    assert response.json() == {"error": "method_not_allowed"}


@pytest.mark.asyncio
async def test_redact_still_allows_post_only():
    response = await get(adapter(), "GET", "/redact")
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"


@pytest.mark.asyncio
async def test_the_service_is_ready_only_while_its_lifespan_runs(caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    proxy_calls = []

    def proxy(request):
        proxy_calls.append(request)
        return httpx.Response(500)

    app = create_service_app(
        ServiceSettings(api_token=TOKEN, _env_file=None),
        LlmProxySettings(base_url="https://proxy.example", api_key="k", _env_file=None),
        llm_transport=httpx.MockTransport(proxy),
    )
    assert (await get(app, "GET", "/readyz")).status_code == 503
    async with app.router.lifespan_context(app):
        ready = await get(app, "GET", "/readyz")
        alive = await get(app, "GET", "/healthz")
    after = await get(app, "GET", "/readyz")
    assert (ready.status_code, ready.json()) == (200, {"status": "ready"})
    assert alive.status_code == 200
    assert (after.status_code, after.json()) == (503, {"status": "not_ready"})
    # Probes never reach the LLM proxy and write no request log line.
    assert proxy_calls == []
    assert not [r for r in caplog.records if r.name == "pii_pipeline.http_api"]
