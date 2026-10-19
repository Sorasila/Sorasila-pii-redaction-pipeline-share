"""A caller that disconnects stops the work: in-flight LLM requests are closed."""

import asyncio
import json
import os

import httpx
import pytest

from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.service import ServiceSettings, create_service_app

TOKEN = "t" * 40


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_", "PII_STORE_")):
            monkeypatch.delenv(name)


class HangingProxy:
    """Never answers until cancelled; records that the request was dropped."""

    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = False
        self.calls = 0

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return httpx.Response(
            200,
            json={
                "status": "success",
                "model": LLM_PROXY_MODEL,
                "structured_output": {"candidates": []},
            },
        )


def service(proxy):
    return create_service_app(
        ServiceSettings(api_token=TOKEN, _env_file=None),
        LlmProxySettings(
            base_url="https://proxy.example", api_key="k", max_retries=0, _env_file=None
        ),
        llm_transport=httpx.MockTransport(proxy),
    )


async def call(app, *, disconnect: asyncio.Event):
    """One raw ASGI request whose caller goes away when ``disconnect`` is set."""
    body = "ชื่อ นายทดสอบ ตัวอย่าง".encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/redact",
        "raw_path": b"/redact",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"content-type", b"text/markdown; charset=utf-8"),
            (b"authorization", f"Bearer {TOKEN}".encode()),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("service.local", 80),
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


@pytest.mark.asyncio
async def test_a_disconnected_caller_cancels_the_llm_request(caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    proxy = HangingProxy()
    app = service(proxy)
    disconnect = asyncio.Event()
    async with app.router.lifespan_context(app):
        request = asyncio.create_task(call(app, disconnect=disconnect))
        await asyncio.wait_for(proxy.started.wait(), 5)
        disconnect.set()
        sent = await asyncio.wait_for(request, 5)
    assert proxy.cancelled is True
    assert proxy.calls == 1  # nothing was retried or started after the caller left
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 499
    body = b"".join(
        m.get("body", b"") for m in sent if m["type"] == "http.response.body"
    )
    assert json.loads(body)["error"] == "client_disconnected"
    (line,) = [
        r.getMessage() for r in caplog.records if r.name == "pii_pipeline.http_api"
    ]
    assert " status=499 " in line
    assert 'reason=ClientDisconnected("Caller closed the connection")' in line
    assert "นายทดสอบ" not in line


@pytest.mark.asyncio
async def test_a_caller_that_waits_gets_the_answer():
    # The disconnect message only comes after the response here, as with a
    # caller that stays connected; the work is not cut short.
    answers = []

    async def proxy(request: httpx.Request) -> httpx.Response:
        schema = request.content.decode()
        answers.append("detection" if "candidates" in schema else "verification")
        output = (
            {"candidates": []}
            if answers[-1] == "detection"
            else {"has_pii": False, "findings": []}
        )
        await asyncio.sleep(0.05)
        return httpx.Response(
            200,
            json={
                "status": "success",
                "model": LLM_PROXY_MODEL,
                "structured_output": output,
            },
        )

    app = service(proxy)
    disconnect = asyncio.Event()
    async with app.router.lifespan_context(app):
        sent = await asyncio.wait_for(call(app, disconnect=disconnect), 5)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 200
    assert answers == ["detection", "verification"]
