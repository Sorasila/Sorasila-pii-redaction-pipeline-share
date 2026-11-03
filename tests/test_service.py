import base64
import hashlib
import json
import os
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import ValidationError

from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.service import (
    UNENCRYPTED_TEST_KID,
    ServiceConfigurationError,
    ServiceSettings,
    create_service_app,
)

TOKEN = "t" * 40


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_")):
            monkeypatch.delenv(name)


def service_settings(**changes):
    values = {
        "api_token": TOKEN,
        "allow_unencrypted_test_manifest": True,
        "return_manifest": True,
        "_env_file": None,
    }
    values.update(changes)
    return ServiceSettings(**values)


def llm_settings():
    return LlmProxySettings(
        base_url="https://proxy.example",
        api_key="synthetic-key",
        max_retries=0,
        _env_file=None,
    )


def success(output):
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": LLM_PROXY_MODEL,
            "structured_output": output,
        },
    )


def wire(request):
    form = {
        key: values[0] for key, values in parse_qs(request.content.decode()).items()
    }
    role = next(iter(json.loads(form["json_schema"])["properties"]))
    if role == "candidates":
        return success(
            {"candidates": [{"pii_type": "NAME", "value": "นายทดสอบ ตัวอย่าง"}]}
        )
    return success({"has_pii": False, "findings": []})


async def post(app, body, token=TOKEN):
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://service.local"
        ) as caller,
    ):
        return await caller.post(
            "/redact",
            content=body.encode(),
            headers={
                "content-type": "text/markdown; charset=utf-8",
                "authorization": f"Bearer {token}",
            },
        )


def parts(response):
    message = BytesParser(policy=policy.HTTP).parsebytes(
        b"Content-Type: "
        + response.headers["content-type"].encode()
        + b"\r\n\r\n"
        + response.content
    )
    return {
        part.get_param("name", header="content-disposition"): part.get_payload(
            decode=True
        )
        for part in message.iter_parts()
    }


def test_settings_require_a_long_caller_token():
    with pytest.raises(ValidationError):
        ServiceSettings(_env_file=None)
    with pytest.raises(ValidationError):
        ServiceSettings(api_token="short", _env_file=None)


def test_service_refuses_to_return_a_manifest_without_an_encryptor():
    with pytest.raises(ServiceConfigurationError):
        create_service_app(
            service_settings(allow_unencrypted_test_manifest=False), llm_settings()
        )


@pytest.mark.asyncio
async def test_by_default_the_response_is_the_redacted_markdown_alone(caplog):
    """Default settings: no manifest, no metadata, no encryptor needed."""
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    settings = ServiceSettings(api_token=TOKEN, _env_file=None)
    assert (settings.return_manifest, settings.return_metadata) == (False, False)
    app = create_service_app(
        settings, llm_settings(), llm_transport=httpx.MockTransport(wire)
    )
    response = await post(app, "ชื่อ นายทดสอบ ตัวอย่าง")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    assert response.content == "ชื่อ [PII_NAME_1]".encode()
    assert response.headers["cache-control"] == "no-store"
    # The request log line names the same document.
    (line,) = [
        r.getMessage() for r in caplog.records if r.name == "pii_pipeline.http_api"
    ]
    assert f"document_id={response.headers['x-document-id']} " in line


@pytest.mark.asyncio
async def test_metadata_alone_can_be_returned_without_a_manifest():
    settings = ServiceSettings(api_token=TOKEN, return_metadata=True, _env_file=None)
    app = create_service_app(
        settings, llm_settings(), llm_transport=httpx.MockTransport(wire)
    )
    response = await post(app, "ชื่อ นายทดสอบ ตัวอย่าง")
    assert response.status_code == 200
    received = parts(response)
    assert set(received) == {"redacted_md", "metadata"}
    assert "นายทดสอบ".encode() not in response.content
    metadata = json.loads(received["metadata"])
    assert metadata["document_id"] == response.headers["x-document-id"]
    assert (
        metadata["redacted_md_sha256"]
        == hashlib.sha256(received["redacted_md"]).hexdigest()
    )


@pytest.mark.asyncio
async def test_wrong_token_is_rejected_before_any_llm_call():
    calls = []

    def recording(request):
        calls.append(request)
        return wire(request)

    app = create_service_app(
        service_settings(), llm_settings(), llm_transport=httpx.MockTransport(recording)
    )
    response = await post(app, "ชื่อ นายทดสอบ ตัวอย่าง", token="x" * 40)
    assert response.status_code == 401
    assert calls == []


@pytest.mark.asyncio
async def test_page_is_redacted_with_rules_llm_and_test_manifest():
    app = create_service_app(
        service_settings(), llm_settings(), llm_transport=httpx.MockTransport(wire)
    )
    source = "ชื่อ นายทดสอบ ตัวอย่าง\r\nหนังสือที่ กข 1234/5678"
    response = await post(app, source)
    assert response.status_code == 200
    received = parts(response)
    assert received["redacted_md"].decode() == (
        "ชื่อ [PII_NAME_1]\r\nหนังสือที่ [PII_OFFICIAL_LETTER_NUMBER_1]"
    )
    envelope = json.loads(received["pii_manifest"])
    protected = json.loads(base64.urlsafe_b64decode(envelope["protected"] + "=="))
    assert protected["kid"] == UNENCRYPTED_TEST_KID
    manifest = json.loads(
        base64.urlsafe_b64decode(
            envelope["ciphertext"] + "=" * (-len(envelope["ciphertext"]) % 4)
        )
    )
    assert [(e["pii_type"], e["original_value"]) for e in manifest["entries"]] == [
        ("NAME", "นายทดสอบ ตัวอย่าง"),
        ("OFFICIAL_LETTER_NUMBER", "กข 1234/5678"),
    ]
    assert json.loads(received["metadata"])["document_id"] == manifest["document_id"]


@pytest.mark.asyncio
async def test_lifespan_closes_the_llm_client():
    transport = httpx.MockTransport(wire)
    app = create_service_app(
        service_settings(), llm_settings(), llm_transport=transport
    )
    await post(app, "ชื่อ นายทดสอบ ตัวอย่าง")
    with pytest.raises(RuntimeError):
        # A closed httpx client refuses new requests.
        await post(app, "ชื่อ นายทดสอบ ตัวอย่าง")
