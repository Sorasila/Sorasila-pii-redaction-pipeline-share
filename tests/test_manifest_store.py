"""Optional manifest store: PostgREST writer and its use by the service."""

import asyncio
import base64
import hashlib
import json
import os
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr
from replay_support import _multipart

from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.service import ServiceSettings, create_service_app
from pii_pipeline.service.app import ServiceConfigurationError
from pii_pipeline.service.delivery import PreparedDelivery
from pii_pipeline.service.http import HttpApiConfigurationError, create_app
from pii_pipeline.service.manifest_store import (
    ManifestStoreError,
    ManifestStoreSettings,
    PostgrestManifestStore,
    is_local_url,
)

TOKEN = "t" * 40
STORE_TOKEN = SecretStr("s" * 40)
LOCAL = "http://127.0.0.1:3000"
NAME = "นายสมมุติ ทดลองดี"


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_", "PII_STORE_")):
            monkeypatch.delenv(name)


def _b64(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


ENVELOPE = json.dumps(
    {"protected": _b64({"alg": "dir", "kid": "KEY-1"}), "ciphertext": "c"}
).encode()


def package(**overrides) -> PreparedDelivery:
    fields = {"encrypted_manifest": ENVELOPE, "metadata": b'{"m":1}'} | overrides
    return PreparedDelivery(b"body", "multipart", uuid4(), uuid4(), "a" * 64, **fields)


class FakeStore:
    """PostgREST stand-in: answers ``status`` and keeps each request."""

    def __init__(self, status=201, *, unreachable=False):
        self.status = status
        self.unreachable = unreachable
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectError("refused", request=request)
        self.requests.append(request)
        # A body that must never reach an error message or the log.
        return httpx.Response(self.status, json={"message": "secret detail"})

    @property
    def rows(self) -> list[dict]:
        return [json.loads(request.content) for request in self.requests]


async def put(store_reply: FakeStore, item: PreparedDelivery) -> None:
    store = PostgrestManifestStore(
        LOCAL + "/", STORE_TOKEN, transport=httpx.MockTransport(store_reply)
    )
    try:
        await store.put(item)
    finally:
        await store.aclose()


# --- PostgrestManifestStore -------------------------------------------------


def test_a_row_holds_the_envelope_metadata_key_id_and_hash_only():
    reply = FakeStore()
    item = package()
    asyncio.run(put(reply, item))
    (request,) = reply.requests
    assert str(request.url) == f"{LOCAL}/pii_manifests"
    assert (
        request.headers["authorization"] == f"Bearer {STORE_TOKEN.get_secret_value()}"
    )
    assert request.headers["prefer"] == "return=minimal"
    assert reply.rows == [
        {
            "delivery_id": str(item.delivery_id),
            "document_id": str(item.document_id),
            "kid": "KEY-1",
            "manifest_jwe": ENVELOPE.decode(),
            "metadata": '{"m":1}',
            "redacted_md_sha256": "a" * 64,
        }
    ]


@pytest.mark.parametrize(
    "reply,code",
    [
        (FakeStore(409), "duplicate_delivery"),
        (FakeStore(403), "http_403"),
        (FakeStore(500), "http_500"),
        (FakeStore(unreachable=True), "store_unreachable"),
    ],
)
def test_a_failed_store_raises_a_fixed_code_and_message(reply, code):
    with pytest.raises(ManifestStoreError) as raised:
        asyncio.run(put(reply, package()))
    assert raised.value.reason_code == code
    assert str(raised.value) == "PII manifest could not be stored"
    assert "secret" not in repr(raised.value)


def test_a_package_without_manifest_parts_is_not_sent():
    reply = FakeStore()
    with pytest.raises(ManifestStoreError, match="could not be stored") as raised:
        asyncio.run(put(reply, package(encrypted_manifest=b"")))
    assert raised.value.reason_code == "missing_parts"
    assert reply.requests == []


def test_prepared_delivery_repr_hides_the_manifest_and_metadata():
    shown = repr(package())
    assert "KEY-1" not in shown and "ciphertext" not in shown and '"m"' not in shown


@pytest.mark.parametrize(
    "url,local",
    [
        ("http://127.0.0.1:3000", True),
        ("http://localhost:3000/", True),
        ("http://[::1]:3000", True),
        ("https://project.supabase.co", False),
        ("http://127.0.0.1.example.com", False),
    ],
)
def test_only_this_machine_counts_as_local(url, local):
    assert is_local_url(url) is local


# --- the service --------------------------------------------------------------


def llm(request: httpx.Request) -> httpx.Response:
    form = {key: v[0] for key, v in parse_qs(request.content.decode()).items()}
    if "candidates" in form["json_schema"]:
        output = {"candidates": [{"pii_type": "NAME", "value": NAME}]}
    else:
        output = {"has_pii": False, "findings": []}
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": LLM_PROXY_MODEL,
            "structured_output": output,
        },
    )


def service(store_reply=None, store_settings=None, settings=None, *, returned=True):
    return create_service_app(
        settings
        or ServiceSettings(
            api_token=TOKEN,
            allow_unencrypted_test_manifest=True,
            return_manifest=returned,
            _env_file=None,
        ),
        LlmProxySettings(
            base_url="https://proxy.example", api_key="k", max_retries=0, _env_file=None
        ),
        store_settings=store_settings,
        llm_transport=httpx.MockTransport(llm),
        store_transport=httpx.MockTransport(store_reply or FakeStore()),
    )


def local_store(**overrides):
    return ManifestStoreSettings(
        **({"url": LOCAL, "token": STORE_TOKEN} | overrides), _env_file=None
    )


async def post(app) -> httpx.Response:
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://service.local"
        ) as caller,
    ):
        return await caller.post(
            "/redact",
            content=f"ผู้ฟ้องคดี {NAME} ยื่นคำร้อง".encode(),
            headers={
                "content-type": "text/markdown; charset=utf-8",
                "authorization": f"Bearer {TOKEN}",
            },
        )


def test_a_store_without_returning_the_manifest_keeps_it_out_of_the_response():
    reply = FakeStore()
    response = asyncio.run(post(service(reply, local_store(), returned=False)))
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    assert NAME.encode() not in response.content
    (row,) = reply.rows
    assert row["document_id"] == response.headers["x-document-id"]
    assert row["redacted_md_sha256"] == hashlib.sha256(response.content).hexdigest()
    assert row["kid"] == "UNENCRYPTED-TEST-ONLY"


def test_a_store_needs_the_manifest_encryptor_even_when_nothing_is_returned():
    settings = ServiceSettings(api_token=TOKEN, _env_file=None)
    with pytest.raises(ServiceConfigurationError, match="No manifest encryptor"):
        service(store_settings=local_store(), settings=settings)


def test_the_stored_row_matches_the_delivered_parts():
    reply = FakeStore()
    response = asyncio.run(post(service(reply, local_store())))
    assert response.status_code == 200
    parts = _multipart(response)
    (row,) = reply.rows
    metadata = json.loads(parts["metadata"])
    assert row["manifest_jwe"].encode() == parts["pii_manifest"]
    assert row["metadata"].encode() == parts["metadata"]
    assert row["redacted_md_sha256"] == hashlib.sha256(parts["redacted_md"]).hexdigest()
    assert row["document_id"] == metadata["document_id"]
    assert row["kid"] == "UNENCRYPTED-TEST-ONLY"
    # The redacted text is delivered, never stored; the value only in the manifest.
    assert NAME not in json.dumps(row, ensure_ascii=False).replace(
        row["manifest_jwe"], ""
    )


@pytest.mark.parametrize(
    "status,code", [(403, "http_403"), (409, "duplicate_delivery")]
)
def test_a_failed_store_fails_the_request(status, code, caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    response = asyncio.run(post(service(FakeStore(status), local_store())))
    assert response.status_code == 502
    assert response.json()["error"] == "processing_failed"
    (line,) = [
        r.getMessage() for r in caplog.records if r.name == "pii_pipeline.http_api"
    ]
    assert (
        f'reason=ManifestStoreError:{code}("PII manifest could not be stored")' in line
    )
    assert "secret" not in line and NAME not in line


def test_without_a_store_url_nothing_is_stored():
    reply = FakeStore()
    assert asyncio.run(post(service(reply, local_store(url=None)))).status_code == 200
    assert asyncio.run(post(service(reply))).status_code == 200
    assert reply.requests == []


def test_explicit_service_settings_never_read_the_store_from_the_environment(
    monkeypatch,
):
    monkeypatch.setenv("PII_STORE_URL", LOCAL)
    monkeypatch.setenv("PII_STORE_TOKEN", STORE_TOKEN.get_secret_value())
    reply = FakeStore()
    assert asyncio.run(post(service(reply))).status_code == 200
    assert reply.requests == []


def test_the_uvicorn_factory_reads_the_store_from_the_environment(monkeypatch):
    monkeypatch.setenv("PII_SERVICE_API_TOKEN", TOKEN)
    monkeypatch.setenv("PII_SERVICE_ALLOW_UNENCRYPTED_TEST_MANIFEST", "true")
    monkeypatch.setenv("PII_STORE_URL", "https://project.supabase.co")
    monkeypatch.setenv("PII_STORE_TOKEN", STORE_TOKEN.get_secret_value())
    monkeypatch.chdir(os.path.dirname(__file__))  # no .env here
    with pytest.raises(ServiceConfigurationError, match="only be stored locally"):
        create_service_app(
            llm_settings=LlmProxySettings(
                base_url="https://proxy.example", api_key="k", _env_file=None
            )
        )


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"url": "https://project.supabase.co"}, "only be stored locally"),
        ({"token": None}, "PII_STORE_TOKEN is required"),
    ],
)
def test_the_service_refuses_an_unsafe_store(overrides, message):
    with pytest.raises(ServiceConfigurationError, match=message):
        service(store_settings=local_store(**overrides))


def test_create_app_refuses_a_store_that_is_not_async():
    from fake_llm import fake_processor

    from pii_pipeline.core.verification import make_detection_checker
    from pii_pipeline.recovery.process import RecoveryPolicy
    from pii_pipeline.rules.thai import detect_thai_rule_pii

    async def allow(_request):
        return True

    rules = (detect_thai_rule_pii,)
    with pytest.raises(HttpApiConfigurationError):
        create_app(
            processor=fake_processor(),
            policy=RecoveryPolicy(),
            rule_detectors=rules,
            rules_has_pii=make_detection_checker(list(rules)),
            encrypt_manifest=lambda plaintext, **_: plaintext,
            authenticate=allow,
            request_deadline_seconds=60,
            store_manifest=lambda package: None,
        )
