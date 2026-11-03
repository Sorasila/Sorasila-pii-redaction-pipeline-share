import asyncio
import base64
import hashlib
import json
import time
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from inspect import getcoroutinestate
from uuid import UUID, uuid4

import httpx
import pytest
from fake_llm import fake_processor
from fastapi import Request

from pii_pipeline.core.models import PiiMatch
from pii_pipeline.recovery.process import RecoveryPolicy
from pii_pipeline.service import http as http_api
from pii_pipeline.service import request_log
from pii_pipeline.service.delivery import PreparedDelivery, prepare_delivery
from pii_pipeline.service.http import HttpApiConfigurationError, create_app

CANARY = "Synthetic Private Name"


def no_rules(source: str) -> list[PiiMatch]:
    return []


async def no_semantics(source: str) -> list[PiiMatch]:
    return []


def clean_rules(source: str) -> bool:
    return False


async def clean_llm(source: str) -> bool:
    return False


async def authenticated(request: Request) -> bool:
    return True


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def fake_encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
    """Structural JWE test double; this is deliberately not an encryption adapter."""
    return json.dumps(
        {
            "protected": b64(
                json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM"}).encode()
            ),
            "encrypted_key": b64(b"test-wrapped-key"),
            "iv": b64(b"0" * 12),
            "ciphertext": b64(b"test-ciphertext"),
            "tag": b64(b"1" * 16),
            "aad": b64(additional_authenticated_data),
        }
    ).encode()


def package(result, **kwargs) -> PreparedDelivery:
    return prepare_delivery(result, **kwargs)


def app(*, detect=no_semantics, verify=clean_llm, **overrides):
    """The adapter with the recovery pipeline; ``detect``/``verify`` fake the LLM."""
    arguments = {
        "processor": fake_processor(detect, verify),
        "policy": RecoveryPolicy(),
        "rule_detectors": (no_rules,),
        "rules_has_pii": clean_rules,
        "encrypt_manifest": fake_encryptor,
        "authenticate": authenticated,
        "request_deadline_seconds": 1.0,
    }
    arguments.update(overrides)
    return create_app(**arguments)


def multipart_parts(response: httpx.Response):
    mime = (
        b"MIME-Version: 1.0\r\nContent-Type: "
        + response.headers["content-type"].encode("ascii")
        + b"\r\n\r\n"
        + response.content
    )
    message = BytesParser(policy=policy.default).parsebytes(mime)
    assert message.is_multipart()
    assert not message.defects
    return {
        part.get_param("name", header="content-disposition"): part
        for part in message.iter_parts()
    }


def assert_private_response(response: httpx.Response) -> None:
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_raw_document_real_core_and_three_part_delivery_after_verification(
    capsys, caplog
) -> None:
    source = f"# เอกสาร\r\n\nชื่อ {CANARY}\t\nจบ \n"
    expected = "# เอกสาร\r\n\nชื่อ [PII_NAME_1]\t\nจบ \n"
    calls: list[str] = []
    manifests: list[dict[str, object]] = []

    async def detect(text: str) -> list[PiiMatch]:
        calls.append("detect")
        assert text == source
        start = text.index(CANARY)
        return [PiiMatch("NAME", CANARY, start, start + len(CANARY))]

    async def verify(text: str) -> bool:
        calls.append("verify")
        assert text == expected
        return False

    def encrypt(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        calls.append("encrypt")
        manifests.append(json.loads(plaintext))
        return fake_encryptor(
            plaintext, additional_authenticated_data=additional_authenticated_data
        )

    application = app(
        detect=detect,
        verify=verify,
        encrypt_manifest=encrypt,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        response = await client.post(
            "/redact",
            content=source.encode("utf-8"),
            headers={"Content-Type": "text/markdown"},
        )
    assert response.status_code == 200
    assert_private_response(response)
    assert calls == ["detect", "verify", "encrypt"]
    parts = multipart_parts(response)
    assert set(parts) == {"redacted_md", "pii_manifest", "metadata"}
    markdown = parts["redacted_md"]
    assert markdown.get_content_type() == "text/markdown"
    assert markdown.get_payload(decode=True) == expected.encode("utf-8")
    assert markdown.get_filename() == "redacted.md"
    metadata_bytes = parts["metadata"].get_payload(decode=True)
    metadata = json.loads(metadata_bytes)
    assert metadata["created_at"].endswith("Z")
    assert UUID(metadata["document_id"]).version == 4
    assert UUID(metadata["delivery_id"]).version == 4
    assert metadata["document_id"] != metadata["delivery_id"]
    assert (
        metadata["redacted_md_sha256"] == hashlib.sha256(expected.encode()).hexdigest()
    )
    manifest = manifests[0]
    assert manifest["document_id"] == metadata["document_id"]
    assert manifest["entries"] == [
        {
            "placeholder": "[PII_NAME_1]",
            "pii_type": "NAME",
            "occurrence_index": 1,
            "original_value": CANARY,
            "redacted_at": metadata["created_at"],
        }
    ]
    encrypted = json.loads(parts["pii_manifest"].get_payload(decode=True))
    assert encrypted["aad"] == b64(metadata_bytes)
    assert CANARY not in response.text
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err + caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "text/markdown",
        'text/plain; charset="UTF-8"',
        'text/plain; charset = "utf-8"',
    ],
)
async def test_plain_literal_quotes_and_json_examples_are_not_decoded(
    content_type,
) -> None:
    source = '  "literal text"\n{"example":"Markdown content"}\n  '
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app()), base_url="https://api.example"
    ) as client:
        response = await client.post(
            "/redact", content=source.encode(), headers={"Content-Type": content_type}
        )
    assert response.status_code == 200
    assert (
        multipart_parts(response)["redacted_md"].get_payload(decode=True)
        == source.encode()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [None, 5])
@pytest.mark.parametrize("character", ["x", "ก", "😀"])
@pytest.mark.parametrize("extra, status", [(0, 200), (1, 413)])
async def test_limit_counts_unicode_codepoints_not_utf8_bytes(
    limit, character, extra, status
) -> None:
    overrides = {} if limit is None else {"max_source_characters": limit}
    source = character * ((limit or http_api.DEFAULT_MAX_SOURCE_CHARACTERS) + extra)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(**overrides)),
        base_url="https://api.example",
    ) as client:
        response = await client.post(
            "/redact", content=source.encode(), headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == status
    if status == 200:
        assert (
            multipart_parts(response)["redacted_md"].get_payload(decode=True)
            == source.encode()
        )
    else:
        assert response.json()["error"] == "document_too_large"


@pytest.mark.asyncio
async def test_source_limit_precedes_core_nfc_normalization() -> None:
    seen: list[str] = []

    async def detect(source: str) -> list[PiiMatch]:
        seen.append(source)
        return []

    application = app(detect=detect, max_source_characters=10)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        accepted = await client.post(
            "/redact",
            content=("e\u0301" * 5).encode(),
            headers={"Content-Type": "text/plain"},
        )
        rejected = await client.post(
            "/redact",
            content=("e\u0301" * 6).encode(),
            headers={"Content-Type": "text/plain"},
        )
    assert accepted.status_code == 200
    assert seen == ["é" * 5]
    assert (
        multipart_parts(accepted)["redacted_md"].get_payload(decode=True)
        == ("é" * 5).encode()
    )
    assert rejected.status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers, body, status, code",
    [
        (
            {"Content-Type": "application/json"},
            b'{"markdown":"test"}',
            415,
            "unsupported_media_type",
        ),
        (
            {"Content-Type": "multipart/form-data; boundary=x"},
            b"test",
            415,
            "unsupported_media_type",
        ),
        (
            {"Content-Type": "text/plain; charset=latin-1"},
            b"test",
            415,
            "unsupported_media_type",
        ),
        (
            {"Content-Type": "text/plain; charset=utf-8; charset=utf-8"},
            b"test",
            415,
            "unsupported_media_type",
        ),
        (
            {"Content-Type": "text/plain", "Content-Encoding": "gzip"},
            b"test",
            415,
            "unsupported_media_type",
        ),
        ({"Content-Type": "text/plain"}, b"\xff", 400, "invalid_request"),
        ({"Content-Type": "text/plain"}, b"", 400, "invalid_request"),
        ({"Content-Type": "text/plain"}, b" \n\t ", 400, "invalid_request"),
        (
            {"Content-Type": "text/plain", "Content-Length": "-1"},
            b"test",
            400,
            "invalid_request",
        ),
        (
            {"Content-Type": "text/plain", "Content-Length": "garbage"},
            b"test",
            400,
            "invalid_request",
        ),
        (
            {"Content-Type": "text/plain", "Content-Length": "9" * 5000},
            b"test",
            413,
            "document_too_large",
        ),
        (
            {"Content-Type": "text/plain"},
            b"x" * (http_api.DEFAULT_MAX_SOURCE_CHARACTERS + 1),
            413,
            "document_too_large",
        ),
    ],
)
async def test_invalid_requests_never_call_processing_or_package(
    headers, body, status, code
) -> None:
    calls: list[str] = []

    async def detect(source: str) -> list[PiiMatch]:
        calls.append("detect")
        return []

    def encrypt(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        calls.append("encrypt")
        return fake_encryptor(
            plaintext, additional_authenticated_data=additional_authenticated_data
        )

    application = app(detect=detect, encrypt_manifest=encrypt)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        response = await client.post("/redact", content=body, headers=headers)
    assert response.status_code == status
    assert response.json()["error"] == code
    assert UUID(response.json()["document_id"]).version == 4
    assert_private_response(response)
    assert calls == []


@pytest.mark.asyncio
async def test_authentication_precedes_body_stream_and_all_processors() -> None:
    calls: list[str] = []

    async def unauthorized(request: Request) -> bool:
        calls.append("auth")
        return False

    async def body():
        calls.append("body")
        yield CANARY.encode()

    async def detect(source: str) -> list[PiiMatch]:
        calls.append("detect")
        return []

    application = app(authenticate=unauthorized, detect=detect)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        response = await client.post("/redact", content=body())
    assert response.status_code == 401
    assert response.json() == {"error": "authentication_failed"}
    assert_private_response(response)
    assert calls == ["auth"]


@pytest.mark.asyncio
@pytest.mark.parametrize("return_value", [1, "true", None])
async def test_non_boolean_authentication_results_are_rejected(return_value) -> None:
    async def invalid_auth(request: Request):
        return return_value

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(authenticate=invalid_auth)),
        base_url="https://api.example",
    ) as client:
        response = await client.post("/redact", content=CANARY)
    assert response.status_code == 401
    assert CANARY not in response.text


@pytest.mark.asyncio
async def test_split_utf8_chunks_are_combined_before_decoding() -> None:
    source = "ทดสอบ 😀\n"
    encoded = source.encode()

    async def body():
        for byte in encoded:
            yield bytes([byte])

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app()), base_url="https://api.example"
    ) as client:
        response = await client.post(
            "/redact", content=body(), headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 200
    assert multipart_parts(response)["redacted_md"].get_payload(decode=True) == encoded


@pytest.mark.asyncio
async def test_stream_size_bound_does_not_trust_declared_content_length() -> None:
    chunks_seen: list[int] = []

    async def body():
        for index in range(10):
            chunks_seen.append(index)
            yield b"x" * 1500

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(max_source_characters=2000)),
        base_url="https://api.example",
    ) as client:
        response = await client.post(
            "/redact",
            content=body(),
            headers={"Content-Type": "text/plain", "Content-Length": "1"},
        )
    assert response.status_code == 413
    assert chunks_seen == [0, 1, 2, 3, 4, 5]


@pytest.mark.asyncio
async def test_disconnect_during_upload_stops_before_processing() -> None:
    calls: list[str] = []
    sent: list[dict[str, object]] = []
    messages = iter(
        [
            {"type": "http.request", "body": CANARY.encode(), "more_body": True},
            {"type": "http.disconnect"},
        ]
    )

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    async def detect(source: str) -> list[PiiMatch]:
        calls.append("detect")
        return []

    application = app(detect=detect)
    await application(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/redact",
            "raw_path": b"/redact",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"content-type", b"text/plain")],
            "server": ("api.example", 443),
            "client": ("127.0.0.1", 5000),
        },
        receive,
        send,
    )
    assert calls == []
    assert sent[0]["status"] == 400
    assert CANARY.encode() not in sent[1]["body"]


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["auth", "detect", "verify", "encrypt"])
async def test_external_exceptions_never_echo_document_or_partial_output(
    stage, capsys, caplog
) -> None:
    calls: list[str] = []

    async def authorize(request: Request) -> bool:
        calls.append("auth")
        if stage == "auth":
            raise RuntimeError(CANARY)
        return True

    async def detect(source: str) -> list[PiiMatch]:
        calls.append("detect")
        if stage == "detect":
            raise RuntimeError(CANARY)
        return [PiiMatch("NAME", CANARY, 0, len(CANARY))]

    async def verify(source: str) -> bool:
        calls.append("verify")
        if stage == "verify":
            raise RuntimeError(CANARY)
        return False

    def encrypt(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        calls.append("encrypt")
        raise RuntimeError(CANARY)

    application = app(
        authenticate=authorize,
        detect=detect,
        verify=verify,
        encrypt_manifest=encrypt,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        response = await client.post(
            "/redact", content=CANARY.encode(), headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == (401 if stage == "auth" else 502)
    assert response.headers["content-type"] == "application/json"
    assert CANARY not in response.text
    assert "[PII_NAME_1]" not in response.text
    assert set(response.json()).issubset({"error", "document_id"})
    assert_private_response(response)
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err + caplog.text
    assert (
        calls
        == ["auth", "detect", "verify", "encrypt"][
            : ["auth", "detect", "verify", "encrypt"].index(stage) + 1
        ]
    )


@pytest.mark.asyncio
async def test_residual_pii_blocks_package_construction() -> None:
    package_called = False

    async def residual(source: str) -> bool:
        return True

    def encrypt(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        nonlocal package_called
        package_called = True
        return fake_encryptor(
            plaintext, additional_authenticated_data=additional_authenticated_data
        )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app(verify=residual, encrypt_manifest=encrypt)
        ),
        base_url="https://api.example",
    ) as client:
        response = await client.post(
            "/redact", content=CANARY.encode(), headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 502
    assert response.json()["error"] == "processing_failed"
    assert not package_called
    assert CANARY not in response.text


@pytest.mark.asyncio
async def test_response_waits_for_independent_verification_and_returns_once() -> None:
    verification_started = asyncio.Event()
    release = asyncio.Event()
    packaged: list[bool] = []

    async def verify(source: str) -> bool:
        verification_started.set()
        await release.wait()
        return False

    def encrypt(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        packaged.append(True)
        return fake_encryptor(
            plaintext, additional_authenticated_data=additional_authenticated_data
        )

    application = app(verify=verify, encrypt_manifest=encrypt)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        request_task = asyncio.create_task(
            client.post(
                "/redact", content=b"test", headers={"Content-Type": "text/plain"}
            )
        )
        await asyncio.wait_for(verification_started.wait(), timeout=0.5)
        assert not request_task.done()
        assert not packaged
        release.set()
        response = await request_task
    assert response.status_code == 200
    assert packaged == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["auth", "body", "detect", "verify"])
async def test_whole_request_deadline_cancels_async_work_without_partial_delivery(
    stage,
) -> None:
    cancelled: list[str] = []
    package_calls: list[bool] = []

    async def pause(name: str) -> None:
        if stage == name:
            try:
                await asyncio.sleep(1)
            finally:
                cancelled.append(name)

    async def authorize(request: Request) -> bool:
        await pause("auth")
        return True

    async def body():
        yield CANARY.encode()
        await pause("body")

    async def detect(source: str) -> list[PiiMatch]:
        await pause("detect")
        return []

    async def verify(source: str) -> bool:
        await pause("verify")
        return False

    def encrypt(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        package_calls.append(True)
        return fake_encryptor(
            plaintext, additional_authenticated_data=additional_authenticated_data
        )

    application = app(
        authenticate=authorize,
        detect=detect,
        verify=verify,
        encrypt_manifest=encrypt,
        request_deadline_seconds=0.03,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        response = await client.post(
            "/redact", content=body(), headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 504
    assert response.json()["error"] == "request_timeout"
    assert cancelled == [stage]
    assert not package_calls
    assert CANARY not in response.text


@pytest.mark.asyncio
async def test_sync_encryptor_deadline_overrun_never_returns_success() -> None:
    def slow_encryptor(
        plaintext: bytes, *, additional_authenticated_data: bytes
    ) -> bytes:
        time.sleep(0.03)
        return fake_encryptor(
            plaintext, additional_authenticated_data=additional_authenticated_data
        )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app(encrypt_manifest=slow_encryptor, request_deadline_seconds=0.01)
        ),
        base_url="https://api.example",
    ) as client:
        response = await client.post(
            "/redact", content=b"test", headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 504
    assert response.headers["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_external_task_cancellation_propagates_without_becoming_http_error() -> (
    None
):
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def detect(source: str) -> list[PiiMatch]:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    application = app(detect=detect)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        task = asyncio.create_task(
            client.post(
                "/redact", content=b"test", headers={"Content-Type": "text/plain"}
            )
        )
        await asyncio.wait_for(started.wait(), timeout=0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert cancelled.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    ["body", "content_type", "document_id", "delivery_id", "redacted_md_sha256"],
)
async def test_trusted_internal_serializer_invariant_failures_are_rejected(
    field, monkeypatch
) -> None:
    bad_values = {
        "body": b"",
        "content_type": "multipart/form-data; boundary=x\r\nX-Leak: " + CANARY,
        "document_id": uuid4(),
        "delivery_id": uuid4(),
        "redacted_md_sha256": "0" * 64,
    }

    def invalid_prepare(result, **kwargs):
        return replace(package(result, **kwargs), **{field: bad_values[field]})

    monkeypatch.setattr(http_api, "prepare_delivery", invalid_prepare)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app()),
        base_url="https://api.example",
    ) as client:
        response = await client.post(
            "/redact", content=b"test", headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 502
    assert CANARY not in response.text
    assert CANARY not in str(response.headers)


@pytest.mark.asyncio
async def test_trusted_internal_serializer_returning_coroutine_is_closed(
    monkeypatch,
) -> None:
    returned = []

    async def asynchronous_package(result, **kwargs):
        raise AssertionError("Async package must not run")

    def hidden_async_package(result, **kwargs):
        coroutine = asynchronous_package(result, **kwargs)
        returned.append(coroutine)
        return coroutine

    monkeypatch.setattr(http_api, "prepare_delivery", hidden_async_package)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app()),
        base_url="https://api.example",
    ) as client:
        response = await client.post(
            "/redact", content=b"test", headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 502
    assert getcoroutinestate(returned[0]) == "CORO_CLOSED"


@pytest.mark.parametrize(
    "deadline", [False, True, "1", None, 0, -1, float("nan"), float("inf"), 10**1000]
)
def test_invalid_deadlines_reject_factory_without_sensitive_details(deadline) -> None:
    with pytest.raises(
        HttpApiConfigurationError, match="^HTTP API configuration is invalid$"
    ):
        app(request_deadline_seconds=deadline)


@pytest.mark.parametrize("limit", [False, True, "10", None, 0, -1, 10.0])
def test_invalid_source_limits_reject_factory(limit) -> None:
    with pytest.raises(HttpApiConfigurationError):
        app(max_source_characters=limit)


@pytest.mark.parametrize(
    "dependency",
    [
        "processor",
        "policy",
        "rule_detectors",
        "rules_has_pii",
        "encrypt_manifest",
        "authenticate",
    ],
)
def test_required_dependencies_have_no_insecure_default(dependency) -> None:
    with pytest.raises(HttpApiConfigurationError):
        app(**{dependency: None})


def test_factory_rejects_async_encryptor() -> None:
    async def async_encryptor(
        plaintext: bytes, *, additional_authenticated_data: bytes
    ):
        return fake_encryptor(
            plaintext, additional_authenticated_data=additional_authenticated_data
        )

    with pytest.raises(HttpApiConfigurationError):
        app(encrypt_manifest=async_encryptor)


def test_factory_cannot_accept_an_arbitrary_package_builder() -> None:
    builder_called = False

    def uncontrolled_builder(result, **kwargs):
        nonlocal builder_called
        builder_called = True
        prepared = package(result, **kwargs)
        return replace(prepared, body=CANARY.encode())

    with pytest.raises(
        TypeError, match="unexpected keyword argument 'prepare_package'"
    ):
        app(prepare_package=uncontrolled_builder)
    assert not builder_called


@pytest.mark.asyncio
@pytest.mark.parametrize("plaintext_result", [b"plaintext-canary", b'{"entries":[]}'])
async def test_plaintext_encryptor_output_cannot_become_success(
    plaintext_result,
) -> None:
    def plaintext_encryptor(plaintext: bytes, *, additional_authenticated_data: bytes):
        return plaintext_result

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(encrypt_manifest=plaintext_encryptor)),
        base_url="https://api.example",
    ) as client:
        response = await client.post(
            "/redact", content=CANARY.encode(), headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 502
    assert response.json()["error"] == "processing_failed"
    assert CANARY not in response.text
    assert "plaintext-canary" not in response.text
    assert "[PII_NAME_1]" not in response.text
    assert response.headers["content-type"] == "application/json"
    assert_private_response(response)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method, path, status, code",
    [
        ("GET", "/redact", 405, "method_not_allowed"),
        ("POST", "/other", 404, "not_found"),
        ("POST", "/redact/?query=synthetic", 404, "not_found"),
    ],
)
async def test_framework_errors_are_safe_and_not_cached(
    method, path, status, code
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app()), base_url="https://api.example"
    ) as client:
        response = await client.request(method, path, content=CANARY)
    assert response.status_code == status
    assert response.json() == {"error": code}
    if status == 405:
        assert response.headers["allow"] == "POST"
    assert_private_response(response)
    assert CANARY not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("verification_unavailable", [False, True])
async def test_automatic_recovery_http_delivers_only_after_final_verification(
    monkeypatch, verification_unavailable
):
    import os
    from urllib.parse import parse_qs

    from pii_pipeline.llm.client import LlmProxyClient
    from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
    from pii_pipeline.llm.processing import LlmDocumentProcessor
    from pii_pipeline.llm.windows import make_text_window
    from pii_pipeline.recovery.process import RecoveryPolicy

    for name in list(os.environ):
        if name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(name)
    order = []

    def wire(request):
        form = parse_qs(request.content.decode())
        role = next(iter(json.loads(form["json_schema"][0])["properties"]))
        order.append(role)
        if role == "has_pii":
            if verification_unavailable:
                raise httpx.ReadTimeout("Synthetic confidential error")
            output = {"has_pii": False, "findings": []}
        else:
            output = {
                "candidates": [
                    {
                        "pii_type": "NAME",
                        "value": "Alicee" if len(order) == 1 else "Alice",
                    }
                ]
            }
        return httpx.Response(
            200,
            json={
                "status": "success",
                "model": LLM_PROXY_MODEL,
                "structured_output": output,
            },
        )

    def plan(source):
        return [make_text_window(source, 0, len(source))]

    def encrypt(plaintext, **kwargs):
        order.append("encrypt")
        return fake_encryptor(plaintext, **kwargs)

    async with LlmProxyClient(
        LlmProxySettings(
            base_url="https://proxy.example",
            api_key="synthetic-key",
            max_retries=0,
            _env_file=None,
        ),
        transport=httpx.MockTransport(wire),
    ) as llm:
        processor = LlmDocumentProcessor(llm, plan, plan)
        service = app(
            processor=processor, policy=RecoveryPolicy(), encrypt_manifest=encrypt
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=service), base_url="https://api.example"
        ) as caller:
            response = await caller.post(
                "/redact",
                content="Name Alice",
                headers={"content-type": "text/markdown"},
            )
    if verification_unavailable:
        assert response.status_code == 502
        assert response.json()["error"] == "processing_failed"
        assert "encrypt" not in order and "Alice" not in response.text
        assert order == ["candidates", "candidates", "has_pii", "has_pii"]
    else:
        assert response.status_code == 200
        parts = multipart_parts(response)
        assert set(parts) == {"redacted_md", "pii_manifest", "metadata"}
        assert (
            parts["redacted_md"].get_payload(decode=True).decode()
            == "Name [PII_NAME_1]"
        )
        assert order == ["candidates", "candidates", "has_pii", "encrypt"]


async def async_rules(source):
    return []


@pytest.mark.parametrize(
    "extra",
    [
        {"processor": object()},
        {"policy": object()},
        {"rule_detectors": ()},
        {"rule_detectors": [lambda source: []]},
        {"rule_detectors": (async_rules,)},
        {"rules_has_pii": async_rules},
    ],
)
def test_invalid_pipeline_configuration_rejected(extra):
    with pytest.raises(HttpApiConfigurationError):
        app(**extra)


@pytest.mark.asyncio
async def test_failure_log_names_the_cause_chain_without_private_text(caplog):
    class SyntheticProxyError(Exception):
        reason_code = "unsuccessful_envelope"

    async def failing(source: str) -> list[PiiMatch]:
        try:
            raise SyntheticProxyError(f"proxy said {source}")
        except SyntheticProxyError:
            raise RuntimeError(f"wrapped {source}") from None

    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(detect=failing)),
        base_url="https://api.example",
    ) as client:
        response = await client.post(
            "/redact", content=CANARY.encode(), headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 502
    records = [r for r in caplog.records if r.name == "pii_pipeline.http_api"]
    assert len(records) == 1 and records[0].levelname == "WARNING"
    line = records[0].getMessage()
    assert "status=502" in line
    assert f"document_id={response.json()['document_id']}" in line
    assert "SyntheticProxyError:unsuccessful_envelope" in line
    assert CANARY not in line and "proxy said" not in line and "wrapped" not in line


@pytest.mark.asyncio
async def test_success_is_logged_with_counts_only(caplog):
    caplog.set_level("INFO", logger="pii_pipeline.http_api")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app()), base_url="https://api.example"
    ) as client:
        response = await client.post(
            "/redact", content=CANARY.encode(), headers={"Content-Type": "text/plain"}
        )
    assert response.status_code == 200
    (record,) = [r for r in caplog.records if r.name == "pii_pipeline.http_api"]
    assert record.levelname == "INFO" and "status=200" in record.getMessage()
    assert " residual=- " in record.getMessage()
    assert CANARY not in record.getMessage()


def test_residual_summary_reports_fixed_types_and_shapes_only():
    assert request_log.residual_summary([{"event": "FINAL_VERIFIED"}]) == "-"
    events = [
        {
            "event": "RESIDUAL_RECOVERY_STARTED",
            "finding_types": ["ADDRESS"],
            "rules_found": False,
        },
        {
            "event": "RESIDUAL_CANDIDATES",
            "candidates": 2,
            "by_type": {"ADDRESS": 1, "NAME": 1},
            "with_placeholder": 1,
            "placeholder_parts": 2,
            "land_prefix_trimmed": 0,
            "unmapped": 1,
            "issue_codes": ["value_not_found", CANARY],
        },
    ]
    assert request_log.residual_summary(events) == (
        "findings:ADDRESS;rules:no;candidates:2;types:ADDRESS_1+NAME_1;"
        "placeholder:1;placeholder_parts:2;land_prefix_trimmed:0;unmapped:1;"
        "issues:value_not_found"
    )
    assert request_log.residual_summary(events[:1]) == "findings:ADDRESS;rules:no"


def test_safe_reason_keeps_fixed_core_messages_and_drops_external_ones():
    from pii_pipeline.core.verification import VerificationError

    try:
        try:
            raise RuntimeError(CANARY)
        except RuntimeError:
            raise VerificationError("Residual PII remains after bounded recovery")
    except VerificationError as error:
        reason = request_log.safe_reason(error)
    assert reason == (
        'VerificationError("Residual PII remains after bounded recovery")'
        " <- RuntimeError"
    )
    assert CANARY not in reason


# Approved 2026-10-16: the manifest part is optional and off in the service
# by default; without it the response carries redacted_md and metadata only.


async def _post_canary(application) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="https://api.example"
    ) as client:
        return await client.post(
            "/redact",
            content=f"ชื่อ {CANARY}".encode(),
            headers={"Content-Type": "text/markdown"},
        )


async def _detect_canary(text: str) -> list[PiiMatch]:
    start = text.index(CANARY)
    return [PiiMatch("NAME", CANARY, start, start + len(CANARY))]


@pytest.mark.asyncio
@pytest.mark.parametrize("encryptor", ["fake", None])
async def test_without_the_manifest_part_only_redacted_md_and_metadata_leave(
    encryptor,
) -> None:
    encrypted: list[bytes] = []

    def encrypt(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        encrypted.append(plaintext)
        return fake_encryptor(
            plaintext, additional_authenticated_data=additional_authenticated_data
        )

    response = await _post_canary(
        app(
            detect=_detect_canary,
            encrypt_manifest=encrypt if encryptor else None,
            return_manifest=False,
        )
    )
    assert response.status_code == 200
    parts = multipart_parts(response)
    assert set(parts) == {"redacted_md", "metadata"}
    assert parts["redacted_md"].get_payload(decode=True) == "ชื่อ [PII_NAME_1]".encode()
    assert CANARY not in response.text
    # Without an encryptor no manifest is built at all.
    assert len(encrypted) == (1 if encryptor else 0)


@pytest.mark.parametrize(
    "overrides",
    [
        {"encrypt_manifest": None},  # returning a manifest needs an encryptor
        {"encrypt_manifest": None, "return_manifest": False, "store_manifest": "store"},
        {"return_manifest": "no"},
    ],
)
def test_a_manifest_without_an_encryptor_is_a_configuration_error(overrides) -> None:
    async def store(package) -> None:
        return None

    if overrides.get("store_manifest") == "store":
        overrides = {**overrides, "store_manifest": store}
    with pytest.raises(HttpApiConfigurationError):
        app(**overrides)


@pytest.mark.asyncio
async def test_without_metadata_the_body_is_the_redacted_markdown() -> None:
    response = await _post_canary(
        app(
            detect=_detect_canary,
            encrypt_manifest=None,
            return_manifest=False,
            return_metadata=False,
        )
    )
    assert response.status_code == 200
    assert_private_response(response)
    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    assert response.content == "ชื่อ [PII_NAME_1]".encode()
    assert UUID(response.headers["x-document-id"]).version == 4


def test_a_manifest_without_its_metadata_is_a_configuration_error() -> None:
    with pytest.raises(HttpApiConfigurationError):
        app(return_manifest=True, return_metadata=False)
