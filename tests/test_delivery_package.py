"""Multipart and fail-closed checks with explicitly non-cryptographic JWE fakes."""

import base64
import gc
import hashlib
import json
import traceback
import warnings
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from uuid import UUID

import pytest

import pii_pipeline.delivery_package as package_module
from pii_pipeline.delivery_package import DeliveryPackageError, prepare_delivery
from pii_pipeline.llm_prompts import DETECTION_PROMPT_VERSION
from pii_pipeline.models import PiiEntry, RedactionResult

DOCUMENT_ID = UUID("00000000-0000-4000-8000-000000000001")
DELIVERY_ID = UUID("00000000-0000-4000-8000-000000000002")
REDACTED_AT = datetime(2026, 10, 2, 15, 30, tzinfo=timezone(timedelta(hours=7)))
ORIGINAL_VALUE = "นายทดสอบ\tตัวอย่าง"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def fake_jwe(aad: bytes, *, protected: dict[str, object] | None = None) -> bytes:
    """Test-only envelope; this helper does not encrypt anything."""
    return json.dumps(
        {
            "protected": b64url(
                json.dumps(
                    protected or {"alg": "RSA-OAEP-256", "enc": "A256GCM"}
                ).encode("utf-8")
            ),
            "encrypted_key": b64url(b"test-only-wrapped-key"),
            "iv": b64url(b"0" * 12),
            "ciphertext": b64url(b"test-only-ciphertext"),
            "tag": b64url(b"1" * 16),
            "aad": b64url(aad),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def fake_encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
    return fake_jwe(additional_authenticated_data)


def result(markdown: str = "ชื่อ [PII_NAME_1]") -> RedactionResult:
    return RedactionResult(
        markdown, (PiiEntry("[PII_NAME_1]", "NAME", 1, ORIGINAL_VALUE),)
    )


def prepare(source: RedactionResult, **overrides: object):
    options = {
        "document_id": DOCUMENT_ID,
        "delivery_id": DELIVERY_ID,
        "redacted_at": REDACTED_AT,
        "encrypt_manifest": fake_encryptor,
    }
    options.update(overrides)
    return prepare_delivery(source, **options)


def mime_parts(prepared):
    message = BytesParser(policy=policy.default).parsebytes(
        b"MIME-Version: 1.0\r\nContent-Type: "
        + prepared.content_type.encode("ascii")
        + b"\r\n\r\n"
        + prepared.body
    )
    assert message.is_multipart()
    assert not message.defects
    return list(message.iter_parts())


@pytest.mark.parametrize(
    "markdown",
    [
        'ชื่อ "[PII_NAME_1]"\nข้อความภาษาไทย\\path',
        "# เอกสาร\r\nชื่อ [PII_NAME_1]\r\nท้าย\r\n",
        "# เอกสาร\nชื่อ [PII_NAME_1]\nท้าย\n",
        "ชื่อ [PII_NAME_1] ไม่มี newline ปิดท้าย",
        '😀\tชื่อ [PII_NAME_1]\r\n\\literal\\n "quoted"\nท้าย',
    ],
)
def test_multipart_preserves_exact_markdown_bytes_and_has_three_named_parts(
    markdown: str,
) -> None:
    observed: dict[str, bytes] = {}

    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        observed["plaintext"] = plaintext
        observed["aad"] = additional_authenticated_data
        observed["jwe"] = fake_jwe(additional_authenticated_data)
        return observed["jwe"]

    prepared = prepare(result(markdown), encrypt_manifest=encryptor)
    parts = mime_parts(prepared)
    assert [part.get_param("name", header="content-disposition") for part in parts] == [
        "redacted_md",
        "pii_manifest",
        "metadata",
    ]
    assert len(parts) == 3
    assert [part.get_content_type() for part in parts] == [
        "text/markdown",
        "application/json",
        "application/json",
    ]
    assert parts[0].get_content_charset() == "utf-8"
    assert [part.get_filename() for part in parts] == [
        "redacted.md",
        "pii_manifest.json",
        None,
    ]
    assert parts[0].get_payload(decode=True) == markdown.encode("utf-8")
    assert parts[1].get_payload(decode=True) == observed["jwe"]
    assert parts[2].get_payload(decode=True) == observed["aad"]
    assert prepared.document_id == DOCUMENT_ID
    assert prepared.delivery_id == DELIVERY_ID
    expected_hash = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
    assert prepared.redacted_md_sha256 == expected_hash
    metadata = json.loads(observed["aad"])
    assert metadata == {
        "document_id": str(DOCUMENT_ID),
        "delivery_id": str(DELIVERY_ID),
        "detector_version": DETECTION_PROMPT_VERSION,
        "redacted_md_sha256": expected_hash,
        "created_at": "2026-10-02T08:30:00Z",
    }
    assert observed["aad"] == json.dumps(
        metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    manifest = json.loads(observed["plaintext"])
    assert manifest == {
        "document_id": str(DOCUMENT_ID),
        "entries": [
            {
                "placeholder": "[PII_NAME_1]",
                "pii_type": "NAME",
                "occurrence_index": 1,
                "original_value": ORIGINAL_VALUE,
                "redacted_at": "2026-10-02T08:30:00Z",
            }
        ],
    }
    assert ORIGINAL_VALUE.encode("utf-8") not in prepared.body
    assert ORIGINAL_VALUE not in repr(prepared)
    assert markdown not in repr(prepared)
    assert ORIGINAL_VALUE not in repr(result(markdown))
    with pytest.raises(FrozenInstanceError):
        prepared.body = b"other"  # type: ignore[misc]


def test_per_type_occurrence_indices_preserve_document_order() -> None:
    entries = (
        PiiEntry("[PII_NAME_1]", "NAME", 1, ORIGINAL_VALUE),
        PiiEntry("[PII_FAX_1]", "FAX", 1, "000-123-4567"),
        PiiEntry("[PII_NAME_2]", "NAME", 2, ORIGINAL_VALUE),
    )
    captured: list[bytes] = []

    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        captured.append(plaintext)
        return fake_jwe(additional_authenticated_data)

    prepared = prepare(
        RedactionResult("[PII_NAME_1]\n[PII_FAX_1]\n[PII_NAME_2]", entries),
        encrypt_manifest=encryptor,
    )
    assert len(mime_parts(prepared)) == 3
    manifest = json.loads(captured[0])
    assert [entry["placeholder"] for entry in manifest["entries"]] == [
        entry.placeholder for entry in entries
    ]
    assert [entry["occurrence_index"] for entry in manifest["entries"]] == [1, 1, 2]


def test_clean_document_still_requires_encrypted_empty_manifest() -> None:
    captured: list[bytes] = []

    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        captured.append(plaintext)
        return fake_jwe(additional_authenticated_data)

    prepared = prepare(RedactionResult("ไม่มีข้อมูลบุคคล\n", ()), encrypt_manifest=encryptor)
    assert json.loads(captured[0]) == {"document_id": str(DOCUMENT_ID), "entries": []}
    assert mime_parts(prepared)[0].get_payload(decode=True) == "ไม่มีข้อมูลบุคคล\n".encode()


@pytest.mark.parametrize(
    "entry",
    [
        PiiEntry("[PII_NAME_1]", "name", 1, ORIGINAL_VALUE),
        PiiEntry("[PII_CUSTOM_1]", "CUSTOM", 1, ORIGINAL_VALUE),
        PiiEntry("[PII_NAME_1]", "NAME", True, ORIGINAL_VALUE),
        PiiEntry("[PII_NAME_1]", "NAME", 0, ORIGINAL_VALUE),
        PiiEntry("[PII_NAME_2]", "NAME", 2, ORIGINAL_VALUE),
        PiiEntry("[PII_NAME_2]", "NAME", 1, ORIGINAL_VALUE),
        PiiEntry("[pii_name_1]", "NAME", 1, ORIGINAL_VALUE),
        PiiEntry("[PII_NAME_1]", "NAME", 1, ""),
        PiiEntry("[PII_NAME_1]", "NAME", 1, " \t\n"),
        PiiEntry("[PII_NAME_1]", "NAME", 1, "Cafe\u0301"),
        PiiEntry("[PII_NAME_1]", "NAME", 1, None),  # type: ignore[arg-type]
    ],
)
def test_invalid_mapping_is_rejected_before_encryptor_runs(entry: PiiEntry) -> None:
    calls = 0

    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        nonlocal calls
        calls += 1
        return fake_jwe(additional_authenticated_data)

    with pytest.raises(DeliveryPackageError, match="Delivery package is invalid"):
        prepare(
            RedactionResult(entry.placeholder, (entry,)), encrypt_manifest=encryptor
        )
    assert calls == 0


@pytest.mark.parametrize(
    "source",
    [
        None,
        {},
        RedactionResult("[PII_NAME_1]", ()),
        result(""),
        result("[PII_NAME_1] [PII_NAME_1]"),
        result("[PII_NAME_1] [PII_CUSTOM_1]"),
        result("[PII_NAME_1] [PII_NAME_0]"),
        RedactionResult("[PII_NAME_1]", []),  # type: ignore[arg-type]
        RedactionResult("[PII_NAME_1]", ({"original_value": ORIGINAL_VALUE},)),  # type: ignore[arg-type]
        RedactionResult(
            "[PII_NAME_2] [PII_NAME_1]",
            (
                PiiEntry("[PII_NAME_1]", "NAME", 1, ORIGINAL_VALUE),
                PiiEntry("[PII_NAME_2]", "NAME", 2, ORIGINAL_VALUE),
            ),
        ),
    ],
)
def test_missing_duplicate_out_of_order_or_forged_placeholder_mapping_is_rejected(
    source: object,
) -> None:
    with pytest.raises(DeliveryPackageError):
        prepare(source)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"document_id": str(DOCUMENT_ID)},
        {"delivery_id": None},
        {"redacted_at": REDACTED_AT.replace(tzinfo=None)},
        {"redacted_at": "private-timestamp-canary"},
        {"encrypt_manifest": None},
    ],
)
def test_invalid_identifiers_naive_timestamp_or_missing_encryptor_are_refused(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(DeliveryPackageError):
        prepare(result(), **overrides)


@pytest.mark.parametrize(
    "output",
    [
        b"private-plaintext-canary",
        b'{"document_id":"private-document-canary","entries":[]}',
        b"[]",
        b"\xff",
        "private-plaintext-canary",
        None,
    ],
)
def test_plaintext_or_non_jwe_adapter_output_never_becomes_package(
    output: object,
) -> None:
    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes):
        return output

    with pytest.raises(DeliveryPackageError) as captured:
        prepare(result(), encrypt_manifest=encryptor)
    assert captured.value.args == ("Delivery package is invalid",)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("encrypted_key", ""),
        ("iv", b64url(b"0" * 11)),
        ("tag", b64url(b"1" * 15)),
        ("ciphertext", ""),
        ("ciphertext", "not-base64!"),
        ("ciphertext", "Zh"),
        ("ciphertext", "Zg=="),
        ("aad", b64url(b"wrong-metadata")),
        ("protected", b64url(b"[]")),
    ],
)
def test_malformed_jwe_fields_or_corrupted_metadata_aad_are_refused(
    field: str,
    value: object,
) -> None:
    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        envelope = json.loads(fake_jwe(additional_authenticated_data))
        envelope[field] = value
        return json.dumps(envelope).encode("utf-8")

    with pytest.raises(DeliveryPackageError):
        prepare(result(), encrypt_manifest=encryptor)


@pytest.mark.parametrize(
    "protected",
    [
        {"alg": "dir", "enc": "A256GCM"},
        {"alg": "RSA-OAEP-256", "enc": "A128GCM"},
        {"alg": "RSA-OAEP-256"},
        {"alg": "RSA-OAEP-256", "enc": "A256GCM", "zip": "DEF"},
        {"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": ""},
        {"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "x" * 129},
        {"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "คีย์"},
        {"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "key\r\n"},
        {"alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "text/plain"},
        {"alg": "RSA-OAEP-256", "enc": "A256GCM", "typ": "JWT"},
    ],
)
def test_unapproved_protected_algorithms_or_header_fields_are_refused(
    protected: dict[str, object],
) -> None:
    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        return fake_jwe(additional_authenticated_data, protected=protected)

    with pytest.raises(DeliveryPackageError):
        prepare(result(), encrypt_manifest=encryptor)


def test_optional_protected_headers_use_only_agreed_exact_values() -> None:
    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        return fake_jwe(
            additional_authenticated_data,
            protected={
                "alg": "RSA-OAEP-256",
                "enc": "A256GCM",
                "kid": "test-only-key",
                "cty": "application/json",
                "typ": "JWE",
            },
        )

    assert len(mime_parts(prepare(result(), encrypt_manifest=encryptor))) == 3


@pytest.mark.parametrize(
    "malformation", ["missing", "extra", "duplicate", "protected-duplicate"]
)
def test_jwe_requires_exact_nonduplicated_flattened_fields(malformation: str) -> None:
    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        envelope = json.loads(fake_jwe(additional_authenticated_data))
        if malformation == "missing":
            envelope.pop("tag")
        elif malformation == "extra":
            envelope["plaintext"] = "private-plaintext-canary"
        elif malformation == "duplicate":
            raw = json.dumps(envelope)
            return (raw[:-1] + ',"aad":"' + envelope["aad"] + '"}').encode("utf-8")
        else:
            envelope["protected"] = b64url(
                b'{"alg":"RSA-OAEP-256","alg":"RSA-OAEP-256","enc":"A256GCM"}'
            )
        return json.dumps(envelope).encode("utf-8")

    with pytest.raises(DeliveryPackageError):
        prepare(result(), encrypt_manifest=encryptor)


def test_boundary_collision_is_avoided_without_changing_markdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = UUID("00000000-0000-4000-8000-000000000003")
    second = UUID("00000000-0000-4000-8000-000000000004")
    generated = iter((first, second))
    monkeypatch.setattr(package_module, "uuid4", lambda: next(generated))
    markdown = f"pii-{first.hex}\r\nชื่อ [PII_NAME_1]"
    prepared = prepare(result(markdown))
    assert prepared.content_type.endswith(f"boundary=pii-{second.hex}")
    assert mime_parts(prepared)[0].get_payload(decode=True) == markdown.encode("utf-8")


def test_repeated_boundary_collision_fails_closed_with_bounded_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collision = UUID("00000000-0000-4000-8000-000000000003")
    calls = 0

    def repeated_uuid() -> UUID:
        nonlocal calls
        calls += 1
        return collision

    monkeypatch.setattr(package_module, "uuid4", repeated_uuid)
    with pytest.raises(DeliveryPackageError):
        prepare(result(f"pii-{collision.hex}\n[PII_NAME_1]"))
    assert calls == 8


def test_boundary_collision_in_encryptor_output_is_avoided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = UUID("00000000-0000-4000-8000-000000000003")
    second = UUID("00000000-0000-4000-8000-000000000004")
    generated = iter((first, second))
    monkeypatch.setattr(package_module, "uuid4", lambda: next(generated))

    def encryptor(plaintext: bytes, *, additional_authenticated_data: bytes) -> bytes:
        envelope = json.loads(fake_jwe(additional_authenticated_data))
        envelope["ciphertext"] = f"pii-{first.hex}"
        return json.dumps(envelope).encode("utf-8")

    prepared = prepare(result(), encrypt_manifest=encryptor)
    assert prepared.content_type.endswith(f"boundary=pii-{second.hex}")
    manifest = json.loads(mime_parts(prepared)[1].get_payload(decode=True))
    assert manifest["ciphertext"] == f"pii-{first.hex}"


def test_encryptor_fault_does_not_retain_or_print_pii_exception_context(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def broken_encryptor(
        plaintext: bytes, *, additional_authenticated_data: bytes
    ) -> bytes:
        raise RuntimeError(plaintext.decode("utf-8") + " private-key-canary")

    with pytest.raises(DeliveryPackageError) as captured:
        prepare(result(), encrypt_manifest=broken_encryptor)
    error = captured.value
    assert error.args == ("Delivery package is invalid",)
    assert error.__cause__ is None
    assert error.__context__ is None
    rendered = (
        repr(error) + repr(vars(error)) + "".join(traceback.format_exception(error))
    )
    for sensitive in (ORIGINAL_VALUE, "private-key-canary", "original_value"):
        assert sensitive not in rendered
    assert capsys.readouterr().out == ""


def test_hidden_async_encryptor_coroutine_is_closed_without_await_or_warning() -> None:
    observed = []
    executed = False

    async def asynchronous_adapter(plaintext: bytes, aad: bytes) -> bytes:
        nonlocal executed
        executed = True
        return fake_jwe(aad)

    def hidden_async_adapter(plaintext: bytes, *, additional_authenticated_data: bytes):
        coroutine = asynchronous_adapter(plaintext, additional_authenticated_data)
        assert coroutine.cr_frame is not None
        assert coroutine.cr_frame.f_locals["plaintext"] == plaintext
        observed.append(coroutine)
        return coroutine

    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        with pytest.raises(DeliveryPackageError) as captured:
            prepare(result(), encrypt_manifest=hidden_async_adapter)
        assert len(observed) == 1
        assert observed[0].cr_frame is None
        assert observed[0].cr_await is None
        assert executed is False
        gc.collect()
    assert not [item for item in recorded if issubclass(item.category, RuntimeWarning)]
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert captured.value.args == ("Delivery package is invalid",)


@pytest.mark.parametrize("callback_kind", ["function", "callable-object"])
def test_known_async_encryptors_are_rejected_before_manifest_callback(
    callback_kind: str,
) -> None:
    executed = False

    async def asynchronous_adapter(
        plaintext: bytes, *, additional_authenticated_data: bytes
    ) -> bytes:
        nonlocal executed
        executed = True
        return fake_jwe(additional_authenticated_data)

    class AsyncAdapter:
        async def __call__(
            self, plaintext: bytes, *, additional_authenticated_data: bytes
        ) -> bytes:
            return await asynchronous_adapter(
                plaintext, additional_authenticated_data=additional_authenticated_data
            )

    callback = asynchronous_adapter if callback_kind == "function" else AsyncAdapter()
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        with pytest.raises(DeliveryPackageError) as captured:
            prepare(result(), encrypt_manifest=callback)
        gc.collect()
    assert not [item for item in recorded if issubclass(item.category, RuntimeWarning)]
    assert executed is False
    assert captured.value.args == ("Delivery package is invalid",)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
