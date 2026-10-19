"""Multipart packaging after verification, with a required encryption adapter.

The injected adapter owns actual authenticated encryption and key selection.
Structural JWE checks cannot prove encryption or successful decryption. No
production encryptor or plaintext fallback is provided by this module.
"""

import base64
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from inspect import iscoroutine, iscoroutinefunction
from typing import Protocol
from uuid import UUID, uuid4

from ..core.models import PiiEntry, RedactionResult
from ..core.pii_types import CANONICAL_PII_TYPE_SET
from ..llm.prompts import DETECTION_PROMPT_VERSION

_PLACEHOLDER_PATTERN = re.compile(r"\[PII_[A-Z][A-Z0-9_]*_[0-9]+\]", re.IGNORECASE)
_BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
_JWE_FIELDS = frozenset(
    {"protected", "encrypted_key", "iv", "ciphertext", "tag", "aad"}
)
_PROTECTED_FIELDS = frozenset({"alg", "enc", "kid", "cty", "typ"})
_MAX_BOUNDARY_ATTEMPTS = 8


class DeliveryPackageError(ValueError):
    """The package could not be prepared; messages never contain document data."""


class ManifestEncryptor(Protocol):
    """Caller-supplied real encryption adapter; test fakes are never production."""

    def __call__(
        self, plaintext: bytes, *, additional_authenticated_data: bytes
    ) -> bytes:
        """Return flattened JWE JSON bytes with the supplied metadata as AAD."""
        ...


@dataclass(frozen=True, slots=True)
class PreparedDelivery:
    body: bytes = field(repr=False)
    content_type: str
    document_id: UUID
    delivery_id: UUID
    redacted_md_sha256: str
    # Exact bytes of the manifest and metadata parts, for an optional store.
    encrypted_manifest: bytes = field(default=b"", repr=False)
    metadata: bytes = field(default=b"", repr=False)


# Body type when only the redacted Markdown is returned.
PLAIN_CONTENT_TYPE = "text/markdown; charset=utf-8"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Invalid package field")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError("Invalid package field")


def _decode_json(value: bytes) -> object:
    return json.loads(
        value.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )


def _decode_base64url(value: object) -> bytes:
    if type(value) is not str or _BASE64URL_PATTERN.fullmatch(value) is None:
        raise ValueError("Invalid package field")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("Invalid package field")
    return decoded


def _validate_encrypted_manifest(encrypted: object, metadata: bytes) -> bytes:
    if iscoroutine(encrypted):
        # A synchronous adapter must not retain manifest bytes in a suspended
        # frame or emit an unawaited-coroutine warning on rejection.
        encrypted.close()
    if type(encrypted) is not bytes:
        raise ValueError("Invalid package field")
    envelope = _decode_json(encrypted)
    if type(envelope) is not dict or set(envelope) != _JWE_FIELDS:
        raise ValueError("Invalid package field")
    protected = _decode_json(_decode_base64url(envelope["protected"]))
    if (
        type(protected) is not dict
        or not {"alg", "enc"}.issubset(protected)
        or not set(protected).issubset(_PROTECTED_FIELDS)
        or protected["alg"] != "RSA-OAEP-256"
        or protected["enc"] != "A256GCM"
    ):
        raise ValueError("Invalid package field")
    if "kid" in protected:
        kid = protected["kid"]
        if (
            type(kid) is not str
            or not 1 <= len(kid) <= 128
            or not kid.isascii()
            or any(ord(character) < 32 or ord(character) == 127 for character in kid)
        ):
            raise ValueError("Invalid package field")
    if "cty" in protected and protected["cty"] != "application/json":
        raise ValueError("Invalid package field")
    if "typ" in protected and protected["typ"] != "JWE":
        raise ValueError("Invalid package field")
    if (
        not _decode_base64url(envelope["encrypted_key"])
        or len(_decode_base64url(envelope["iv"])) != 12
        or not _decode_base64url(envelope["ciphertext"])
        or len(_decode_base64url(envelope["tag"])) != 16
        or _decode_base64url(envelope["aad"]) != metadata
    ):
        raise ValueError("Invalid package field")
    return encrypted


def _validate_result(result: RedactionResult) -> None:
    if (
        type(result) is not RedactionResult
        or type(result.redacted_markdown) is not str
        or type(result.entries) is not tuple
    ):
        raise ValueError("Invalid package field")
    counts: dict[str, int] = {}
    placeholders: list[str] = []
    for entry in result.entries:
        if (
            type(entry) is not PiiEntry
            or type(entry.pii_type) is not str
            or entry.pii_type not in CANONICAL_PII_TYPE_SET
            or type(entry.occurrence_index) is not int
            or type(entry.original_value) is not str
            or not entry.original_value.strip()
            or not unicodedata.is_normalized("NFC", entry.original_value)
        ):
            raise ValueError("Invalid package field")
        index = counts.get(entry.pii_type, 0) + 1
        if (
            entry.occurrence_index != index
            or type(entry.placeholder) is not str
            or entry.placeholder != f"[PII_{entry.pii_type}_{index}]"
        ):
            raise ValueError("Invalid package field")
        counts[entry.pii_type] = index
        placeholders.append(entry.placeholder)
    if _PLACEHOLDER_PATTERN.findall(result.redacted_markdown) != placeholders:
        raise ValueError("Invalid package field")


def _multipart_body(parts: tuple[tuple[bytes, bytes], ...]) -> tuple[bytes, str]:
    for _ in range(_MAX_BOUNDARY_ATTEMPTS):
        boundary = f"pii-{uuid4().hex}"
        boundary_bytes = boundary.encode("ascii")
        if all(boundary_bytes not in payload for _, payload in parts):
            break
    else:
        raise ValueError("Invalid package field")
    body = b"".join(
        b"--" + boundary_bytes + b"\r\n" + headers + b"\r\n\r\n" + payload + b"\r\n"
        for headers, payload in parts
    )
    return (
        body + b"--" + boundary_bytes + b"--\r\n",
        f"multipart/form-data; boundary={boundary}",
    )


def _prepare_delivery(
    result: RedactionResult,
    *,
    document_id: UUID,
    delivery_id: UUID,
    redacted_at: datetime,
    encrypt_manifest: ManifestEncryptor | None,
    return_manifest: bool,
    return_metadata: bool,
) -> PreparedDelivery:
    _validate_result(result)
    if (
        type(document_id) is not UUID
        or type(delivery_id) is not UUID
        or type(redacted_at) is not datetime
        or redacted_at.tzinfo is None
        or redacted_at.utcoffset() is None
        or type(return_manifest) is not bool
        or type(return_metadata) is not bool
        or (encrypt_manifest is None and return_manifest)
        # The metadata bytes are the manifest's AAD: never one without the other.
        or (return_manifest and not return_metadata)
        or (
            encrypt_manifest is not None
            and (
                not callable(encrypt_manifest)
                or iscoroutinefunction(encrypt_manifest)
                or iscoroutinefunction(type(encrypt_manifest).__call__)
            )
        )
    ):
        raise ValueError("Invalid package field")
    timestamp = redacted_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    markdown_bytes = result.redacted_markdown.encode("utf-8")
    markdown_hash = hashlib.sha256(markdown_bytes).hexdigest()
    metadata = _canonical_json(
        {
            "document_id": str(document_id),
            "detector_version": DETECTION_PROMPT_VERSION,
            "delivery_id": str(delivery_id),
            "redacted_md_sha256": markdown_hash,
            "created_at": timestamp,
        }
    )
    encrypted = (
        b""
        if encrypt_manifest is None
        else _encrypted_manifest(
            result, document_id, timestamp, metadata, encrypt_manifest
        )
    )
    if not return_metadata:
        # Plain mode: the body is the redacted Markdown itself, nothing else.
        return PreparedDelivery(
            markdown_bytes,
            PLAIN_CONTENT_TYPE,
            document_id,
            delivery_id,
            markdown_hash,
            encrypted_manifest=encrypted,
            metadata=metadata,
        )
    manifest_part = (
        (
            b'Content-Disposition: form-data; name="pii_manifest"; filename="pii_manifest.json"'
            b"\r\nContent-Type: application/json"
        ),
        encrypted,
    )
    body, content_type = _multipart_body(
        (
            (
                (
                    b'Content-Disposition: form-data; name="redacted_md"; filename="redacted.md"'
                    b"\r\nContent-Type: text/markdown; charset=utf-8"
                ),
                markdown_bytes,
            ),
            *((manifest_part,) if return_manifest else ()),
            (
                (
                    b'Content-Disposition: form-data; name="metadata"'
                    b"\r\nContent-Type: application/json"
                ),
                metadata,
            ),
        )
    )
    return PreparedDelivery(
        body,
        content_type,
        document_id,
        delivery_id,
        markdown_hash,
        encrypted_manifest=encrypted,
        metadata=metadata,
    )


def _encrypted_manifest(
    result: RedactionResult,
    document_id: UUID,
    timestamp: str,
    metadata: bytes,
    encrypt_manifest: ManifestEncryptor,
) -> bytes:
    """The manifest exists only in memory, and only encrypted leaves here."""
    manifest = _canonical_json(
        {
            "document_id": str(document_id),
            "entries": [
                {
                    "placeholder": entry.placeholder,
                    "pii_type": entry.pii_type,
                    "occurrence_index": entry.occurrence_index,
                    "original_value": entry.original_value,
                    "redacted_at": timestamp,
                }
                for entry in result.entries
            ],
        }
    )
    return _validate_encrypted_manifest(
        encrypt_manifest(manifest, additional_authenticated_data=metadata), metadata
    )


def prepare_delivery(
    result: RedactionResult,
    *,
    document_id: UUID,
    delivery_id: UUID,
    redacted_at: datetime,
    encrypt_manifest: ManifestEncryptor | None,
    return_manifest: bool = True,
    return_metadata: bool = True,
) -> PreparedDelivery:
    """Package an already verified result with caller-authoritative UTC timestamps.

    The caller must complete verification first. The manifest is serialized only
    in memory and passed to the trusted encryption adapter. The adapter must
    authenticate the exact canonical metadata bytes as JWE external AAD.
    ``return_manifest=False`` leaves the pii_manifest part out of the body (the
    encrypted manifest stays on the package for an optional store); without an
    encryptor no manifest is built at all and none can be returned.
    ``return_metadata=False`` (only without the manifest) makes the body the
    redacted Markdown itself (``text/markdown``) instead of a multipart package.
    Errors never expose callback exceptions, raw responses, or document values.
    """
    try:
        return _prepare_delivery(
            result,
            document_id=document_id,
            delivery_id=delivery_id,
            redacted_at=redacted_at,
            encrypt_manifest=encrypt_manifest,
            return_manifest=return_manifest,
            return_metadata=return_metadata,
        )
    except Exception:  # noqa: BLE001, S110 - never log or retain adapter PII errors.
        pass
    raise DeliveryPackageError("Delivery package is invalid")
