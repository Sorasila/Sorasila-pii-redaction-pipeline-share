"""Store each delivered manifest envelope through PostgREST.

The same REST interface serves the local Postgres + PostgREST store now and
Supabase later. Only the manifest envelope, the PII-free metadata and the key id
are sent. A failure raises ManifestStoreError so the request fails closed;
nothing here retries or falls back.
"""

import base64
import json
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from .delivery import PreparedDelivery

LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class ManifestStoreSettings(BaseSettings):
    """PII_STORE_URL and PII_STORE_TOKEN; without a URL nothing is stored."""

    model_config = SettingsConfigDict(
        env_prefix="PII_STORE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    url: str | None = None
    token: SecretStr | None = None


class ManifestStoreError(RuntimeError):
    """Fixed message and reason code only; never response bodies or values."""

    def __init__(self, reason_code: str) -> None:
        super().__init__("PII manifest could not be stored")
        self.reason_code = reason_code


def is_local_url(url: str) -> bool:
    return urlsplit(url).hostname in LOCAL_HOSTS


def _key_id(encrypted_manifest: bytes) -> str:
    envelope = json.loads(encrypted_manifest)
    protected = envelope["protected"]
    header = json.loads(
        base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4))
    )
    kid = header.get("kid")
    return kid if isinstance(kid, str) and kid else "unspecified"


class PostgrestManifestStore:
    """Insert-only writer for the api.pii_manifests table."""

    def __init__(
        self,
        base_url: str,
        token: SecretStr,
        *,
        table: str = "pii_manifests",
        timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = f"{base_url.rstrip('/')}/{table}"
        self._headers = {
            "Authorization": f"Bearer {token.get_secret_value()}",
            "Prefer": "return=minimal",
        }
        self._client = httpx.AsyncClient(
            timeout=timeout_seconds, transport=transport, follow_redirects=False
        )

    async def put(self, package: PreparedDelivery) -> None:
        if not package.encrypted_manifest or not package.metadata:
            raise ManifestStoreError("missing_parts")
        record = {
            "delivery_id": str(package.delivery_id),
            "document_id": str(package.document_id),
            "kid": _key_id(package.encrypted_manifest),
            "manifest_jwe": package.encrypted_manifest.decode("utf-8"),
            "metadata": package.metadata.decode("utf-8"),
            "redacted_md_sha256": package.redacted_md_sha256,
        }
        try:
            response = await self._client.post(
                self._url, json=record, headers=self._headers
            )
        except httpx.HTTPError:
            raise ManifestStoreError("store_unreachable") from None
        if response.status_code == 409:
            raise ManifestStoreError("duplicate_delivery")
        if response.status_code != 201:
            raise ManifestStoreError(f"http_{response.status_code}")

    async def aclose(self) -> None:
        await self._client.aclose()
