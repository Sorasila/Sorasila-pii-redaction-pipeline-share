"""Username and password login for the Swagger page: short-lived Bearer tokens.

Active only with the docs page (PII_SERVICE_ENABLE_DOCS) and both
PII_SERVICE_DOCS_USERNAME and PII_SERVICE_DOCS_PASSWORD. A token is
``docs.<expiry>.<signature>``: an HMAC-SHA256 over the expiry time with a key
derived from PII_SERVICE_API_TOKEN. Tokens therefore survive restarts, work on
every replica and all stop working when the API token changes. The API token
itself is never returned.
"""

import hashlib
import hmac
import time
from collections.abc import Callable

from pydantic import SecretStr

_PREFIX = "docs"
_KEY_LABEL = b"pii-redaction docs login v1"


class DocsLogin:
    def __init__(
        self,
        username: str,
        password: SecretStr,
        api_token: SecretStr,
        *,
        ttl_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._username = username.encode("utf-8")
        self._password = password.get_secret_value().encode("utf-8")
        self._key = hmac.new(
            api_token.get_secret_value().encode("utf-8"), _KEY_LABEL, hashlib.sha256
        ).digest()
        self.ttl_seconds = ttl_seconds
        self._clock = clock

    def check(self, username: str, password: str) -> bool:
        """Constant-time comparison of both values; both must match."""
        user_ok = hmac.compare_digest(username.encode("utf-8"), self._username)
        password_ok = hmac.compare_digest(password.encode("utf-8"), self._password)
        return user_ok and password_ok

    def _signature(self, expiry: str) -> str:
        message = f"{_PREFIX}.{expiry}".encode("ascii")
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def issue(self) -> str:
        expiry = str(int(self._clock()) + self.ttl_seconds)
        return f"{_PREFIX}.{expiry}.{self._signature(expiry)}"

    def valid(self, token: str) -> bool:
        parts = token.split(".")
        if (
            len(parts) != 3
            or parts[0] != _PREFIX
            or not (parts[1].isascii() and parts[1].isdigit())
        ):
            return False
        if not hmac.compare_digest(parts[2], self._signature(parts[1])):
            return False
        return int(parts[1]) > self._clock()
