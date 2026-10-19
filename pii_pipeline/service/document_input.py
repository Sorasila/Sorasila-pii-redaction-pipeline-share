"""Accept one raw UTF-8 page: media type, encoding and size limits."""

import re

from starlette.requests import ClientDisconnect, Request

MAX_SOURCE_CHARACTERS = 2000
MAX_SOURCE_BYTES = MAX_SOURCE_CHARACTERS * 4


class InputRejected(Exception):
    """The request is refused before processing; status and fixed code only."""

    def __init__(self, status_code: int, code: str) -> None:
        super().__init__("Document request is invalid")
        self.status_code = status_code
        self.code = code


def _validate_request_headers(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    parameters = content_type.split(";")
    if parameters[0].strip().lower() not in {"text/plain", "text/markdown"}:
        raise InputRejected(415, "unsupported_media_type")
    if len(parameters) > 2:
        raise InputRejected(415, "unsupported_media_type")
    if (
        len(parameters) == 2
        and re.fullmatch(
            r'\s*charset\s*=\s*(?:utf-8|utf8|"utf-8"|"utf8")\s*',
            parameters[1],
            flags=re.IGNORECASE,
        )
        is None
    ):
        raise InputRejected(415, "unsupported_media_type")
    if (
        request.headers.get("content-encoding", "identity").strip().lower()
        != "identity"
    ):
        raise InputRejected(415, "unsupported_media_type")
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        if re.fullmatch(r"[0-9]+", declared_length) is None:
            raise InputRejected(400, "invalid_request")
        # Comparing the canonical decimal text avoids converting an unbounded
        # attacker-controlled integer. The actual stream remains independently bounded.
        canonical_length = declared_length.lstrip("0") or "0"
        limit = str(MAX_SOURCE_BYTES)
        if len(canonical_length) > len(limit) or (
            len(canonical_length) == len(limit) and canonical_length > limit
        ):
            raise InputRejected(413, "document_too_large")


async def read_document(request: Request) -> str:
    """The page text, or InputRejected (400, 413 or 415)."""
    _validate_request_headers(request)
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_SOURCE_BYTES:
                raise InputRejected(413, "document_too_large")
            chunks.append(chunk)
    except ClientDisconnect:
        raise InputRejected(400, "invalid_request") from None
    try:
        markdown = b"".join(chunks).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise InputRejected(400, "invalid_request") from None
    # Count source Unicode codepoints before the core's required NFC normalization.
    if len(markdown) > MAX_SOURCE_CHARACTERS:
        raise InputRejected(413, "document_too_large")
    if not markdown.strip():
        raise InputRejected(400, "invalid_request")
    return markdown
