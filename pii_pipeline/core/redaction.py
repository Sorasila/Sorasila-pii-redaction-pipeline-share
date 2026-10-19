import re

from .models import PiiEntry, PiiMatch, RedactionResult

_PII_TYPE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*")
_PLACEHOLDER_PATTERN = re.compile(r"\[PII_[A-Z][A-Z0-9_]*_[1-9][0-9]*\]")
_RESERVED_PLACEHOLDER_PATTERN = re.compile(
    r"\[PII_[A-Z][A-Z0-9_]*_[0-9]+\]",
    re.IGNORECASE,
)


class RedactionError(ValueError):
    pass


def normalize_pii_type(pii_type: str) -> str:
    if not isinstance(pii_type, str):
        raise RedactionError("Invalid PII type")

    cleaned = pii_type.strip().upper()

    if _PII_TYPE_PATTERN.fullmatch(cleaned) is None:
        raise RedactionError("Invalid PII type")

    return cleaned


def _match_fields_are_valid(match: object) -> bool:
    if not isinstance(match, PiiMatch):
        return False

    try:
        normalize_pii_type(match.pii_type)
    except ValueError:
        return False

    if not isinstance(match.value, str) or not match.value.strip():
        return False

    if type(match.start) is not int or type(match.end) is not int:
        return False

    return 0 <= match.start < match.end


def is_exact_match(markdown: str, match: PiiMatch) -> bool:
    if not isinstance(markdown, str) or not _match_fields_are_valid(match):
        return False

    if match.end > len(markdown):
        return False

    return markdown[match.start : match.end] == match.value


def validate_redaction_source(markdown: str) -> None:
    """Reject invalid input and reserved placeholders before external processing."""

    if not isinstance(markdown, str):
        raise RedactionError("Invalid Markdown")

    if _RESERVED_PLACEHOLDER_PATTERN.search(markdown) is not None:
        raise RedactionError("PII placeholder already exists in source document")


def _validate_placeholder(placeholder: object) -> None:
    if (
        not isinstance(placeholder, str)
        or _PLACEHOLDER_PATTERN.fullmatch(placeholder) is None
    ):
        raise RedactionError("Invalid PII placeholder")


def redact_many(markdown: str, replacements: list[tuple[PiiMatch, str]]) -> str:
    validate_redaction_source(markdown)

    if not isinstance(replacements, list):
        raise RedactionError("Invalid PII replacements")

    validated_replacements: list[tuple[PiiMatch, str]] = []
    seen_placeholders: set[str] = set()

    for replacement in replacements:
        if not isinstance(replacement, tuple) or len(replacement) != 2:
            raise RedactionError("Invalid PII replacements")

        match, placeholder = replacement

        if not is_exact_match(markdown, match):
            raise RedactionError("PII match does not match source document")

        _validate_placeholder(placeholder)

        if placeholder in seen_placeholders:
            raise RedactionError("Duplicate PII placeholder")

        seen_placeholders.add(placeholder)
        validated_replacements.append((match, placeholder))

    ordered_replacements = sorted(
        validated_replacements,
        key=lambda item: (
            item[0].start,
            item[0].end,
            normalize_pii_type(item[0].pii_type),
            item[0].value,
            item[1],
        ),
    )

    parts: list[str] = []
    cursor = 0

    for match, placeholder in ordered_replacements:
        if match.start < cursor:
            raise RedactionError("PII match overlapped")

        parts.append(markdown[cursor : match.start])
        parts.append(placeholder)
        cursor = match.end

    parts.append(markdown[cursor:])

    return "".join(parts)


def build_replacements_and_entries(
    matches: list[PiiMatch],
) -> tuple[list[tuple[PiiMatch, str]], list[PiiEntry]]:
    if not isinstance(matches, list):
        raise RedactionError("Invalid PII matches")

    prepared_matches: list[tuple[PiiMatch, str]] = []

    for match in matches:
        if not _match_fields_are_valid(match):
            raise RedactionError("Invalid PII match")

        prepared_matches.append((match, normalize_pii_type(match.pii_type)))

    ordered_matches = sorted(
        prepared_matches,
        key=lambda item: (
            item[0].start,
            item[0].end,
            item[1],
            item[0].value,
            item[0].pii_type,
        ),
    )

    counts: dict[str, int] = {}
    seen_matches: set[tuple[str, str, int, int]] = set()
    entries: list[PiiEntry] = []
    replacements: list[tuple[PiiMatch, str]] = []
    cursor = 0

    for match, pii_type in ordered_matches:
        match_key = (
            pii_type,
            match.value,
            match.start,
            match.end,
        )

        if match_key in seen_matches:
            continue

        if match.start < cursor:
            raise RedactionError("PII match overlapped")

        seen_matches.add(match_key)
        cursor = match.end

        counts[pii_type] = counts.get(pii_type, 0) + 1
        occurrence_index = counts[pii_type]
        placeholder = f"[PII_{pii_type}_{occurrence_index}]"

        replacements.append((match, placeholder))
        entries.append(
            PiiEntry(
                placeholder=placeholder,
                pii_type=pii_type,
                occurrence_index=occurrence_index,
                original_value=match.value,
            )
        )

    return replacements, entries


def redact(markdown: str, matches: list[PiiMatch]) -> RedactionResult:
    validate_redaction_source(markdown)
    replacements, entries = build_replacements_and_entries(matches)
    redacted_markdown = redact_many(markdown, replacements)

    return RedactionResult(
        redacted_markdown=redacted_markdown,
        entries=tuple(entries),
    )
