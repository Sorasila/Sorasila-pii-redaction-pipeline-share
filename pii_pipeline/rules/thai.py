"""Opt-in detectors for approved, explicitly labelled Thai fields and emails."""

import re

from ..core.detection import DetectionError, normalize_unicode
from ..core.models import PiiMatch

_DIGITS = r"[0-9๐-๙]"
# Keep optional colons for existing field fixtures; never consume labels as PII.
_SEPARATOR = r"(?:\s*[:：]\s*|\s+)"
_TOKEN_END = rf"(?![\w/]|[.-]{_DIGITS})"
# A case number is digits or Thai letters (approved 2026-10-06), then the year.
_THAI_LETTERS = r"[ก-ฮ][ก-ฺเ-๎]*"
_CASE_NUMBER = rf"(?:{_DIGITS}+|{_THAI_LETTERS})/{_DIGITS}{{4}}"
# Official letter number (approved 2026-10-06): agency letters, digit groups
# joined by periods, '/', running number. Tolerates the OCR forms seen so far:
# dotted letters, a trailing period, a dash, one space inside the number or
# around '/'.
_AGENCY_LETTERS = r"[ก-ฮ](?:[ก-ฺเ-๎]|\.(?=[ก-ฮ]))*\.?"
_LETTER_NUMBER = (
    rf"{_AGENCY_LETTERS}[ \t]*{_DIGITS}+(?:[.-][ \t]?{_DIGITS}+)*"
    rf"[ \t]?/[ \t]?{_DIGITS}+"
)
# Land-use certificate (approved 2026-10-12 as TITLE_DEED_NUMBER): "น.ส. 3 ก."
# with OCR-variable periods, spaces or line breaks, Arabic or Thai 3.
_NS3_LABEL = r"น\.?\s*ส\.?\s*[3๓]\s*(?:ก\.?)?\s*เลขที่"
_RULES = (
    (
        "CASE_NUMBER",
        re.compile(
            rf"คดีหมายเลข(?:ดำ|แดง)ที่{_SEPARATOR}"
            rf"(?P<value>{_CASE_NUMBER}){_TOKEN_END}"
        ),
    ),
    (
        "TITLE_DEED_NUMBER",
        re.compile(
            rf"(?:ที่ดินโฉนดเลขที่|โฉนดเลขที่|โฉนดที่ดิน\s*เลขที่|{_NS3_LABEL})"
            rf"{_SEPARATOR}(?P<value>{_DIGITS}+){_TOKEN_END}"
        ),
    ),
    (
        "LAND_PARCEL_NUMBER",
        re.compile(rf"เลขที่ดิน{_SEPARATOR}(?P<value>{_DIGITS}+){_TOKEN_END}"),
    ),
    (
        "OFFICIAL_LETTER_NUMBER",
        re.compile(rf"หนังสือ\s*ที่{_SEPARATOR}(?P<value>{_LETTER_NUMBER}){_TOKEN_END}"),
    ),
)


# Labelled identifiers approved 2026-10-05. Numbers always need a label; the
# label and separator stay outside the value. EMAIL needs no label.
_ID_VALUE = (
    rf"(?:{_DIGITS}\s{_DIGITS}{{4}}\s{_DIGITS}{{5}}\s{_DIGITS}{{2}}\s{_DIGITS}"
    rf"|{_DIGITS}+(?:-{_DIGITS}+)*)"
)
_PHONE_VALUE = (
    rf"(?:\+{_DIGITS}{{2}}[-\s]?{_DIGITS}{{1,2}}[-\s]?{_DIGITS}{{3}}[-\s]?"
    rf"{_DIGITS}{{3,4}}"
    rf"|{_DIGITS}{{3}}[-\s]?{_DIGITS}{{3}}[-\s]?{_DIGITS}{{4}}"
    rf"|{_DIGITS}{{2}}[-\s]?{_DIGITS}{{3}}[-\s]?{_DIGITS}{{4}}"
    rf"|{_DIGITS}{{3}}[-\s]?{_DIGITS}{{3}}[-\s]?{_DIGITS}{{3}}"
    rf"|{_DIGITS}-{_DIGITS}{{4}}-{_DIGITS}{{4}})"
)
_ACCOUNT_VALUE = (
    rf"(?:{_DIGITS}{{3}}\s{_DIGITS}\s{_DIGITS}{{5}}\s{_DIGITS}"
    rf"|{_DIGITS}+(?:-{_DIGITS}+)*)"
)
_PASSPORT_VALUE = rf"[A-Za-z]{{0,3}}{_DIGITS}{{5,10}}"
_PHONE_LABEL = (
    r"(?:หมายเลขโทรศัพท์|เบอร์โทรศัพท์|โทรศัพท์มือถือ|โทรศัพท์|เบอร์โทร|มือถือ"
    r"|โทร\.?|Tel\.?|Mobile)"
)
_FAX_LABEL = r"(?:หมายเลขโทรสาร|โทรสาร|แฟ็กซ์|แฟกซ์|Fax\.?)"
_PHONE_PATTERN = re.compile(rf"(?P<value>{_PHONE_VALUE}){_TOKEN_END}")
# Further numbers listed after one phone/fax label belong to the same field.
_CONTINUATION = re.compile(r"\s*(?:,|/|หรือ|และ)\s*")
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])(?P<value>[A-Za-z0-9._%+-]+@[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
    r"\.[A-Za-z]{2,})(?![A-Za-z0-9-]|\.[A-Za-z0-9])"
)
_IDENTIFIER_RULES = (
    (
        "ID_NUMBER",
        re.compile(
            r"(?:เลขบัตรประจำตัวประชาชน|เลขประจำตัวประชาชน|บัตรประจำตัวประชาชน\s*เลขที่"
            r"|บัตรประชาชน\s*เลขที่|เลขบัตรประชาชน)"
            rf"{_SEPARATOR}(?P<value>{_ID_VALUE}){_TOKEN_END}"
        ),
        None,
    ),
    (
        "PHONE",
        re.compile(rf"{_PHONE_LABEL}{_SEPARATOR}(?P<value>{_PHONE_VALUE}){_TOKEN_END}"),
        _PHONE_PATTERN,
    ),
    (
        "FAX",
        re.compile(rf"{_FAX_LABEL}{_SEPARATOR}(?P<value>{_PHONE_VALUE}){_TOKEN_END}"),
        _PHONE_PATTERN,
    ),
    (
        "BANK_ACCOUNT_NUMBER",
        re.compile(
            r"(?:บัญชีเงินฝากเลขที่|บัญชีออมทรัพย์เลขที่|บัญชีกระแสรายวันเลขที่"
            r"|เลขที่บัญชี|บัญชีเลขที่|หมายเลขบัญชี|เลขบัญชี)"
            rf"{_SEPARATOR}(?P<value>{_ACCOUNT_VALUE}){_TOKEN_END}"
        ),
        None,
    ),
    (
        "PASSPORT_NUMBER",
        re.compile(
            r"(?:หนังสือเดินทาง\s*เลขที่|เลขที่หนังสือเดินทาง|หมายเลขหนังสือเดินทาง"
            r"|Passport\s*No\.?)"
            rf"{_SEPARATOR}(?P<value>{_PASSPORT_VALUE})(?![\w/])"
        ),
        None,
    ),
    ("EMAIL", _EMAIL, None),
)


def _require_nfc_source(normalized_markdown: object) -> None:
    if (
        not isinstance(normalized_markdown, str)
        or normalize_unicode(normalized_markdown) != normalized_markdown
    ):
        raise DetectionError("PII source document is invalid")


def _sorted(matches: list[PiiMatch]) -> list[PiiMatch]:
    return sorted(matches, key=lambda match: (match.start, match.end, match.pii_type))


# Approved 2026-10-15: a labelled land number followed by the location of the
# land (at least two levels such as ตำบล/อำเภอ, abbreviations allowed, at most
# one line break between parts) is one ADDRESS from the number through the
# last level; the label stays. Without such a location the number keeps its type.
_LOCALITY_WORD = r"(?:ตำบล|ต\.|แขวง|อำเภอ|อ\.|เขต|จังหวัด|จ\.|หมู่ที่|ม\.)"
_LOCALITY_NAME = rf"(?:(?!{_LOCALITY_WORD})[^\s,;:()\[\]|])+"
_LOCALITY_GAP = r"[ \t]*(?:\r?\n[ \t]*)?"
_LAND_LOCATION = re.compile(
    rf"{_LOCALITY_GAP}(?P<location>{_LOCALITY_WORD}\s*{_LOCALITY_NAME}"
    rf"(?:{_LOCALITY_GAP}{_LOCALITY_WORD}\s*{_LOCALITY_NAME}){{1,6}})"
)
_LAND_NUMBER_TYPES = frozenset({"TITLE_DEED_NUMBER", "LAND_PARCEL_NUMBER"})


def _with_land_location(text: str, pii_type: str, start: int, end: int) -> PiiMatch:
    location = (
        _LAND_LOCATION.match(text, end) if pii_type in _LAND_NUMBER_TYPES else None
    )
    if location is None:
        return PiiMatch(pii_type, text[start:end], start, end)
    stop = location.end("location")
    return PiiMatch("ADDRESS", text[start:stop], start, stop)


def detect_thai_labeled_numbers(normalized_markdown: str) -> list[PiiMatch]:
    """Return exact numeric spans; names and addresses need semantic detection.

    Supply this callable as a rule detector of the recovery pipeline. It does
    not enable a default production pipeline.
    """

    _require_nfc_source(normalized_markdown)
    matches = [
        _with_land_location(normalized_markdown, pii_type, *match.span("value"))
        for pii_type, pattern in _RULES
        for match in pattern.finditer(normalized_markdown)
    ]
    return _sorted(matches)


def detect_thai_labeled_identifiers(normalized_markdown: str) -> list[PiiMatch]:
    """Labelled ID/phone/fax/bank/passport values and unlabelled email addresses.

    Values are exact source spans; labels stay outside them. Unlabelled numbers
    remain the semantic lane's responsibility.
    """

    _require_nfc_source(normalized_markdown)
    matches: list[PiiMatch] = []
    for pii_type, pattern, continuation in _IDENTIFIER_RULES:
        for match in pattern.finditer(normalized_markdown):
            matches.append(PiiMatch(pii_type, match["value"], *match.span("value")))
            cursor = match.end("value")
            while continuation is not None:
                separator = _CONTINUATION.match(normalized_markdown, cursor)
                following = separator and continuation.match(
                    normalized_markdown, separator.end()
                )
                if not following:
                    break
                matches.append(
                    PiiMatch(pii_type, following["value"], *following.span("value"))
                )
                cursor = following.end("value")
    return _sorted(matches)


def detect_thai_rule_pii(normalized_markdown: str) -> list[PiiMatch]:
    """All approved rule-lane detectors: labelled numbers and identifiers."""

    return _sorted(
        [
            *detect_thai_labeled_numbers(normalized_markdown),
            *detect_thai_labeled_identifiers(normalized_markdown),
        ]
    )
