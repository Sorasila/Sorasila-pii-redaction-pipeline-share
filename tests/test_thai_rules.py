import pytest

from pii_pipeline.core.detection import DetectionError, normalize_unicode, run_detectors
from pii_pipeline.core.models import PiiMatch
from pii_pipeline.core.redaction import redact
from pii_pipeline.core.verification import make_detection_checker
from pii_pipeline.rules.thai import (
    detect_thai_labeled_identifiers,
    detect_thai_labeled_numbers,
    detect_thai_rule_pii,
)


@pytest.mark.parametrize(
    "label,pii_type,value",
    [
        ("คดีหมายเลขดำที่", "CASE_NUMBER", "1/2569"),
        ("คดีหมายเลขแดงที่", "CASE_NUMBER", "123456789012345/2569"),
        ("คดีหมายเลขดำที่", "CASE_NUMBER", "๑๒๓/๒๕๖๙"),
        ("โฉนดเลขที่", "TITLE_DEED_NUMBER", "9"),
        ("ที่ดินโฉนดเลขที่", "TITLE_DEED_NUMBER", "123456789012345"),
        ("โฉนดที่ดินเลขที่", "TITLE_DEED_NUMBER", "98765"),
        ("โฉนดที่ดิน เลขที่", "TITLE_DEED_NUMBER", "98765"),
        ("โฉนดที่ดิน   เลขที่", "TITLE_DEED_NUMBER", "๙๘๗๖๕"),
        ("เลขที่ดิน", "LAND_PARCEL_NUMBER", "9"),
        ("เลขที่ดิน", "LAND_PARCEL_NUMBER", "123456789012345"),
    ],
)
@pytest.mark.parametrize("separator", [" ", "   ", "\t", "\n", ": "])
def test_numeric_rules_preserve_exact_labels_and_whitespace(
    label: str, pii_type: str, value: str, separator: str
) -> None:
    prefix = f"{label}{separator}"
    source = normalize_unicode(f"{prefix}{value}")
    matches = detect_thai_labeled_numbers(source)
    assert matches == [PiiMatch(pii_type, value, len(prefix), len(source))]
    result = redact(source, matches)
    assert result.redacted_markdown == f"{prefix}[PII_{pii_type}_1]"


@pytest.mark.parametrize(
    "source",
    [
        "คดีหมายเลขดำที่ 1/256",
        "คดีหมายเลขดำที่ 1/25690",
        "คดีหมายเลขแดงที่ 123/25690",
        "คดีหมายเลขดำที่ 1/2569/3",
        "คดีหมายเลขดำที่ 1/2569.5",
        "คดีหมายเลขดำที่ 1/2569A",
        "คดีหมายเลขดำที่1/2569",
        "คดีหมายเลขแดงที่ x/2569",
        "โฉนดเลขที่12345",
        "โฉนดที่ดินเลขที่ 123/456",
        "เลขที่ดิน 123.45",
        "เลขที่ดิน 123-45",
        "เลขที่ดิน 123A",
        "เลขที่ดิน12345",
        "หน้าสำรวจ 12345 ระวาง 67890",
        "วันที่ออกเอกสาร 1/2569",
        "บ้านเลขที่ 12345",
        "โทรศัพท์ 0812345678",
        "12345 98765 1/2569",
        "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1]",
        "โฉนดเลขที่ [PII_TITLE_DEED_NUMBER_1]",
        "เลขที่ดิน [PII_LAND_PARCEL_NUMBER_1]",
    ],
)
def test_numeric_rules_do_not_redact_partial_or_unrelated_numbers(source: str) -> None:
    assert detect_thai_labeled_numbers(source) == []


@pytest.mark.parametrize("suffix", [".", ",", ")", " | หมายเหตุ"])
def test_numeric_rules_allow_sentence_punctuation_and_field_boundaries(
    suffix: str,
) -> None:
    source = f"คดีหมายเลขดำที่ 1/2569{suffix}"
    result = redact(source, detect_thai_labeled_numbers(source))
    assert result.redacted_markdown == f"คดีหมายเลขดำที่ [PII_CASE_NUMBER_1]{suffix}"


def test_numeric_rules_sort_repeated_values_and_keep_type_identity() -> None:
    source = (
        "เลขที่ดิน 123\nโฉนดที่ดิน เลขที่ 123\nคดีหมายเลขแดงที่ 123/2569\n"
        "คดีหมายเลขดำที่ 1/2569\nเลขที่ดิน 123"
    )
    normalized, matches = run_detectors(source, [detect_thai_labeled_numbers])
    assert [(match.pii_type, match.value) for match in matches] == [
        ("LAND_PARCEL_NUMBER", "123"),
        ("TITLE_DEED_NUMBER", "123"),
        ("CASE_NUMBER", "123/2569"),
        ("CASE_NUMBER", "1/2569"),
        ("LAND_PARCEL_NUMBER", "123"),
    ]
    assert redact(normalized, matches).redacted_markdown == (
        "เลขที่ดิน [PII_LAND_PARCEL_NUMBER_1]\n"
        "โฉนดที่ดิน เลขที่ [PII_TITLE_DEED_NUMBER_1]\n"
        "คดีหมายเลขแดงที่ [PII_CASE_NUMBER_1]\n"
        "คดีหมายเลขดำที่ [PII_CASE_NUMBER_2]\n"
        "เลขที่ดิน [PII_LAND_PARCEL_NUMBER_2]"
    )


@pytest.mark.parametrize("source", [None, 123, "Cafe\u0301"])
def test_numeric_rules_reject_invalid_or_non_nfc_source(source: object) -> None:
    with pytest.raises(DetectionError, match="PII source document is invalid"):
        detect_thai_labeled_numbers(source)


def _found(source: str) -> list[tuple[str, str]]:
    matches = detect_thai_labeled_identifiers(source)
    for match in matches:
        assert source[match.start : match.end] == match.value
    return [(match.pii_type, match.value) for match in matches]


@pytest.mark.parametrize(
    "source,expected",
    [
        ("เลขประจำตัวประชาชน 1234567890123 อายุ 45 ปี", [("ID_NUMBER", "1234567890123")]),
        (
            "เลขบัตรประจำตัวประชาชน: 1-2345-67890-12-3",
            [("ID_NUMBER", "1-2345-67890-12-3")],
        ),
        (
            "บัตรประจำตัวประชาชนเลขที่ 1 2345 67890 12 3 ออกให้",
            [("ID_NUMBER", "1 2345 67890 12 3")],
        ),
        ("เลขประจำตัวประชาชน ๑๒๓๔๕๖๗๘๙๐๑๒๓.", [("ID_NUMBER", "๑๒๓๔๕๖๗๘๙๐๑๒๓")]),
        ("โทรศัพท์มือถือ 0812345678 และ 3 คน", [("PHONE", "0812345678")]),
        ("Tel. +66 81 234 5678", [("PHONE", "+66 81 234 5678")]),
        ("โทรสาร 02-123-4568", [("FAX", "02-123-4568")]),
        ("ติดต่อ somchai.test@example.co.th.", [("EMAIL", "somchai.test@example.co.th")]),
        ("เลขที่บัญชี 123-4-56789-0 ธนาคาร", [("BANK_ACCOUNT_NUMBER", "123-4-56789-0")]),
        ("บัญชีเลขที่ 123 4 56789 0", [("BANK_ACCOUNT_NUMBER", "123 4 56789 0")]),
        ("หนังสือเดินทางเลขที่ AA1234567", [("PASSPORT_NUMBER", "AA1234567")]),
        ("Passport No. A12345678 expiry", [("PASSPORT_NUMBER", "A12345678")]),
    ],
)
def test_labelled_identifiers_keep_labels_and_return_exact_values(source, expected):
    assert _found(source) == expected


def test_phone_label_covers_listed_numbers_only_while_they_continue():
    assert _found("โทร. 02-123-4567, 081-234-5678 หรือ 053 123 456 ต่อ") == [
        ("PHONE", "02-123-4567"),
        ("PHONE", "081-234-5678"),
        ("PHONE", "053 123 456"),
    ]
    # A field change stops the list; the next label decides its own type.
    assert _found("โทร 02-111-1111 / โทรสาร 02-222-2222") == [
        ("PHONE", "02-111-1111"),
        ("FAX", "02-222-2222"),
    ]


@pytest.mark.parametrize(
    "source",
    [
        "ประชาชน 1234567890123",  # incomplete label
        "1234567890123",  # unlabelled number stays with the semantic lane
        "โทรศัพท์ 3 เครื่อง",  # not a phone-number shape
        "โทรศัพท์ของจำเลย",  # label without a value
        "เลขประจำตัวประชาชน 1234567890123อายุ",  # value runs into a word
        "หนังสือเดินทาง 3 เล่ม",
        "อีเมล ไม่มี@",
        "คดีหมายเลขดำที่ 123/2569",
    ],
)
def test_identifier_rules_skip_unlabelled_or_malformed_values(source):
    assert _found(source) == []


def test_combined_rules_redact_and_rule_verification_sees_no_residual():
    source = (
        "คดีหมายเลขดำที่ 123/2569 เลขประจำตัวประชาชน 1234567890123 "
        "โทร 081-234-5678 อีเมล a.b@example.com"
    )
    matches = detect_thai_rule_pii(source)
    assert [match.pii_type for match in matches] == [
        "CASE_NUMBER",
        "ID_NUMBER",
        "PHONE",
        "EMAIL",
    ]
    redacted = redact(source, matches).redacted_markdown
    assert redacted == (
        "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1] เลขประจำตัวประชาชน [PII_ID_NUMBER_1] "
        "โทร [PII_PHONE_1] อีเมล [PII_EMAIL_1]"
    )
    checker = make_detection_checker([detect_thai_rule_pii])
    assert checker(source) is True
    assert checker(redacted) is False


@pytest.mark.parametrize("source", [None, 123, "Café"])
def test_identifier_rules_reject_invalid_or_non_nfc_source(source):
    with pytest.raises(DetectionError):
        detect_thai_labeled_identifiers(source)


@pytest.mark.parametrize(
    "source,value",
    [
        ("คดีหมายเลขแดงที่ ก/2569", "ก/2569"),
        ("คดีหมายเลขแดงที่ ผบ/2569 ตัดสินแล้ว", "ผบ/2569"),
        ("คดีหมายเลขดำที่ ฟ/๒๕๖๙", "ฟ/๒๕๖๙"),
    ],
)
def test_case_numbers_with_thai_letter_numbers_keep_label(source, value):
    matches = detect_thai_labeled_numbers(source)
    assert [(m.pii_type, m.value) for m in matches] == [("CASE_NUMBER", value)]
    assert redact(source, matches).redacted_markdown.startswith(
        source.split(value)[0] + "[PII_CASE_NUMBER_1]"
    )


@pytest.mark.parametrize(
    "source",
    [
        "คดีหมายเลขแดงที่ ก/256",  # year must have four digits
        "คดีหมายเลขแดงที่ ก/25690",
        "คดีหมายเลขแดงที่ ก.1/2569",  # dot/digit mix is not the approved form
        "คดีหมายเลขแดงที่ x/2569",  # Latin letters stay out of scope
        "คดีหมายเลขแดงที่ ก",
    ],
)
def test_case_number_letter_form_rejects_partial_or_other_shapes(source):
    assert detect_thai_labeled_numbers(source) == []


@pytest.mark.parametrize(
    "source,value",
    [
        ("หนังสือที่ กข 1234.56.7/8901 ลงวันที่ 1 มกราคม 2569", "กข 1234.56.7/8901"),
        ("ตามหนังสือ ที่ กข 1234.56.7/8901", "กข 1234.56.7/8901"),
        ("หนังสือที่\n\nกขค 1234.56.7/890\n\n---", "กขค 1234.56.7/890"),
        ("หนังสือที่ กข 1234.5/67890 ลงวันที่", "กข 1234.5/67890"),
        ("หนังสือที่ กข 1234/5678 ลงวันที่", "กข 1234/5678"),
        ("หนังสือที่: กข1234/5678", "กข1234/5678"),
        ("หนังสือที่ ก.ข. 1234/5678", "ก.ข. 1234/5678"),
        ("หนังสือที่ กข ๑๒๓๔.๕/๖๗๘๙", "กข ๑๒๓๔.๕/๖๗๘๙"),
        # OCR forms seen in real documents: trailing period, dash, spaces.
        ("หนังสือที่ กขค. 1- 234/ 5678 ลงวันที่", "กขค. 1- 234/ 5678"),
    ],
)
def test_official_letter_numbers_keep_label(source, value):
    matches = detect_thai_labeled_numbers(source)
    assert [(m.pii_type, m.value) for m in matches] == [
        ("OFFICIAL_LETTER_NUMBER", value)
    ]
    assert source[matches[0].start : matches[0].end] == value
    redacted = redact(source, matches).redacted_markdown
    assert redacted == source.replace(value, "[PII_OFFICIAL_LETTER_NUMBER_1]")
    checker = make_detection_checker([detect_thai_rule_pii])
    assert checker(redacted) is False


@pytest.mark.parametrize(
    "source",
    [
        "หนังสือที่ส่งมา 12/2569",  # no separator after the label
        "หนังสือที่ กข 1234.56.7",  # no running number
        "หนังสือที่ กข 1234/5678.9",  # prefix of a longer token
        "หนังสือที่ กข 1234/5678ก",
        "หนังสือที่ 1234/5678",  # no agency letters
        "หนังสือที่ กข 1234.56.7/ว 123",  # circular form is left to the LLM
        "ที่ กข 1234/5678",  # the label needs 'หนังสือ'
        "หนังสือเดินทาง เลขที่ กข 1234/5678",
    ],
)
def test_official_letter_number_rejects_partial_or_unlabelled_shapes(source):
    assert detect_thai_labeled_numbers(source) == []


def test_official_letter_number_and_passport_labels_do_not_collide():
    source = "หนังสือเดินทางเลขที่ AA1234567 หนังสือที่ กข 1234/5678"
    assert [(m.pii_type, m.value) for m in detect_thai_rule_pii(source)] == [
        ("PASSPORT_NUMBER", "AA1234567"),
        ("OFFICIAL_LETTER_NUMBER", "กข 1234/5678"),
    ]


@pytest.mark.parametrize(
    "source,value",
    [
        ("ที่ดินตาม น.ส. 3 ก. เลขที่ 123 ตำบลทดสอบ", "123"),
        ("น.ส. 3 ก.\nเลขที่ 456", "456"),
        ("น.ส.3ก. เลขที่ 789", "789"),
        ("นส.3 เลขที่ ๑๒๓", "๑๒๓"),
        ("น.ส. ๓ ก. เลขที่: 99", "99"),
    ],
)
def test_land_use_certificate_numbers_are_title_deed_numbers(source, value):
    # Approved 2026-10-12: "น.ส. 3 ก." numbers leaked when only the LLM saw them.
    matches = detect_thai_labeled_numbers(source)
    assert [(m.pii_type, m.value) for m in matches] == [("TITLE_DEED_NUMBER", value)]
    redacted = redact(source, matches).redacted_markdown
    assert redacted == source.replace(value, "[PII_TITLE_DEED_NUMBER_1]")


@pytest.mark.parametrize(
    "source",
    [
        "น.ส. สมใจ เลขที่ 12",  # "น.ส." as the honorific for a woman
        "น.ส. 3 ก. 123",  # no 'เลขที่'
        "น.ส. 3 ก. เลขที่ 12/3",  # prefix of a longer token
    ],
)
def test_land_use_certificate_rule_needs_its_full_label(source):
    assert detect_thai_labeled_numbers(source) == []


# Approved 2026-10-15: a labelled land number followed by its location is one
# ADDRESS (label kept); without a location of 2+ levels the number stays.
@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "ที่ดินโฉนดเลขที่ 1234 ตำบลบางพลี อำเภอบางพลี จังหวัดสมุทรปราการ ต่อมา",
            ("ADDRESS", "1234 ตำบลบางพลี อำเภอบางพลี จังหวัดสมุทรปราการ"),
        ),
        (
            "น.ส. 3 ก. เลขที่ 55 ต.บางพลี อ.บางพลี จ.สมุทรปราการ",
            ("ADDRESS", "55 ต.บางพลี อ.บางพลี จ.สมุทรปราการ"),
        ),
        (
            "เลขที่ดิน 77\r\n    ตำบลบางพลี\r\n    อำเภอบางพลี (แปลงที่ 2)",
            ("ADDRESS", "77\r\n    ตำบลบางพลี\r\n    อำเภอบางพลี"),
        ),
        (
            "| โฉนดเลขที่ 1234 ตำบลบางพลี อำเภอบางพลี | ผู้ถือ |",
            ("ADDRESS", "1234 ตำบลบางพลี อำเภอบางพลี"),
        ),
        # One level only, or a blank line between: the number alone.
        ("โฉนดเลขที่ 1234 ตำบลบางพลี ต่อมา", ("TITLE_DEED_NUMBER", "1234")),
        (
            "โฉนดเลขที่ 1234\n\nตำบลบางพลี อำเภอบางพลี",
            ("TITLE_DEED_NUMBER", "1234"),
        ),
        ("โฉนดเลขที่ 1234 ของผู้ร้อง", ("TITLE_DEED_NUMBER", "1234")),
    ],
)
def test_land_number_with_location_is_one_address(text, expected):
    (match,) = detect_thai_labeled_numbers(text)
    assert (match.pii_type, match.value) == expected
    assert text[match.start : match.end] == match.value
