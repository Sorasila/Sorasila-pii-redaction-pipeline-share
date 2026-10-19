import traceback

import pytest

from pii_pipeline.core.models import PiiMatch
from pii_pipeline.core.pii_types import CANONICAL_PII_TYPES
from pii_pipeline.core.redaction import redact
from pii_pipeline.llm.response import (
    DetectionResponseError,
    VerificationFinding,
    VerificationResponse,
    VerificationResponseError,
    parse_detection_outcome,
    parse_detection_response,
    parse_verification_response,
)


def test_detection_unique_exact_values_sort_and_normalize_nfc():
    source = "Café met Alpha"
    matches = parse_detection_response(
        source,
        {
            "candidates": [
                {"pii_type": "name", "value": "Alpha"},
                {"pii_type": " name ", "value": "Cafe\u0301"},
            ]
        },
    )
    assert matches == [PiiMatch("NAME", "Café", 0, 4), PiiMatch("NAME", "Alpha", 9, 14)]


@pytest.mark.parametrize(
    "response,reason",
    [
        ({}, "invalid_response_shape"),
        ({"candidates": [], "private": "Alpha"}, "invalid_response_shape"),
        ({"candidates": None}, "candidates_not_list"),
        (
            {"candidates": [{"pii_type": "NAME", "value": "Alpha", "anchor": "Alpha"}]},
            "invalid_candidate_shape",
        ),
        (
            {"candidates": [{"pii_type": "NAME", "value": "Alpha", "start": 0}]},
            "invalid_candidate_shape",
        ),
        ({"candidates": [{"pii_type": "NAME", "value": ""}]}, "invalid_value"),
        (
            {"candidates": [{"pii_type": "UNKNOWN", "value": "Alpha"}]},
            "invalid_pii_type",
        ),
        ({"candidates": [{"pii_type": "NAME", "value": "ALPHA"}]}, "value_not_found"),
    ],
)
def test_detection_rejects_old_schema_bad_shapes_or_nonexact_values(response, reason):
    with pytest.raises(DetectionResponseError) as caught:
        parse_detection_response("Alpha", response)
    assert caught.value.reason_code == reason
    assert "Alpha" not in str(caught.value)
    assert "ALPHA" not in repr(caught.value.details)


def test_detection_error_details_allow_only_safe_copied_metadata():
    details = {
        "pii_type": "NAME",
        "value_length": 3,
        "value": "Alpha",
        "anchor": "Alpha",
    }
    error = DetectionResponseError("Invalid", details=details)
    details["pii_type"] = "Alpha"
    assert error.details == {"pii_type": "NAME", "value_length": 3}
    with pytest.raises(TypeError):
        error.details["pii_type"] = "Alpha"


def test_parse_verification_response_accepts_clean_result() -> None:
    result = parse_verification_response(
        "Name: [PII_NAME_1]",
        {"has_pii": False, "findings": []},
    )

    assert result == VerificationResponse(has_pii=False, findings=())


def test_parse_verification_response_derives_inspected_window_and_sorts_types() -> None:
    response = {
        "has_pii": True,
        "findings": [
            {"pii_type": "PHONE"},
            {"pii_type": " name "},
        ],
    }

    result = parse_verification_response("Alpha and 00000", response)

    assert result == VerificationResponse(
        has_pii=True,
        findings=(
            VerificationFinding("NAME", 0, 15, location_scope="window"),
            VerificationFinding("PHONE", 0, 15, location_scope="window"),
        ),
    )


@pytest.mark.parametrize(
    ("response", "reason_code"),
    [
        (None, "invalid_response_shape"),
        ({}, "invalid_response_shape"),
        (
            {"has_pii": False, "findings": [], "explanation": "extra"},
            "invalid_response_shape",
        ),
        ({"has_pii": 0, "findings": []}, "has_pii_not_bool"),
        ({"has_pii": False, "findings": None}, "findings_not_list"),
        (
            {
                "has_pii": False,
                "findings": [{"pii_type": "NAME"}],
            },
            "has_pii_findings_mismatch",
        ),
        ({"has_pii": True, "findings": []}, "has_pii_findings_mismatch"),
        (
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME", "value": "Alpha"}],
            },
            "invalid_finding_shape",
        ),
        (
            {
                "has_pii": True,
                "findings": [{"pii_type": "CUSTOM"}],
            },
            "invalid_pii_type",
        ),
        (
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME", "start": True, "end": 5}],
            },
            "invalid_finding_shape",
        ),
        (
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME", "start": 0, "end": 99}],
            },
            "invalid_finding_shape",
        ),
    ],
)
def test_parse_verification_response_rejects_invalid_response(
    response: object,
    reason_code: str,
) -> None:
    with pytest.raises(
        VerificationResponseError, match="response is invalid"
    ) as captured:
        parse_verification_response("Alpha", response)
    assert captured.value.reason_code == reason_code


def test_verification_v3_rejects_observed_off_by_one_response_without_repair() -> None:
    source = "คดีหมายเลขดำที่ 123456789/2569 คดีหมายเลขแดงที่   [PII_CASE_NUMBER_2]"
    assert source[16:30] == "123456789/2569"
    assert source[15:29] == " 123456789/256"
    response = {
        "has_pii": True,
        "findings": [{"pii_type": "CASE_NUMBER", "start": 15, "end": 29}],
    }

    with pytest.raises(VerificationResponseError) as captured:
        parse_verification_response(source, response)

    assert captured.value.reason_code == "invalid_finding_shape"
    rendered = "".join(traceback.format_exception(captured.value))
    assert source not in rendered
    assert "123456789/2569" not in rendered


@pytest.mark.parametrize(
    "source",
    ["😀 ชื่อ: สมชาย ใจดี", "Café กิ้", "Name: Alice Alice"],
)
def test_verification_v3_derives_python_range_without_counting_pii_offsets(
    source: str,
) -> None:
    response = parse_verification_response(
        source, {"has_pii": True, "findings": [{"pii_type": "NAME"}]}
    )

    assert response.findings == (
        VerificationFinding("NAME", 0, len(source), location_scope="window"),
    )
    assert source[response.findings[0].start : response.findings[0].end] == source


@pytest.mark.parametrize("duplicate_type", ["NAME", " name ", "name"])
def test_verification_v3_rejects_duplicate_canonical_types(
    duplicate_type: str,
) -> None:
    with pytest.raises(VerificationResponseError) as captured:
        parse_verification_response(
            "Name: Alice Alice",
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME"}, {"pii_type": duplicate_type}],
            },
        )

    assert captured.value.reason_code == "duplicate_finding_type"


def test_verification_v3_accepts_every_canonical_type_once() -> None:
    response = parse_verification_response(
        "Synthetic inspection window",
        {
            "has_pii": True,
            "findings": [{"pii_type": pii_type} for pii_type in CANONICAL_PII_TYPES],
        },
    )

    assert len(response.findings) == len(CANONICAL_PII_TYPES) == 17
    assert {finding.pii_type for finding in response.findings} == set(
        CANONICAL_PII_TYPES
    )
    assert all(finding.location_scope == "window" for finding in response.findings)


def test_verification_v3_rejects_more_than_canonical_type_count() -> None:
    with pytest.raises(VerificationResponseError) as captured:
        parse_verification_response(
            "Synthetic inspection window",
            {
                "has_pii": True,
                "findings": [{"pii_type": pii_type} for pii_type in CANONICAL_PII_TYPES]
                + [{"pii_type": "NAME"}],
            },
        )

    assert captured.value.reason_code == "too_many_findings"


@pytest.mark.parametrize("echo_field", ["value", "anchor", "explanation"])
def test_verification_v3_rejects_extra_echo_fields_without_exposing_them(
    echo_field: str,
) -> None:
    # Build the value at runtime: Python 3.13 tracebacks quote test source lines,
    # so a literal here would appear in the traceback without any leak.
    parts = ("Synthetic", "Person")
    private_value = " ".join(parts)
    with pytest.raises(VerificationResponseError) as captured:
        parse_verification_response(
            private_value,
            {
                "has_pii": True,
                "findings": [{"pii_type": "NAME", echo_field: private_value}],
            },
        )

    assert captured.value.reason_code == "invalid_finding_shape"
    assert private_value not in "".join(traceback.format_exception(captured.value))


def test_manually_constructed_verification_finding_defaults_to_reported_scope() -> None:
    assert VerificationFinding("NAME", 0, 5).location_scope == "reported"


def test_parse_verification_response_requires_nfc_source() -> None:
    with pytest.raises(
        VerificationResponseError, match="source is invalid"
    ) as captured:
        parse_verification_response(
            "Cafe\u0301",
            {"has_pii": False, "findings": []},
        )
    assert captured.value.reason_code == "invalid_source"


def test_verification_v3_rejects_positive_finding_for_empty_source() -> None:
    with pytest.raises(VerificationResponseError) as captured:
        parse_verification_response(
            "", {"has_pii": True, "findings": [{"pii_type": "NAME"}]}
        )

    assert captured.value.reason_code == "invalid_source"


@pytest.mark.parametrize("untrusted_reason", ["synthetic-secret", "Bob", ["body"]])
def test_verification_error_reason_is_allowlisted_without_echoing_untrusted_data(
    untrusted_reason: object,
) -> None:
    error = VerificationResponseError(
        "LLM verification response is invalid", reason_code=untrusted_reason
    )
    assert error.reason_code == "invalid_response"
    assert str(error) == "LLM verification response is invalid"


def test_parse_detection_response_resolves_thai_value_without_llm_offsets() -> None:
    text = "ชื่อ: สมชาย ใจดี"
    response = {
        "candidates": [
            {
                "pii_type": "NAME",
                "value": "สมชาย ใจดี",
            }
        ]
    }

    result = parse_detection_response(text, response)

    assert result == [
        PiiMatch(
            pii_type="NAME",
            value="สมชาย ใจดี",
            start=6,
            end=16,
        )
    ]


# Synthetic CRLF document shaped like the OCR output that exposed the issue.
_CRLF_SOURCE = (
    "ผู้ฟ้องคดีอยู่บ้านเลขที่ 12/3 ถนนทดสอบ\r\n"
    "    แขวงตัวอย่าง เขตสมมุติ กรุงเทพมหานคร\r\n"
    "โฉนดที่ดิน\r\n    เลขที่ 4567"
)
_CRLF_ADDRESS = "บ้านเลขที่ 12/3 ถนนทดสอบ\r\n    แขวงตัวอย่าง เขตสมมุติ กรุงเทพมหานคร"


def _detect(source, pii_type, value):
    return parse_detection_response(
        source, {"candidates": [{"pii_type": pii_type, "value": value}]}
    )


@pytest.mark.parametrize(
    "model_copy",
    [
        _CRLF_ADDRESS.replace("\r\n", "\n"),  # CR dropped
        _CRLF_ADDRESS.replace("\r\n    ", "\n"),  # indentation dropped too
        _CRLF_ADDRESS.replace("\r\n    ", ""),  # line break dropped entirely
        _CRLF_ADDRESS.replace("\r\n    ", " "),
    ],
)
def test_whitespace_differences_resolve_to_the_exact_source_span(model_copy):
    assert model_copy not in _CRLF_SOURCE
    start = _CRLF_SOURCE.index(_CRLF_ADDRESS)
    assert _detect(_CRLF_SOURCE, "ADDRESS", model_copy) == [
        PiiMatch("ADDRESS", _CRLF_ADDRESS, start, start + len(_CRLF_ADDRESS))
    ]


@pytest.mark.parametrize(
    "model_copy",
    [
        _CRLF_ADDRESS.replace("ตัวอย่าง", "ตัวอย้าง"),  # one substituted letter
        _CRLF_ADDRESS.replace("ตัวอย่าง", "ตัวอย่่าง"),  # one extra mark
        _CRLF_ADDRESS.replace("สมมุติ", "สมมติ"),  # one missing vowel
        # One letter read as tone mark + letter, plus a dropped CR.
        _CRLF_ADDRESS.replace("ทดสอบ", "ทดสอ่ง").replace("\r\n", "\n"),
        _CRLF_ADDRESS.replace("ทดสอบ", "ทดสnบ"),  # Latin look-alike
        # 56 non-whitespace characters allow max(2, 56 // 10) = 5 edits.
        _CRLF_ADDRESS.replace("ตัวอย่าง", "ตัวอย้าง").replace("สมมุติ", "สมมติ"),
        # Four corrected OCR misspellings (seen 2026-10-12) are within budget.
        _CRLF_ADDRESS.replace("ตัวอย่าง", "ตัวอย้าง")
        .replace("สมมุติ", "สมมติ")
        .replace("ทดสอบ", "ทดสอป")
        .replace("มหา", "มฮา"),
        # Only the first and last characters must be exact.
        _CRLF_ADDRESS.replace("บ้าน", "บ่าน"),
        # OCR "repairs" seen in practice: a tone mark moved past a letter
        # (two edits) plus an added letter.
        _CRLF_ADDRESS.replace("ตัวอย่าง", "ตัวอยา่ง").replace("สมมุติ", "สมมุตติ"),
    ],
)
def test_near_copies_within_the_edit_budget_resolve_to_source(model_copy):
    start = _CRLF_SOURCE.index(_CRLF_ADDRESS)
    assert _detect(_CRLF_SOURCE, "ADDRESS", model_copy) == [
        PiiMatch("ADDRESS", _CRLF_ADDRESS, start, start + len(_CRLF_ADDRESS))
    ]


# Approved 2026-10-15: a changed last character no longer cuts the value
# short; the match runs to the end of its word.
@pytest.mark.parametrize(
    "model_copy",
    [
        _CRLF_ADDRESS[:-1] + "ส",  # last letter replaced
        # Ends mid-word on a changed letter: extended to the end of the word.
        _CRLF_ADDRESS[:-3] + "ม",
    ],
)
def test_changed_ending_still_covers_the_whole_last_word(model_copy):
    start = _CRLF_SOURCE.index(_CRLF_ADDRESS)
    assert _detect(_CRLF_SOURCE, "ADDRESS", model_copy) == [
        PiiMatch("ADDRESS", _CRLF_ADDRESS, start, start + len(_CRLF_ADDRESS))
    ]


def test_changed_ending_stops_at_punctuation_and_within_the_budget():
    value = "บ้านเลขที่ 12 ถนนสุขุมวิท แขวงคลองเตย เขตคลองเตย"
    # Table cell: the word ends at the pipe, which stays visible.
    source = f"| {value} | ต่อมา |"
    located = _detect(source, "ADDRESS", value[:-1] + "ม")
    assert [m.value for m in located] == [value]
    # A run longer than the edit budget after the match is not a word end.
    long_run = f"{value}ก{'ข' * 30} แจ้งว่า"
    with pytest.raises(DetectionResponseError) as raised:
        _detect(long_run, "ADDRESS", value[:-1] + "ม")
    assert raised.value.reason_code == "value_not_found"


def test_near_copy_must_be_closer_to_one_source_region_than_any_other():
    # The copy is one edit from each region: neither can be chosen.
    first = "ที่ดินแปลงนี้อยู่ที่ตำบลทดสอบก อำเภอตัวอย่าง จังหวัดสมมุติ"
    second = "ที่ดินแปลงนี้อยู่ที่ตำบลทดสอบข อำเภอตัวอย่าง จังหวัดสมมุติ"
    model_copy = "ที่ดินแปลงนี้อยู่ที่ตำบลทดสอบค อำเภอตัวอย่าง จังหวัดสมมุติ"
    with pytest.raises(DetectionResponseError):
        _detect(f"{first}\n{second}", "ADDRESS", model_copy)
    # With one region alone the same near copy resolves to it.
    assert [m.value for m in _detect(f"{first}\nอื่น ๆ", "ADDRESS", model_copy)] == [
        first
    ]


@pytest.mark.parametrize(
    "pii_type,model_copy",
    [
        # Six differences exceed the five-edit budget.
        (
            "ADDRESS",
            _CRLF_ADDRESS.replace("ตัวอย่าง", "ตัวอย้าง")
            .replace("สมมุติ", "สมมติ")
            .replace("ทดสอบ", "ทดสอป")
            .replace("มหา", "มฮา")
            .replace("เลขที่", "เลขทึ่")
            .replace("ถนน", "ถนบ"),
        ),
        # Joining nonadjacent text is far outside the budget.
        ("ADDRESS", _CRLF_ADDRESS.replace("แขวงตัวอย่าง ", "")),
        # A changed first character moves the boundary: not tolerated.
        ("ADDRESS", "ป" + _CRLF_ADDRESS[1:]),
        # Short values get whitespace tolerance only.
        ("TITLE_DEED_NUMBER", "4568"),
        ("NAME", "ทดสอป"),
        # Text that is not in the source at all.
        ("ADDRESS", "บ้านเลขที่ 99 ถนนอื่น แขวงอื่น เขตอื่น จังหวัดอื่น"),
    ],
)
def test_values_beyond_the_tolerance_still_fail_closed(pii_type, model_copy):
    with pytest.raises(DetectionResponseError) as raised:
        _detect(_CRLF_SOURCE, pii_type, model_copy)
    assert raised.value.reason_code == "value_not_found"


def test_whitespace_tolerance_needs_one_unambiguous_source_text():
    source = "ชื่อ นายทดสอบ ตัวอย่าง และ นายทดสอบ\tตัวอย่าง"
    with pytest.raises(DetectionResponseError):
        _detect(source, "NAME", "นายทดสอบตัวอย่าง")
    # Equal source copies are fine: occurrence selection decides each one.
    repeated = "ชื่อ นายทดสอบ ตัวอย่าง และ นายทดสอบ ตัวอย่าง"
    outcome = parse_detection_outcome(
        repeated, {"candidates": [{"pii_type": "NAME", "value": "นายทดสอบตัวอย่าง"}]}
    )
    assert outcome.issues == ()
    assert [c.value for c in outcome.candidates] == ["นายทดสอบ ตัวอย่าง"]


def test_tolerant_location_never_spans_a_placeholder():
    source = "บ้านเลขที่ [PII_ADDRESS_1] แขวงตัวอย่าง"
    with pytest.raises(DetectionResponseError):
        _detect(source, "ADDRESS", "[PII_ADDRESS_1]แขวงตัวอย่าง")


def test_short_values_still_get_whitespace_tolerance():
    source = "โทร 081 234\r\n5678"
    assert _detect(source, "PHONE", "081 234\n5678") == [
        PiiMatch("PHONE", "081 234\r\n5678", 4, len(source))
    ]


# Approved 2026-10-19: 10-19 non-whitespace characters allow max(1, length // 7)
# edits, so one fixed letter in 10-13 characters and two in 14-19.
_SHORT_SOURCE = "ผู้ร้องอยู่บ้านเลขที่ 12/3 อำเภอสมมุติ แจ้งว่า"


@pytest.mark.parametrize(
    "value,model_copy",
    [
        ("อำเภอสมมุติ", "อำเภอสมมติ"),  # 11 characters, one missing vowel
        ("อำเภอสมมุติ", "อำเภอสมมุตี"),  # last mark changed: runs to word end
        ("บ้านเลขที่ 12/3", "บ่านเลขทึ่ 12/3"),  # 14 characters, two edits
    ],
)
def test_short_near_copies_within_their_budget_resolve_to_source(value, model_copy):
    start = _SHORT_SOURCE.index(value)
    assert _detect(_SHORT_SOURCE, "ADDRESS", model_copy) == [
        PiiMatch("ADDRESS", value, start, start + len(value))
    ]


@pytest.mark.parametrize(
    "model_copy",
    [
        "อำเภอสนมติ",  # 10 characters, two edits: over the one-edit budget
        "บ่านเลขทึ่ 12/8",  # 14 characters, three edits
        "สมมุตี",  # under 10 characters: whitespace tolerance only
    ],
)
def test_short_near_copies_beyond_their_budget_fail_closed(model_copy):
    with pytest.raises(DetectionResponseError) as raised:
        _detect(_SHORT_SOURCE, "ADDRESS", model_copy)
    assert raised.value.reason_code == "value_not_found"


def test_short_near_copy_close_to_two_source_texts_is_ambiguous():
    source = "หนังสือที่ ศย 0001/123 และ ศย 0001/128"
    with pytest.raises(DetectionResponseError):
        _detect(source, "OFFICIAL_LETTER_NUMBER", "ศย 0001/125")


# Synthetic OCR page break splitting one address, as seen on a real page.
_PAGE_BREAK = "\r\n\r\n----  ---|-- | Page 2 --|\r\n\r\n"
_FIRST_PART = "บ้านเลขที่ 12/3 ถนนทดสอบ"
_SECOND_PART = "แขวงตัวอย่าง เขตสมมุติ กรุงเทพมหานคร"
_SPLIT_SOURCE = f"ผู้ฟ้องคดีอยู่{_FIRST_PART}{_PAGE_BREAK}{_SECOND_PART} ต่อมา"
_JOINED = f"{_FIRST_PART} {_SECOND_PART}"


def test_value_joined_across_a_page_break_redacts_each_part():
    matches = _detect(_SPLIT_SOURCE, "ADDRESS", _JOINED)
    assert [m.value for m in matches] == [_FIRST_PART, _SECOND_PART]
    assert all(_SPLIT_SOURCE[m.start : m.end] == m.value for m in matches)
    redacted = redact(_SPLIT_SOURCE, matches).redacted_markdown
    assert redacted == (f"ผู้ฟ้องคดีอยู่[PII_ADDRESS_1]{_PAGE_BREAK}[PII_ADDRESS_2] ต่อมา")


@pytest.mark.parametrize(
    "source",
    [
        # Thai words between the parts: the model skipped text, not a break.
        f"{_FIRST_PART} และที่ดิน {_SECOND_PART}",
        # A placeholder between the parts is not a page break.
        f"{_FIRST_PART} [PII_ORGANIZATION_1] {_SECOND_PART}",
        # The separator is too long to be a page-break line.
        f"{_FIRST_PART}\r\n{'-' * 130}\r\n{_SECOND_PART}",
        # Parts in the wrong order.
        f"{_SECOND_PART}{_PAGE_BREAK}{_FIRST_PART}",
    ],
)
def test_joined_value_is_rejected_unless_only_a_page_break_separates_it(source):
    with pytest.raises(DetectionResponseError) as raised:
        _detect(source, "ADDRESS", _JOINED)
    assert raised.value.reason_code == "value_not_found"


def test_page_break_parts_must_be_unambiguous_and_long_enough():
    twice = f"{_SPLIT_SOURCE}\n{_SPLIT_SOURCE}"
    with pytest.raises(DetectionResponseError):
        _detect(twice, "ADDRESS", _JOINED)
    # Every part needs at least four non-whitespace characters.
    short = "เลขที่ 1" + _PAGE_BREAK + "ถนน"
    with pytest.raises(DetectionResponseError):
        _detect(short, "ADDRESS", "เลขที่ 1 ถนน")
