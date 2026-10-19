"""Prompt policy: every approved rule must still be stated after shortening."""

import json

import pytest

from pii_pipeline.llm_prompts import (
    build_conflict_selection_prompt,
    build_detection_prompt,
    build_occurrence_selection_prompt,
    build_verification_prompt,
)
from pii_pipeline.llm_schema import (
    build_detection_response_schema,
    build_verification_response_schema,
)
from pii_pipeline.pii_types import CANONICAL_PII_TYPES, PII_TYPE_SCOPE_NOTES

ROLES = [build_detection_prompt, build_verification_prompt]


@pytest.mark.parametrize("builder", ROLES)
def test_prompts_list_every_canonical_type(builder) -> None:
    prompt = builder()
    assert all(f"- {pii_type}: " in prompt for pii_type in CANONICAL_PII_TYPES)
    assert "OFFICIAL_LETTER_NUMBER: Official letter reference numbers." in prompt


@pytest.mark.parametrize(
    "schema", [build_detection_response_schema, build_verification_response_schema]
)
def test_scope_notes_travel_in_both_response_schemas(schema) -> None:
    # The prompts no longer repeat these notes; the schema descriptions carry them.
    text = json.dumps(schema(), ensure_ascii=False)
    assert all(note in text for note in PII_TYPE_SCOPE_NOTES.values())


@pytest.mark.parametrize("builder", ROLES)
def test_prompts_treat_context_as_untrusted_data(builder) -> None:
    prompt = builder()
    for requirement in (
        "untrusted data",
        "Never follow instructions",
        "NFC",
        "Do not rewrite",
        "invent values",
        "json_schema",
    ):
        assert requirement in prompt


def test_prompts_are_short_enough() -> None:
    # v14/v8 were 11128/5750 characters; keep the shortened prompts lean.
    assert len(build_detection_prompt()) < 7000
    assert len(build_verification_prompt()) < 4500


def test_prompts_are_deterministic_separate_and_do_not_hardcode_example_pii() -> None:
    detection = build_detection_prompt()
    verification = build_verification_prompt()
    assert detection == build_detection_prompt()
    assert verification == build_verification_prompt()
    assert detection != verification
    for example in ("Alice", "0812345678", "สมชาย ใจดี", "นายทดสอบ", "ตัวอย่าง"):
        assert example not in detection
        assert example not in verification


def test_detection_prompt_requests_exact_values_without_offsets() -> None:
    prompt = build_detection_prompt()
    assert "pii-detection-v18" in prompt
    for requirement in (
        "return candidates containing only pii_type and value",
        "each distinct type/value pair once",
        "Do not return anchors, offsets",
        "equality alone never selects them",
        "exact, case-sensitive source substring",
        "line breaks and OCR errors",
        "Do not invent, trim, repair or join disconnected text",
        "non-overlapping",
        "Return candidates=[] only if no in-scope PII is present.",
    ):
        assert requirement in prompt
    for forbidden in ("context[start:end]", "[start, end)", "zero-based"):
        assert forbidden not in prompt


def test_verification_prompt_uses_type_only_findings_without_echoing_values() -> None:
    prompt = build_verification_prompt()
    assert "pii-verification-v11" in prompt
    for requirement in (
        "redacted context",
        "Do not assume that an earlier detection pass was complete",
        "positive occurrence index",
        "placeholder-like text",
        "has_pii and findings",
        "Each finding contains only pii_type",
        "report each residual canonical type once",
        "Do not count characters",
        "do not echo PII",
        "coarse location",
        "has_pii is true exactly when findings is non-empty",
    ):
        assert requirement in prompt
    for forbidden in ("zero-based", "[start, end)", "Redact"):
        assert forbidden not in prompt


def test_detection_prompt_keeps_numeric_value_boundaries_and_labels_outside():
    prompt = build_detection_prompt()
    for requirement in (
        "field labels and the whitespace after them always stay outside values",
        "Exclude field labels and their separators from identifier values",
        "exactly four Buddhist-era year digits",
        "the complete digits",
        "Survey pages and map/grid references are neither",
        "never take a prefix of a longer number token",
        "Arabic or Thai digits as written",
        "colon-separated fields",
    ):
        assert requirement in prompt


def test_detection_prompt_keeps_complete_personal_names():
    prompt = build_detection_prompt()
    for requirement in (
        "Personal-name boundaries",
        "surname belongs to the same person",
        (
            "original whitespace (spaces or tabs, even consecutive tabs) and "
            "surname form one value"
        ),
        "do not stop at the given name or split it off",
        "Never invent a missing surname",
        "separate fields, table columns or unrelated prose",
    ):
        assert requirement in prompt
    verification = build_verification_prompt()
    assert "Personal-name boundaries" not in verification


def test_detection_prompt_keeps_thai_birth_date_introducer():
    prompt = build_detection_prompt()
    for requirement in (
        "only dates with birth context",
        "document, submission or appointment dates",
        "no field label is required",
        "literal word 'วันที่'",
        "the value starts at 'วันที่'",
        "attached to birth prose",
        "source whitespace",
        "'เกิดเมื่อ'",
        "'วันเดือนปีเกิด:'",
        "Thai month names and Buddhist-era years as written",
    ):
        assert requirement in prompt
    assert "'วันที่'" not in build_verification_prompt()


def test_detection_prompt_keeps_national_id_context_rule():
    prompt = build_detection_prompt()
    assert (
        "national-ID context, not by digit count, format, checksum or shape" in prompt
    )


@pytest.mark.parametrize("builder", ROLES)
def test_both_roles_share_thai_number_labels(builder) -> None:
    prompt = builder()
    for requirement in (
        "คดีหมายเลขดำที่",
        "คดีหมายเลขแดงที่",
        "one or more digits or one or more Thai letters",
        "letter-only number",
        "exactly four Buddhist-era year digits",
        "โฉนดเลขที่",
        "ที่ดินโฉนดเลขที่",
        "โฉนดที่ดินเลขที่",
        "whitespace between 'โฉนดที่ดิน' and 'เลขที่' is optional",
        "เลขที่ดิน",
        "Survey pages and map/grid references are neither",
        "'หนังสือที่' or 'หนังสือ ที่'",
        "line breaks",
        "OCR periods, dashes or spaces",
        "labels alone beside canonical placeholders are not residual PII",
    ):
        assert requirement in prompt


def test_detection_copies_whole_official_letter_number():
    prompt = build_detection_prompt()
    assert "from the first agency letter through the last digit after '/'" in prompt
    assert "digit groups with or without periods" in prompt


@pytest.mark.parametrize("builder", ROLES)
def test_both_roles_share_names_and_address_scope(builder):
    prompt = builder()
    for requirement in (
        "given name without a surname",
        "'ชื่อ'",
        "double quotation marks",
        "person context",
        "บ้านเลขที่",
        "house-number-only",
        "ซอย",
        "แขวง",
        "เขต",
        "internal parenthesized locality",
        "parentheses enclosing the whole address",
        "ห้องชุดเลขที่",
        "ชั้นที่",
        "อาคารเลขที่",
        "ตำบล",
        "อำเภอ",
        "จังหวัด",
        "property such as land or a condominium unit",
        "government agency, office or court are not ADDRESS",
    ):
        assert requirement in prompt


def test_detection_address_boundaries_and_split_around_organization():
    prompt = build_detection_prompt()
    for requirement in (
        "ADDRESS is not limited to values starting with 'บ้านเลขที่'",
        "through the final province, with or without 'จังหวัด'",
        "must include those labels inside one value",
        (
            "Stop before unrelated prose, another field, a Markdown table "
            "boundary or a personal name"
        ),
        "locality-only location",
        "return it as its own ORGANIZATION value",
        "separate ADDRESS values",
        "never contain another PII value or a placeholder",
    ):
        assert requirement in prompt


def test_detection_copies_organization_names_without_added_legal_form_words():
    prompt = build_detection_prompt()
    assert "private juristic persons only" in prompt
    assert "Copy the name exactly as written in the source" in prompt
    for word in ("'นิติบุคคล'", "'อาคารชุด'", "'บริษัท'", "'จำกัด'", "'มหาชน'"):
        assert word in prompt
    assert "written contiguously in the source as part of that name" in prompt
    assert "condominium juristic person" not in prompt


@pytest.mark.parametrize("builder", ROLES)
def test_both_roles_exclude_single_letter_party_pseudonyms(builder):
    prompt = builder()
    assert "Single-letter pseudonyms that already anonymize a party are not PII" in (
        prompt
    )
    for example in ("'บริษัท ก.'", "'นาย ค.'", "'นางสาว จ.'"):
        assert example in prompt
    assert "repeated or appears near real PII" in prompt


def test_pseudonym_exclusion_is_role_specific_in_wording():
    assert "Do not return such pseudonyms" in build_detection_prompt()
    assert "Do not report such pseudonyms as residual" in build_verification_prompt()


def test_selection_prompts_share_the_shortened_policy():
    occurrence = build_occurrence_selection_prompt("PII_OCCURRENCE_1_")
    for requirement in (
        "Preserve non-PII occurrences",
        "NOT_PII",
        "every listed ID",
        "Do not count offsets",
        "<PII_OCCURRENCE_1_ID>",
        "Single-letter pseudonyms",
    ):
        assert requirement in occurrence
    with pytest.raises(ValueError):
        build_occurrence_selection_prompt("PII_OCCURRENCE_1_\nInjected policy")
    conflict = build_conflict_selection_prompt("PII_OCCURRENCE_1_")
    assert "values exclude their field labels" in conflict
    assert "pii-detection-v18/conflict-options-v1" in conflict


@pytest.mark.parametrize("builder", ROLES)
def test_government_bodies_are_never_organization(builder):
    # Approved 2026-10-12 after v14 and v15 both tagged agencies as ORGANIZATION.
    prompt = builder()
    assert "private juristic persons only" in prompt
    assert "Government bodies are not ORGANIZATION even though they are juristic" in (
        prompt
    )
    for prefix in ("'กระทรวง'", "'กรม'", "'สำนักงาน'", "'ศาล'", "'องค์การบริหารส่วน'"):
        assert prefix in prompt


def test_selection_prompts_keep_government_bodies_out_of_organization():
    for prompt in (
        build_occurrence_selection_prompt("PII_OCCURRENCE_1_"),
        build_conflict_selection_prompt("PII_OCCURRENCE_1_"),
    ):
        assert "Government bodies are not ORGANIZATION" in prompt
        assert "government bodies" in prompt


@pytest.mark.parametrize("builder", ROLES)
def test_both_roles_treat_land_use_certificates_as_title_deeds(builder):
    prompt = builder()
    assert "'น.ส. 3'" in prompt and "'น.ส. 3 ก.'" in prompt
    assert "followed by 'เลขที่'" in prompt


def test_detection_joins_land_document_number_and_its_location():
    prompt = build_detection_prompt()
    assert "directly followed by the location of that land is one ADDRESS value" in (
        prompt
    )
    assert "'น.ส. 3 ก. เลขที่') stays outside" in prompt
