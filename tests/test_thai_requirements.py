"""Synthetic source-span oracles; mocked classifications do not test LLM accuracy."""

import pytest
from fake_llm import run_recovery

from pii_pipeline.core.detection import normalize_unicode
from pii_pipeline.core.redaction import redact
from pii_pipeline.core.verification import VerificationError
from pii_pipeline.llm.response import (
    parse_detection_response,
    parse_verification_response,
)
from pii_pipeline.rules.thai import detect_thai_labeled_numbers
from smoke_llm import SMOKE_CASES

ADDITIONAL_CASE_IDS = (
    "thai-case-numbers",
    "thai-title-deeds",
    "thai-land-parcels",
    "thai-name-forms",
    "thai-address-forms",
)


@pytest.mark.parametrize("case_id", ADDITIONAL_CASE_IDS)
def test_thai_requirement_oracles_redact_complete_values_with_exact_boundaries(
    case_id: str,
) -> None:
    case = SMOKE_CASES[case_id]
    assert normalize_unicode(case.text) == case.text
    result = redact(case.text, list(case.expected_matches))
    assert result.redacted_markdown == case.expected_redacted_text
    assert [entry.original_value for entry in result.entries] == [
        match.value for match in case.expected_matches
    ]


@pytest.mark.parametrize(
    "case_id", ["thai-case-numbers", "thai-title-deeds", "thai-land-parcels"]
)
def test_numeric_rules_match_the_additional_trusted_oracles(case_id: str) -> None:
    case = SMOKE_CASES[case_id]
    assert detect_thai_labeled_numbers(case.text) == list(case.expected_matches)


@pytest.mark.parametrize("case_id", ADDITIONAL_CASE_IDS)
def test_each_additional_span_is_supported_by_detection_and_residual_contracts(
    case_id: str,
) -> None:
    case = SMOKE_CASES[case_id]
    for match in case.expected_matches:
        # Isolate each source line so repeated values have an exact unique anchor.
        line_start = case.text.rfind("\n", 0, match.start) + 1
        line_end = case.text.find("\n", match.end)
        if line_end < 0:
            line_end = len(case.text)
        line = case.text[line_start:line_end]
        parsed = parse_detection_response(
            line,
            {
                "candidates": [
                    {
                        "pii_type": match.pii_type,
                        "value": match.value,
                    }
                ]
            },
        )
        assert len(parsed) == 1
        assert parsed[0].start == match.start - line_start
        assert parsed[0].end == match.end - line_start
        assert parsed[0].value == match.value
        residual = parse_verification_response(
            line,
            {
                "has_pii": True,
                "findings": [{"pii_type": match.pii_type}],
            },
        )
        assert residual.has_pii is True
        assert residual.findings[0].pii_type == match.pii_type
        assert residual.findings[0].location_scope == "window"
        assert (residual.findings[0].start, residual.findings[0].end) == (0, len(line))


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", ADDITIONAL_CASE_IDS)
async def test_additional_requirements_work_in_hybrid_pipeline_with_mock_semantics(
    case_id: str,
) -> None:
    case = SMOKE_CASES[case_id]
    checked: list[str] = []

    async def synthetic_semantics(source):
        assert source == case.text
        # Trusted oracle including numeric duplicates tests lane deduplication.
        return list(case.expected_matches)

    async def synthetic_llm_verification(source):
        checked.append(source)
        assert source == case.expected_redacted_text
        return False

    result = await run_recovery(
        case.text,
        synthetic_semantics,
        synthetic_llm_verification,
        rule_detectors=(detect_thai_labeled_numbers,),
    )
    assert result.redacted_markdown == case.expected_redacted_text
    assert len(result.entries) == len(case.expected_matches)
    assert checked == [case.expected_redacted_text]


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", ["thai-name-forms", "thai-address-forms"])
async def test_semantic_miss_remains_fail_closed_when_residual_checker_finds_pii(
    case_id: str,
) -> None:
    case = SMOKE_CASES[case_id]

    async def missed_semantics(source):
        return []

    async def residual_llm(source):
        assert source == case.text
        return True

    # The residual round finds nothing new either: fail closed, no output.
    with pytest.raises(VerificationError, match="Residual recovery made no progress"):
        await run_recovery(
            case.text,
            missed_semantics,
            residual_llm,
            rule_detectors=(detect_thai_labeled_numbers,),
        )
