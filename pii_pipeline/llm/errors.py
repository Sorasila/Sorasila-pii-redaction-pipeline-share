"""Errors for unusable LLM replies: fixed reason codes, never reply data."""

from collections.abc import Mapping
from types import MappingProxyType

from ..core.pii_types import CANONICAL_PII_TYPE_SET

DETECTION_FAILURE_CODES = frozenset(
    {
        "invalid_response",
        "invalid_source",
        "invalid_response_shape",
        "candidates_not_list",
        "invalid_candidate_shape",
        "invalid_value",
        "invalid_pii_type",
        "value_not_found",
        "occurrence_selection_required",
        "invalid_selection_shape",
        "invalid_occurrence_id",
        "duplicate_occurrence_id",
        "missing_occurrence_decision",
        "invalid_selection_type",
        "unexpected_selection",
        "invalid_resolved_span",
        "overlapping_matches",
        "required_match_omitted",
        "conflict_options_exceeded",
        "invalid_conflict_decisions",
        "invalid_conflict_option",
    }
)
VERIFICATION_FAILURE_CODES = frozenset(
    {
        "invalid_response",
        "invalid_source",
        "invalid_response_shape",
        "has_pii_not_bool",
        "findings_not_list",
        "has_pii_findings_mismatch",
        "invalid_finding_shape",
        "invalid_pii_type",
        "duplicate_finding_type",
        "too_many_findings",
    }
)
_DETECTION_DETAIL_COUNTS = frozenset(
    {"candidate_index", "source_length", "value_length"}
)
_DETECTION_DETAIL_FLAGS = frozenset(
    {
        "value_found_in_source",
        "value_unique_in_source",
        "value_found_without_whitespace",
        "value_found_with_nfkc_comparison",
        "value_found_without_format_characters",
        "value_contains_format_characters",
    }
)


def _safe_detection_details(details: object) -> dict[str, str | int | bool]:
    """Copy only bounded primitive metadata; never retain source/response fields."""
    safe: dict[str, str | int | bool] = {}
    if type(details) is not dict:
        return safe
    pii_type = details.get("pii_type")
    if type(pii_type) is str and pii_type in CANONICAL_PII_TYPE_SET:
        safe["pii_type"] = pii_type
    for key in _DETECTION_DETAIL_COUNTS:
        value = details.get(key)
        minimum = 1 if key == "candidate_index" else 0
        if type(value) is int and minimum <= value <= 1_000_000:
            safe[key] = value
    for key in _DETECTION_DETAIL_FLAGS:
        value = details.get(key)
        if type(value) is bool:
            safe[key] = value
    return safe


class StructuredResponseError(ValueError):
    pass


class DetectionResponseError(StructuredResponseError):
    """Keep generic messages and an allowlisted failure code, never response data."""

    def __init__(
        self,
        *args: object,
        reason_code: object = "invalid_response",
        details: object = None,
    ) -> None:
        super().__init__(*args)
        self._reason_code = (
            reason_code
            if type(reason_code) is str and reason_code in DETECTION_FAILURE_CODES
            else "invalid_response"
        )
        self._details = MappingProxyType(_safe_detection_details(details))

    @property
    def reason_code(self) -> str:
        return self._reason_code

    @property
    def details(self) -> Mapping[str, str | int | bool]:
        return self._details

    def _add_details(self, details: dict[str, object]) -> None:
        self._details = MappingProxyType(
            {**self._details, **_safe_detection_details(details)}
        )


class VerificationResponseError(StructuredResponseError):
    """Keep generic messages and an allowlisted failure code, never response data."""

    def __init__(self, *args: object, reason_code: object = "invalid_response") -> None:
        super().__init__(*args)
        self._reason_code = (
            reason_code
            if type(reason_code) is str and reason_code in VERIFICATION_FAILURE_CODES
            else "invalid_response"
        )

    @property
    def reason_code(self) -> str:
        return self._reason_code
