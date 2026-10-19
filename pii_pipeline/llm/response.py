"""Parse LLM detection and verification replies into checked, typed results.

Values are located in the source by ``locate``; failures carry fixed reason
codes only (``errors``).
"""

import unicodedata
from dataclasses import dataclass, field
from typing import Literal

from ..core.models import PiiCandidate, PiiMatch
from ..core.pii_types import CANONICAL_PII_TYPE_SET, canonicalize_pii_type
from ..selection.occurrences import (
    plan_detection_occurrences,
    resolve_detection_occurrences,
)
from .errors import (
    DETECTION_FAILURE_CODES,
    DetectionResponseError,
    StructuredResponseError,
    VerificationResponseError,
)
from .locate import copy_comparison_details, is_nfc_text, locate_value

__all__ = [
    "CandidateOutcome",
    "DetectionIssue",
    "DetectionOutcome",
    "DetectionResponseError",
    "StructuredResponseError",
    "VerificationFinding",
    "VerificationResponse",
    "VerificationResponseError",
    "parse_detection_candidates",
    "parse_detection_outcome",
    "parse_detection_response",
    "parse_verification_response",
]

# Former private name, kept for diagnostic scripts that import it.
_copy_comparison_details = copy_comparison_details

_DETECTION_RESPONSE_KEYS = frozenset({"candidates"})
_DETECTION_CANDIDATE_KEYS = frozenset({"pii_type", "value"})
_VERIFICATION_RESPONSE_KEYS = frozenset({"has_pii", "findings"})
_VERIFICATION_FINDING_KEYS = frozenset({"pii_type"})


def _has_exact_keys(value: object, expected_keys: frozenset[str]) -> bool:
    return isinstance(value, dict) and value.keys() == expected_keys


@dataclass(frozen=True, slots=True)
class VerificationFinding:
    """Residual type and location; window scope is a coarse inspection range."""

    pii_type: str
    start: int
    end: int
    location_scope: Literal["reported", "window"] = "reported"


@dataclass(frozen=True, slots=True)
class VerificationResponse:
    has_pii: bool
    findings: tuple[VerificationFinding, ...]


@dataclass(frozen=True, slots=True)
class DetectionIssue:
    """Safe internal metadata; never a value or a replacement instruction."""

    reason_code: str
    candidate_index: int | None = None

    def __post_init__(self) -> None:
        if self.reason_code not in (
            *DETECTION_FAILURE_CODES,
            "selection_unavailable",
            "detection_unavailable",
        ) or (
            self.candidate_index is not None
            and (
                type(self.candidate_index) is not int
                or not 1 <= self.candidate_index <= 1_000_000
            )
        ):
            raise ValueError("Invalid detection issue")


@dataclass(frozen=True, slots=True)
class CandidateOutcome:
    candidates: tuple[PiiCandidate, ...] = field(repr=False)
    issues: tuple[DetectionIssue, ...]


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    """Intermediate matches with explicit unresolved inspection issues."""

    matches: tuple[PiiMatch, ...] = field(repr=False)
    issues: tuple[DetectionIssue, ...]


def parse_detection_candidates(
    normalized_text: str, response: object
) -> list[PiiCandidate]:
    """Validate exact values; proposals do not select equal-valued occurrences."""
    response_error = "LLM detection response is invalid"
    if not is_nfc_text(normalized_text):
        raise DetectionResponseError(
            "LLM detection source is invalid", reason_code="invalid_source"
        )
    if not _has_exact_keys(response, _DETECTION_RESPONSE_KEYS):
        raise DetectionResponseError(
            response_error, reason_code="invalid_response_shape"
        )
    candidates = response["candidates"]
    if not isinstance(candidates, list):
        raise DetectionResponseError(response_error, reason_code="candidates_not_list")
    unique: dict[tuple[str, str], PiiCandidate] = {}
    for index, candidate in enumerate(candidates, start=1):
        if not _has_exact_keys(candidate, _DETECTION_CANDIDATE_KEYS):
            raise DetectionResponseError(
                response_error, reason_code="invalid_candidate_shape"
            )
        value = candidate["value"]
        if not isinstance(value, str) or not value.strip():
            raise DetectionResponseError(response_error, reason_code="invalid_value")
        try:
            pii_type = canonicalize_pii_type(candidate["pii_type"])
        except (TypeError, ValueError):
            raise DetectionResponseError(
                response_error, reason_code="invalid_pii_type"
            ) from None
        value = unicodedata.normalize("NFC", value)
        values = locate_value(normalized_text, value)
        if any(item not in normalized_text for item in values):
            raise DetectionResponseError(
                response_error,
                reason_code="value_not_found",
                details={
                    "candidate_index": index,
                    "pii_type": pii_type,
                    "source_length": len(normalized_text),
                    "value_length": len(value),
                    "value_found_in_source": False,
                    **copy_comparison_details(normalized_text, value),
                },
            )
        for item in values:
            unique[(pii_type, item)] = PiiCandidate(pii_type, item)
    return list(unique.values())


def parse_detection_response(
    normalized_text: str, response: object, *, occurrence_decisions: object = None
) -> list[PiiMatch]:
    """Resolve unique values directly; repeated values require explicit decisions."""
    candidates = parse_detection_candidates(normalized_text, response)
    plan = plan_detection_occurrences(normalized_text, candidates)
    return resolve_detection_occurrences(normalized_text, plan, occurrence_decisions)


def parse_detection_outcome(normalized_text: str, response: object) -> CandidateOutcome:
    """Retain individually valid proposals without declaring a failed window clean.

    The strict parser remains available. Recovery consumes this internal outcome
    and must independently verify the actual final output before returning it.
    """
    if not is_nfc_text(normalized_text):
        raise DetectionResponseError(
            "LLM detection source is invalid", reason_code="invalid_source"
        )
    if not _has_exact_keys(response, _DETECTION_RESPONSE_KEYS):
        return CandidateOutcome((), (DetectionIssue("invalid_response_shape"),))
    if not isinstance(response["candidates"], list):
        return CandidateOutcome((), (DetectionIssue("candidates_not_list"),))
    valid: dict[tuple[str, str], PiiCandidate] = {}
    issues: list[DetectionIssue] = []
    for index, candidate in enumerate(response["candidates"], 1):
        try:
            parsed = parse_detection_candidates(
                normalized_text, {"candidates": [candidate]}
            )
        except DetectionResponseError as error:
            issues.append(DetectionIssue(error.reason_code, index))
        else:
            for item in parsed:
                valid[(item.pii_type, item.value)] = item
    return CandidateOutcome(tuple(valid.values()), tuple(issues))


def parse_verification_response(
    normalized_redacted_text: str,
    response: object,
) -> VerificationResponse:
    """Validate type-only residual findings and derive coarse locations locally.

    The model never supplies offsets or values. Each location covers the inspected
    source window; it must not be used as an exact PII span or redaction instruction.
    """

    source_error = "LLM verification source is invalid"
    response_error = "LLM verification response is invalid"

    if not is_nfc_text(normalized_redacted_text):
        raise VerificationResponseError(source_error, reason_code="invalid_source")

    if not _has_exact_keys(response, _VERIFICATION_RESPONSE_KEYS):
        raise VerificationResponseError(
            response_error, reason_code="invalid_response_shape"
        )

    has_pii = response["has_pii"]
    findings = response["findings"]

    if type(has_pii) is not bool:
        raise VerificationResponseError(response_error, reason_code="has_pii_not_bool")
    if not isinstance(findings, list):
        raise VerificationResponseError(response_error, reason_code="findings_not_list")

    if has_pii != bool(findings):
        raise VerificationResponseError(
            response_error, reason_code="has_pii_findings_mismatch"
        )

    if len(findings) > len(CANONICAL_PII_TYPE_SET):
        raise VerificationResponseError(response_error, reason_code="too_many_findings")
    if has_pii and not normalized_redacted_text:
        raise VerificationResponseError(source_error, reason_code="invalid_source")

    parsed_findings: list[VerificationFinding] = []
    found_types: set[str] = set()

    for finding in findings:
        if not _has_exact_keys(finding, _VERIFICATION_FINDING_KEYS):
            raise VerificationResponseError(
                response_error, reason_code="invalid_finding_shape"
            )

        try:
            pii_type = canonicalize_pii_type(finding["pii_type"])
        except (TypeError, ValueError):
            raise VerificationResponseError(
                response_error, reason_code="invalid_pii_type"
            ) from None
        if pii_type in found_types:
            raise VerificationResponseError(
                response_error, reason_code="duplicate_finding_type"
            )
        found_types.add(pii_type)
        parsed_findings.append(
            VerificationFinding(
                pii_type=pii_type,
                start=0,
                end=len(normalized_redacted_text),
                location_scope="window",
            )
        )

    parsed_findings.sort(
        key=lambda finding: (finding.start, finding.end, finding.pii_type)
    )

    return VerificationResponse(
        has_pii=has_pii,
        findings=tuple(parsed_findings),
    )
