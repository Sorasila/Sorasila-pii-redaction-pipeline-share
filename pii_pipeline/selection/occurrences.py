"""Locate exact values locally and classify repeated occurrences by service IDs."""

import json
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from itertools import pairwise

from ..core.models import PiiCandidate, PiiMatch
from ..core.pii_types import CANONICAL_PII_TYPE_SET
from ..llm.errors import DetectionResponseError

NOT_PII = "NOT_PII"


@dataclass(frozen=True, slots=True)
class DetectionOccurrence:
    occurrence_id: int
    start: int
    end: int
    value: str = field(repr=False)
    allowed_types: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OccurrencePlan:
    direct_matches: tuple[PiiMatch, ...] = field(repr=False)
    occurrences: tuple[DetectionOccurrence, ...] = field(repr=False)
    context: str = field(repr=False)
    marker_prefix: str


def _reject(reason: str) -> None:
    raise DetectionResponseError(
        "LLM detection response is invalid", reason_code=reason
    )


def _all_copies(source, candidates):
    """Every exact copy of every candidate value, with the types proposed for it."""
    spans: dict[tuple[int, int, str], set[str]] = {}
    for candidate in candidates:
        if (
            not isinstance(candidate, PiiCandidate)
            or candidate.pii_type not in CANONICAL_PII_TYPE_SET
            or not isinstance(candidate.value, str)
            or not candidate.value.strip()
            or not unicodedata.is_normalized("NFC", candidate.value)
        ):
            _reject("invalid_candidate_shape")
        start = source.find(candidate.value)
        if start < 0:
            _reject("value_not_found")
        while start >= 0:
            key = (start, start + len(candidate.value), candidate.value)
            spans.setdefault(key, set()).add(candidate.pii_type)
            # Include self-overlapping copies; selected overlaps are rejected later.
            start = source.find(candidate.value, start + 1)
    return spans


def _direct_and_repeated(spans):
    """A value found once with one type is direct; the rest need a decision."""
    counts = Counter(value for _, _, value in spans)
    direct: list[PiiMatch] = []
    occurrences: list[DetectionOccurrence] = []
    for (start, end, value), types in sorted(spans.items()):
        if counts[value] == 1 and len(types) == 1:
            direct.append(PiiMatch(next(iter(types)), value, start, end))
        else:
            occurrences.append(
                DetectionOccurrence(
                    len(occurrences) + 1, start, end, value, tuple(sorted(types))
                )
            )
    return direct, occurrences


def _marker_prefix(source):
    # Source data cannot forge these service-generated annotation delimiters.
    namespace = 1
    prefix = f"PII_OCCURRENCE_{namespace}_"
    while prefix in source:
        namespace += 1
        prefix = f"PII_OCCURRENCE_{namespace}_"
    return prefix


def _annotated_context(source, occurrences, prefix):
    """The selection request: source with ID-marked occurrences, as JSON."""
    if not occurrences:
        return ""
    events: dict[int, list[tuple[int, int, str]]] = {}
    for item in occurrences:
        events.setdefault(item.start, []).append(
            (1, item.occurrence_id, f"<{prefix}{item.occurrence_id}>")
        )
        events.setdefault(item.end, []).append(
            (0, item.occurrence_id, f"</{prefix}{item.occurrence_id}>")
        )
    pieces: list[str] = []
    cursor = 0
    for position, markers in sorted(events.items()):
        pieces.append(source[cursor:position])
        pieces.extend(marker for _, _, marker in sorted(markers))
        cursor = position
    pieces.append(source[cursor:])
    return json.dumps(
        {
            "annotated_source": "".join(pieces),
            "occurrences": [
                {
                    "occurrence_id": item.occurrence_id,
                    "candidate_types": list(item.allowed_types),
                }
                for item in occurrences
            ],
        },
        ensure_ascii=False,
    )


def plan_detection_occurrences(
    source: str, candidates: list[PiiCandidate]
) -> OccurrencePlan:
    """Enumerate all exact copies without assuming equal values share a meaning."""
    if not isinstance(source, str) or not unicodedata.is_normalized("NFC", source):
        _reject("invalid_source")
    direct, occurrences = _direct_and_repeated(_all_copies(source, candidates))
    prefix = _marker_prefix(source)
    context = _annotated_context(source, occurrences, prefix)
    return OccurrencePlan(tuple(direct), tuple(occurrences), context, prefix)


def resolve_detection_occurrences(
    source: str, plan: OccurrencePlan, response: object = None
) -> list[PiiMatch]:
    """Accept a complete closed decision set; never infer a missing decision."""
    matches = list(plan.direct_matches)
    if plan.occurrences:
        if response is None:
            _reject("occurrence_selection_required")
        if not isinstance(response, dict) or response.keys() != {"decisions"}:
            _reject("invalid_selection_shape")
        decisions = response["decisions"]
        if not isinstance(decisions, list):
            _reject("invalid_selection_shape")
        by_id = {item.occurrence_id: item for item in plan.occurrences}
        seen: set[int] = set()
        for decision in decisions:
            if not isinstance(decision, dict) or decision.keys() != {
                "occurrence_id",
                "pii_type",
            }:
                _reject("invalid_selection_shape")
            occurrence_id = decision["occurrence_id"]
            if type(occurrence_id) is not int or occurrence_id not in by_id:
                _reject("invalid_occurrence_id")
            if occurrence_id in seen:
                _reject("duplicate_occurrence_id")
            seen.add(occurrence_id)
            item = by_id[occurrence_id]
            pii_type = decision["pii_type"]
            if type(pii_type) is not str or pii_type not in (
                *item.allowed_types,
                NOT_PII,
            ):
                _reject("invalid_selection_type")
            if pii_type != NOT_PII:
                matches.append(PiiMatch(pii_type, item.value, item.start, item.end))
        if seen != by_id.keys():
            _reject("missing_occurrence_decision")
    elif response is not None:
        _reject("unexpected_selection")

    matches.sort(key=lambda match: (match.start, match.end, match.pii_type))
    for match in matches:
        if (
            type(match.start) is not int
            or type(match.end) is not int
            or not 0 <= match.start < match.end <= len(source)
            or source[match.start : match.end] != match.value
        ):
            _reject("invalid_resolved_span")
    for previous, current in pairwise(matches):
        if current.start < previous.end:
            _reject("overlapping_matches")
    return matches


# Approved 2026-10-15 (proposal 3.1): copies of a repeated value need no LLM
# choice when (a) a rule matched exactly that span with one of the proposed
# types (rules always win), or (b) the value was proposed with one type only
# and is a NAME with a title or an ADDRESS of 20+ non-space characters. Every
# other copy is still decided by the LLM.
_TITLES = ("นาย", "นาง", "น.ส.", "เด็กชาย", "เด็กหญิง", "ด.ช.", "ด.ญ.")
_LONG_ADDRESS = 20


def type_decidable_without_llm(allowed_types, value) -> str | None:
    """The type of a NAME with a title or a long ADDRESS proposed alone."""
    if len(allowed_types) != 1:
        return None
    (pii_type,) = allowed_types
    if pii_type == "NAME" and value.lstrip().startswith(_TITLES):
        return pii_type
    if pii_type == "ADDRESS" and len("".join(value.split())) >= _LONG_ADDRESS:
        return pii_type
    return None


def _inside_rule_match(item, rule_matches):
    """A copy strictly inside a rule match (e.g. a land number inside the
    rule's number + location ADDRESS) is masked by the rule anyway."""
    for match in rule_matches:
        if (
            match.start <= item.start
            and item.end <= match.end
            and ((match.start, match.end) != (item.start, item.end))
        ):
            return item.allowed_types[0]
    return None


def settle_occurrences(source, plan, known_matches=()):
    """Decide the copies the rules or the policy above already settle.

    Returns the plan the LLM still has to decide (settled copies become direct
    matches; the rest keep their order with new IDs) and how many were settled.
    """
    known = {(match.start, match.end, match.pii_type) for match in known_matches}
    direct = list(plan.direct_matches)
    remaining = []
    for item in plan.occurrences:
        decided = (
            next(
                (t for t in item.allowed_types if (item.start, item.end, t) in known),
                None,
            )
            or _inside_rule_match(item, known_matches)
            or type_decidable_without_llm(item.allowed_types, item.value)
        )
        if decided is None:
            remaining.append(item)
        else:
            direct.append(PiiMatch(decided, item.value, item.start, item.end))
    settled = len(plan.occurrences) - len(remaining)
    if not settled:
        return plan, 0
    occurrences = tuple(
        DetectionOccurrence(
            number, item.start, item.end, item.value, item.allowed_types
        )
        for number, item in enumerate(remaining, 1)
    )
    direct.sort(key=lambda match: (match.start, match.end, match.pii_type))
    context = _annotated_context(source, occurrences, plan.marker_prefix)
    return OccurrencePlan(
        tuple(direct), occurrences, context, plan.marker_prefix
    ), settled
