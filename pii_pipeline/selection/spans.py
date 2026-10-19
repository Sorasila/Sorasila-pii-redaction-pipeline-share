"""Select among service-located source spans without inventing replacements."""

import json
import unicodedata

from ..core.detection import DetectionError, validate_detection_matches
from ..core.pii_types import CANONICAL_PII_TYPE_SET
from ..llm.errors import DetectionResponseError
from .occurrences import (
    DetectionOccurrence,
    OccurrencePlan,
    resolve_detection_occurrences,
)


def match_key(match):
    return match.start, match.end, match.pii_type


def _reject(reason):
    raise DetectionResponseError(
        "LLM conflict selection is invalid", reason_code=reason
    )


def plan_match_selection(source, matches, required_matches=()):
    if not isinstance(source, str) or not unicodedata.is_normalized("NFC", source):
        _reject("invalid_source")
    try:
        checked = validate_detection_matches(source, matches)
        required = validate_detection_matches(source, list(required_matches))
    except DetectionError:
        _reject("invalid_resolved_span")
    by_span = {}
    for match in checked:
        if match.pii_type not in CANONICAL_PII_TYPE_SET:
            _reject("invalid_selection_type")
        by_span.setdefault((match.start, match.end, match.value), set()).add(
            match.pii_type
        )
    required_keys = {match_key(match) for match in required}
    if not required_keys <= {match_key(match) for match in checked}:
        _reject("invalid_resolved_span")
    occurrences = tuple(
        DetectionOccurrence(number, start, end, value, tuple(sorted(types)))
        for number, ((start, end, value), types) in enumerate(
            sorted(by_span.items()), 1
        )
    )
    if not occurrences:
        _reject("invalid_selection_shape")
    namespace = 1
    while (prefix := f"PII_OCCURRENCE_{namespace}_") in source:
        namespace += 1
    events = {}
    items = []
    for item in occurrences:
        events.setdefault(item.start, []).append(
            (1, item.occurrence_id, f"<{prefix}{item.occurrence_id}>")
        )
        events.setdefault(item.end, []).append(
            (0, item.occurrence_id, f"</{prefix}{item.occurrence_id}>")
        )
        required_types = [
            kind
            for kind in item.allowed_types
            if (item.start, item.end, kind) in required_keys
        ]
        if len(required_types) > 1:
            _reject("overlapping_matches")
        items.append(
            {
                "occurrence_id": item.occurrence_id,
                "candidate_types": list(item.allowed_types),
                "required_types": required_types,
            }
        )
    pieces, cursor = [], 0
    for position, markers in sorted(events.items()):
        pieces.append(source[cursor:position])
        pieces.extend(marker for _, _, marker in sorted(markers))
        cursor = position
    pieces.append(source[cursor:])
    context = json.dumps(
        {"annotated_source": "".join(pieces), "occurrences": items}, ensure_ascii=False
    )
    return OccurrencePlan((), occurrences, context, prefix)


def resolve_match_selection(source, plan, response, required_matches=()):
    selected = resolve_detection_occurrences(source, plan, response)
    if not {match_key(match) for match in required_matches} <= {
        match_key(match) for match in selected
    }:
        _reject("required_match_omitted")
    return selected
