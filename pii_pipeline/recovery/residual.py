"""Residual round: find what verification still sees and map it to the source.

The residual pass reads redacted text, so every value it returns must map
back to an unchanged stretch of the original source; a value that crosses a
placeholder cannot, and fails closed.
"""

import re
from collections import Counter

from ..core.detection import DetectionError, run_detectors
from ..core.models import PiiMatch
from ..core.redaction import build_replacements_and_entries
from ..selection.land import trim_land_placeholder
from .detect import detect_window
from .merge import merge_matches

_PLACEHOLDER = re.compile(r"\[PII_[A-Z_]+_\d+\]")


def source_segments(source, matches):
    """Map unchanged final-text intervals to original NFC source intervals."""
    replacements, _ = build_replacements_and_entries(matches)
    cursor = 0
    redacted_cursor = 0
    segments = []
    for match, placeholder in replacements:
        length = match.start - cursor
        if length:
            segments.append((redacted_cursor, redacted_cursor + length, cursor))
        redacted_cursor += length + len(placeholder)
        cursor = match.end
    if cursor < len(source):
        segments.append(
            (redacted_cursor, redacted_cursor + len(source) - cursor, cursor)
        )
    return segments


def map_to_source(source, match, segments):
    for start, end, source_start in segments:
        if start <= match.start < match.end <= end:
            original_start = source_start + match.start - start
            original_end = original_start + len(match.value)
            if source[original_start:original_end] == match.value:
                return PiiMatch(
                    match.pii_type, match.value, original_start, original_end
                )
    raise DetectionError("Recovery match crosses a protected replacement")


def _maps_to_source(source, match, segments):
    try:
        map_to_source(source, match, segments)
    except DetectionError:
        return False
    return True


def _target_windows(verification_windows, response, rules_found):
    return [
        window
        for window in verification_windows
        if rules_found
        or any(
            finding.start < window.document_end and window.document_start < finding.end
            for finding in response.findings
        )
    ]


async def residual_additions(
    source,
    matches,
    redacted,
    response,
    verification_windows,
    rules_found,
    processor,
    rule_detectors,
    budget,
):
    """Source matches for what the rules and a recovery detection still find."""
    segments = source_segments(source, matches)
    _, residual_rules = run_detectors(redacted, list(rule_detectors))
    additions = [
        map_to_source(source, item, segments)
        for item in merge_matches(redacted, residual_rules)
    ]
    found, issue_codes, trimmed = [], set(), 0
    targets = _target_windows(verification_windows, response, rules_found)
    for window_number, window in enumerate(targets, 1):
        if not budget.can_recover():
            break
        local, issues = await detect_window(
            processor,
            window,
            budget,
            recovery=True,
            window_number=window_number,
            rule_detectors=rule_detectors,
        )
        issue_codes.update(issue.reason_code for issue in issues)
        for item in local:
            item, cut = trim_land_placeholder(item)
            trimmed += int(cut)
            found.append(
                PiiMatch(
                    item.pii_type,
                    item.value,
                    window.document_start + item.start,
                    window.document_start + item.end,
                )
            )
    # Fixed types and counts only: why a residual round may fail.
    budget.emit(
        "RESIDUAL_CANDIDATES",
        candidates=len(found),
        by_type=dict(Counter(item.pii_type for item in found)),
        with_placeholder=sum(bool(_PLACEHOLDER.search(item.value)) for item in found),
        land_prefix_trimmed=trimmed,
        unmapped=sum(not _maps_to_source(source, item, segments) for item in found),
        issue_codes=sorted(issue_codes),
    )
    additions.extend(map_to_source(source, item, segments) for item in found)
    return additions
