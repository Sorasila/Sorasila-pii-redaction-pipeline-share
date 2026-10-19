"""Residual round: find what verification still sees and map it to the source.

The residual pass reads redacted text, so every value it returns must map
back to an unchanged stretch of the original source. A value that contains
placeholders keeps only its parts between them (``placeholder_parts``); a
value that still cannot map fails closed.
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

# Approved 2026-10-19: models reading redacted text return values such as
# '[PII_NAME_1] บ้านเลขที่ 12 ...' (full run C10, window 15: 9 of 9 residual
# values held a placeholder and the page failed). The text between the
# placeholders is kept as values of the same type, each part at least
# _MIN_RESIDUAL_PART non-whitespace characters and not only a label or a
# title; the rest is dropped. Final verification still runs afterwards.
_MIN_RESIDUAL_PART = 4
_PART_EDGE = " \t\r\n,.:;-()|"
_LABEL_PARTS = frozenset(
    {
        "เลขที่",
        "บ้านเลขที่",
        "ที่อยู่",
        "อยู่ที่",
        "โฉนดเลขที่",
        "นางสาว",
        "เด็กชาย",
        "เด็กหญิง",
        "นามสกุล",
        "หรือ",
    }
)


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


def placeholder_parts(match):
    """The parts of a value outside its placeholders; the value itself if none."""
    if not _PLACEHOLDER.search(match.value):
        return [match]
    bounds = [0]
    for found in _PLACEHOLDER.finditer(match.value):
        bounds += [found.start(), found.end()]
    bounds.append(len(match.value))
    parts = []
    for start, end in zip(bounds[::2], bounds[1::2], strict=True):
        text = match.value[start:end]
        left = len(text) - len(text.lstrip(_PART_EDGE))
        part = text[left:].rstrip(_PART_EDGE)
        if (
            len("".join(part.split())) < _MIN_RESIDUAL_PART
            or part in _LABEL_PARTS
            or "[PII_" in part
        ):
            continue
        offset = match.start + start + left
        parts.append(PiiMatch(match.pii_type, part, offset, offset + len(part)))
    return parts


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
    with_placeholder = [item for item in found if _PLACEHOLDER.search(item.value)]
    kept = [part for item in found for part in placeholder_parts(item)]
    # Fixed types and counts only: why a residual round may fail.
    budget.emit(
        "RESIDUAL_CANDIDATES",
        candidates=len(found),
        by_type=dict(Counter(item.pii_type for item in found)),
        with_placeholder=len(with_placeholder),
        placeholder_parts=sum(
            len(placeholder_parts(item)) for item in with_placeholder
        ),
        land_prefix_trimmed=trimmed,
        unmapped=sum(not _maps_to_source(source, item, segments) for item in kept),
        issue_codes=sorted(issue_codes),
    )
    additions.extend(map_to_source(source, item, segments) for item in kept)
    return additions
