"""Merge located values; let the rules or the LLM choose between overlapping ones.

Steps of ``merge_with_selection``:

1. drop land numbers that an ADDRESS already covers (``land``);
2. if nothing overlaps, the merge is done;
3. group overlapping values and assign each group to the detection window
   that contains it (one batch per window);
4. plan the legal options per batch; when rule matches leave exactly one
   option per group the choice is forced and made locally;
5. otherwise ask the LLM to choose, re-sending blank replies, within the
   recovery budget.
"""

from dataclasses import dataclass
from itertools import pairwise
from typing import NamedTuple

from ..core.detection import DetectionError, validate_detection_matches
from ..core.models import PiiMatch
from ..core.pii_types import canonicalize_pii_type
from ..llm.proxy import is_recoverable_proxy_error
from ..llm.response import DetectionResponseError
from ..llm.windows import TextWindow
from ..selection.conflicts import plan_conflict_options, resolve_conflict_options
from ..selection.land import absorbed_land_numbers
from ..selection.spans import match_key
from .policy import RecoveryMergeError
from .replies import is_blank_selection_error


def _ordered(matches):
    return sorted(matches, key=lambda match: (match.start, match.end, match.pii_type))


def merge_matches(source, matches):
    """Validated, de-duplicated, ordered matches; any overlap is a conflict."""
    try:
        validated = validate_detection_matches(source, matches)
    except DetectionError:
        raise RecoveryMergeError("invalid_source_match") from None
    unique = {}
    for match in validated:
        if canonicalize_pii_type(match.pii_type) != match.pii_type:
            raise RecoveryMergeError("noncanonical_match")
        unique[(match.start, match.end, match.pii_type)] = match
    ordered = _ordered(unique.values())
    if any(right.start < left.end for left, right in pairwise(ordered)):
        raise RecoveryMergeError("source_span_conflict")
    return ordered


def _shift(matches, offset):
    return [
        PiiMatch(match.pii_type, match.value, match.start + offset, match.end + offset)
        for match in matches
    ]


def _checked_selection(text, selected, local, mandatory):
    """The choice may only keep offered values and must keep every rule match."""
    selected = merge_matches(text, selected)
    selected_keys = {match_key(item) for item in selected}
    if (
        not selected_keys <= {match_key(item) for item in local}
        or not {match_key(item) for item in mandatory} <= selected_keys
    ):
        raise RecoveryMergeError("conflict_selection_rejected")
    return selected


def _overlap_groups(ordered):
    """Runs of transitively overlapping matches, in source order."""
    groups, group, end = [], [], -1
    for match in ordered:
        if group and match.start >= end:
            groups.append(group)
            group = []
        group.append(match)
        end = max(end, match.end) if len(group) > 1 else match.end
    if group:
        groups.append(group)
    return groups


def _window_batches(groups, windows):
    """Matches that overlap nothing, and the rest batched by containing window."""
    settled, batches = [], {}
    for group in groups:
        if len(group) == 1:
            settled.extend(group)
            continue
        start, end = group[0].start, max(item.end for item in group)
        containing = next(
            (
                (number, window)
                for number, window in enumerate(windows, 1)
                if window.document_start <= start and end <= window.document_end
            ),
            None,
        )
        if containing is None:
            raise RecoveryMergeError("conflict_window_unavailable")
        number, window = containing
        batches.setdefault(number, (window, []))[1].extend(group)
    return settled, batches


@dataclass(frozen=True, slots=True)
class _ConflictBatch:
    """Overlapping values of one window, in that window's coordinates."""

    number: int
    window: TextWindow
    local: list
    mandatory: list
    plan: object
    forced: bool


def _is_forced(plan):
    """Mandatory matches leave exactly one legal option in every group."""
    return all(len(group.options) == 1 for group in plan.groups)


def _plan_batch(number, window, alternatives, required_keys, budget, scope, reported):
    local = _shift(alternatives, -window.document_start)
    mandatory = _shift(
        [item for item in alternatives if match_key(item) in required_keys],
        -window.document_start,
    )
    try:
        plan = plan_conflict_options(window.text, local, tuple(mandatory))
    except DetectionResponseError:
        # Deterministic planning failure: no legal option or bounds exceeded.
        raise RecoveryMergeError("conflict_selection_rejected") from None
    forced = _is_forced(plan)
    budget.emit(
        "CONFLICT_GROUPS_PLANNED",
        scope=scope,
        window_number=reported,
        group_count=len(plan.groups),
        forced_group_count=sum(len(group.options) == 1 for group in plan.groups),
        max_option_count=max(len(group.options) for group in plan.groups),
        candidate_count=len(local),
        required_count=len(mandatory),
        selection_required=not forced,
    )
    return _ConflictBatch(number, window, local, mandatory, plan, forced)


def _check_selection_budget(batches, processor, budget, scope, use_reserved):
    selection_batches = sum(not batch.forced for batch in batches)
    budget.emit(
        "CONFLICT_MERGE_PLANNED",
        scope=scope,
        batch_count=len(batches),
        forced_batch_count=len(batches) - selection_batches,
        selection_batch_count=selection_batches,
    )
    if selection_batches:
        if not budget.policy.conflict_selection_attempts:
            raise RecoveryMergeError("source_span_conflict")
        if not callable(getattr(processor.client, "select_matches", None)):
            raise RecoveryMergeError("conflict_selection_unavailable")
        # Each selection batch needs at least one call; fail before spending any.
        remaining = budget.recovery_limit(use_reserved) - budget.recovery_calls
        if selection_batches > remaining:
            raise RecoveryMergeError("conflict_recovery_limit")


def _forced_choice(batch, budget, scope, reported):
    text, plan = batch.window.text, batch.plan
    try:
        selected = _checked_selection(
            text,
            resolve_conflict_options(
                text,
                plan,
                {
                    "decisions": {
                        group.group_id: group.options[0].option_id
                        for group in plan.groups
                    }
                },
                tuple(batch.mandatory),
            ),
            batch.local,
            batch.mandatory,
        )
    except (DetectionResponseError, RecoveryMergeError):
        raise RecoveryMergeError("conflict_selection_rejected") from None
    budget.emit(
        "CONFLICT_SELECTION_FORCED",
        scope=scope,
        window_number=reported,
        selected_count=len(selected),
    )
    return selected


class _SelectionReply(NamedTuple):
    selected: list | None
    failure_reason: str | None
    resends: int


async def _selection_reply(batch, processor, budget, scope, reported, attempt, resends):
    """One counted selection attempt, re-sending blank replies."""
    text = batch.window.text
    while True:
        try:
            selected = _checked_selection(
                text,
                await processor.client.select_matches(
                    text, batch.local, required_matches=tuple(batch.mandatory)
                ),
                batch.local,
                batch.mandatory,
            )
        except Exception as error:  # noqa: BLE001 - sanitize only known failure classes.
            if is_blank_selection_error(error) and budget.can_resend_blank(resends):
                resends += 1
                budget.reserve(False)
                budget.emit(
                    "BLANK_RESPONSE_RETRY",
                    role="selection",
                    scope=scope,
                    window_number=reported,
                    attempt=attempt + 1,
                    retry=resends,
                )
                continue
            if isinstance(error, (DetectionResponseError, RecoveryMergeError)):
                return _SelectionReply(None, "conflict_selection_rejected", resends)
            if is_recoverable_proxy_error(error):
                return _SelectionReply(None, "conflict_selection_unavailable", resends)
            raise DetectionError("Conflict selection failed") from None
        return _SelectionReply(selected, None, resends)


async def _llm_choice(batch, processor, budget, scope, reported, use_reserved):
    resends = 0
    attempts = budget.policy.conflict_selection_attempts
    for attempt in range(attempts):
        if not budget.can_recover(use_reserved):
            raise RecoveryMergeError("conflict_recovery_limit")
        budget.reserve(True, use_reserved)
        budget.conflict_selection_calls += 1
        budget.emit(
            "CONFLICT_SELECTION_STARTED",
            scope=scope,
            window_number=reported,
            attempt=attempt + 1,
            candidate_count=len(batch.local),
            required_count=len(batch.mandatory),
            conflict_selection_calls=budget.conflict_selection_calls,
        )
        reply = await _selection_reply(
            batch, processor, budget, scope, reported, attempt, resends
        )
        resends = reply.resends
        if reply.selected is not None:
            budget.emit(
                "CONFLICT_SELECTION_FINISHED",
                scope=scope,
                window_number=reported,
                selected_count=len(reply.selected),
                conflict_selection_calls=budget.conflict_selection_calls,
            )
            return reply.selected
        if attempt + 1 == attempts:
            raise RecoveryMergeError(reply.failure_reason) from None
    # Unreachable: _check_selection_budget requires at least one attempt.
    raise RecoveryMergeError("conflict_selection_unavailable")


async def merge_with_selection(
    source,
    matches,
    processor,
    budget,
    windows,
    *,
    required=(),
    window_number=None,
    use_reserved=True,
):
    """Resolve span conflicts; a forced choice is local and spends no budget.

    ``window_number`` marks an in-window merge; document merges report the
    detection window that contains each conflict batch. A land number inside an
    ADDRESS that overlaps nothing else is dropped first, rule matches included.
    """
    scope = "document" if window_number is None else "window"
    absorbed = absorbed_land_numbers(matches)
    if absorbed:
        matches = [match for match in matches if match_key(match) not in absorbed]
        required = tuple(
            match for match in required if match_key(match) not in absorbed
        )
        budget.emit("LAND_NUMBERS_ABSORBED", scope=scope, count=len(absorbed))
    try:
        return merge_matches(source, matches)
    except RecoveryMergeError as error:
        if error.reason_code != "source_span_conflict":
            raise
    # Every input was already validated by merge_matches; keep unrelated results.
    ordered = _ordered({match_key(match): match for match in matches}.values())
    merge_matches(source, list(required))
    settled, by_window = _window_batches(_overlap_groups(ordered), windows)
    required_keys = {match_key(item) for item in required}
    batches = [
        _plan_batch(
            number,
            window,
            alternatives,
            required_keys,
            budget,
            scope,
            number if window_number is None else window_number,
        )
        for number, (window, alternatives) in by_window.items()
    ]
    _check_selection_budget(batches, processor, budget, scope, use_reserved)
    for batch in batches:
        reported = batch.number if window_number is None else window_number
        if batch.forced:
            selected = _forced_choice(batch, budget, scope, reported)
        else:
            selected = await _llm_choice(
                batch, processor, budget, scope, reported, use_reserved
            )
        settled.extend(_shift(selected, batch.window.document_start))
    return merge_matches(source, settled)
