"""Detection of one window: blank-reply resends, repairs and in-window merging."""

from typing import NamedTuple

from ..core.detection import DetectionError, run_detectors
from ..llm.response import DetectionIssue, DetectionOutcome
from ..llm.windows import make_text_window
from .merge import merge_with_selection
from .policy import RecoveryMergeError
from .replies import (
    is_blank_detection_outcome,
    is_blank_proxy_error,
    is_recoverable_detection_error,
)

REPAIR_INSTRUCTION = (
    "\nTrusted recovery instruction: Reinspect the supplied source independently. "
    "Return only literal substrings copied exactly from this context; do not repair "
    "spelling, expand names, join nonadjacent text, or include field labels, and "
    "do not add legal-form or type words (such as 'นิติบุคคล') that are not "
    "written in the source as part of that name. "
    "Existing [PII_TYPE_n] placeholders are not PII values. "
    "Preserve occurrences that are not PII according to their context."
)


class DetectionReply(NamedTuple):
    """One detection call; ``matches`` is None when the call itself failed."""

    matches: list | None
    issues: tuple
    blank: bool


class WindowDetection(NamedTuple):
    matches: list
    issues: tuple


async def request_detection(
    processor, text, prompt, rule_matches=None
) -> DetectionReply:
    """One detection call, classified: usable matches, issues, blank reply."""
    try:
        outcome = await processor.client.detect_outcome(
            text, prompt=prompt, rule_matches=rule_matches
        )
        if (
            not isinstance(outcome, DetectionOutcome)
            or not isinstance(outcome.issues, tuple)
            or not all(isinstance(issue, DetectionIssue) for issue in outcome.issues)
        ):
            raise DetectionError("Invalid detection outcome")
    except Exception as error:  # noqa: BLE001 - recover only known safe failure classes.
        if not is_recoverable_detection_error(error):
            raise DetectionError("PII detection failed") from None
        return DetectionReply(
            None,
            (DetectionIssue("detection_unavailable"),),
            is_blank_proxy_error(error),
        )
    return DetectionReply(
        list(outcome.matches), outcome.issues, is_blank_detection_outcome(outcome)
    )


async def _request_with_resends(
    processor, window, prompt, budget, resends, window_number, attempt, known
):
    """Re-send blank replies (outside the recovery budget) while allowed.

    Returns the last reply and the window's blank resends so far.
    """
    while True:
        reply = await request_detection(processor, window.text, prompt, known)
        if not (reply.blank and budget.can_resend_blank(resends)):
            return reply, resends
        resends += 1
        budget.reserve(False)
        budget.emit(
            "BLANK_RESPONSE_RETRY",
            role="detection",
            window_number=window_number,
            attempt=attempt + 1,
            retry=resends,
        )


async def detect_window(
    processor, window, budget, *, recovery=False, window_number=1, rule_detectors=()
) -> WindowDetection:
    """Detect one window, repairing while issues remain.

    ``recovery`` marks a residual-round window: one counted attempt only.
    Initial-pass repairs cannot spend calls reserved for merge/verification.
    Rule matches in the window settle repeated copies they cover (proposal 3.1).
    """
    rules = list(rule_detectors)
    known = (lambda text: run_detectors(text, rules)[1]) if rules else None
    matches = []
    issues = ()
    resends = 0
    attempts = 1 if recovery else 1 + budget.policy.window_repair_attempts
    use_reserved = recovery
    for attempt in range(attempts):
        repair = recovery or attempt > 0
        if repair and not budget.can_recover(use_reserved):
            budget.emit(
                "WINDOW_REPAIR_SKIPPED",
                window_number=window_number,
                attempt=attempt + 1,
                recovery=recovery,
                reserved_recovery_calls=budget.policy.reserved_recovery_calls,
            )
            break
        budget.reserve(repair, use_reserved)
        budget.emit(
            "DETECTION_WINDOW_STARTED",
            window_number=window_number,
            attempt=attempt + 1,
            recovery=repair,
        )
        prompt = processor.detection_prompt + (REPAIR_INSTRUCTION if repair else "")
        reply, resends = await _request_with_resends(
            processor, window, prompt, budget, resends, window_number, attempt, known
        )
        issues = reply.issues
        if reply.matches is not None:
            try:
                matches = await merge_with_selection(
                    window.text,
                    [*matches, *reply.matches],
                    processor,
                    budget,
                    [make_text_window(window.text, 0, len(window.text))],
                    window_number=window_number,
                    use_reserved=use_reserved,
                )
            except RecoveryMergeError as error:
                budget.emit(
                    "DETECTION_WINDOW_REJECTED",
                    window_number=window_number,
                    attempt=attempt + 1,
                    recovery=repair,
                    reason_code=error.reason_code,
                    retained_matches=len(matches),
                    incoming_matches=len(reply.matches),
                )
                raise
        budget.emit(
            "DETECTION_WINDOW_OUTCOME",
            issue_count=len(issues),
            valid_matches=len(matches),
            recovery=repair,
            window_number=window_number,
        )
        if not issues:
            break
    return WindowDetection(matches, issues)
