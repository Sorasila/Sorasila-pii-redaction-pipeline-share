"""Automatic, bounded recovery with one final independent verification gate.

Only exact original-source spans enter redaction/mapping. Intermediate outcomes
stay in memory in this request; failures never return partial documents.

Flow of one request (``_process``):

1. detect every window (``detect``: resends, repairs, in-window merging);
2. add the rule matches and merge (``merge``: rules win, overlaps chosen);
3. join land numbers with their location, redact, run the rule check and an
   independent LLM verification (``verify``);
4. if either still finds PII, run one residual round (``residual``) and go
   back to 3; a round that adds nothing fails closed.
"""

import asyncio
from collections.abc import Callable
from inspect import iscoroutinefunction

from ..core.detection import DetectionError, Detector, normalize_unicode, run_detectors
from ..core.models import PiiMatch, RedactionResult
from ..core.redaction import redact, validate_redaction_source
from ..core.verification import (
    VerificationChecker,
    VerificationError,
    run_verification_checker,
)
from ..llm.processing import LlmDocumentProcessor
from ..selection.land import join_land_numbers_with_addresses
from .detect import REPAIR_INSTRUCTION, detect_window
from .merge import merge_with_selection
from .policy import (
    RECOVERY_MERGE_REASON_CODES,
    RECOVERY_VERSION,
    Budget,
    RecoveryLimitError,
    RecoveryMergeError,
    RecoveryPolicy,
)
from .residual import residual_additions
from .verify import verify_redacted

__all__ = [
    "RECOVERY_MERGE_REASON_CODES",
    "RECOVERY_VERSION",
    "RecoveryLimitError",
    "RecoveryMergeError",
    "RecoveryPolicy",
    "process_markdown_with_recovery_async",
]

# Former private names, kept for diagnostic scripts that import them.
_Budget = Budget
_REPAIR_INSTRUCTION = REPAIR_INSTRUCTION
_detect_window = detect_window
_merge_with_selection = merge_with_selection


def _is_async_callable(callback):
    return iscoroutinefunction(callback) or iscoroutinefunction(type(callback).__call__)


def valid_rule_lane(rule_detectors, rules_has_pii) -> bool:
    """Rule detectors and the rule check: synchronous callables, at least one."""
    return (
        isinstance(rule_detectors, tuple)
        and bool(rule_detectors)
        and all(
            callable(detector) and not _is_async_callable(detector)
            for detector in rule_detectors
        )
        and callable(rules_has_pii)
        and not _is_async_callable(rules_has_pii)
    )


async def _detect_document(source, processor, budget, rule_detectors):
    """Detected matches in document coordinates and how many windows kept issues."""
    windows = processor._plan(source, processor.detection_window_planner)
    budget.emit(
        "RECOVERY_STARTED",
        detection_windows=len(windows),
        max_recovery_calls=budget.policy.max_recovery_calls,
        reserved_recovery_calls=budget.policy.reserved_recovery_calls,
    )
    matches = []
    issue_windows = 0
    for window_number, window in enumerate(windows, 1):
        local, issues = await detect_window(
            processor,
            window,
            budget,
            window_number=window_number,
            rule_detectors=rule_detectors,
        )
        issue_windows += int(bool(issues))
        matches.extend(
            PiiMatch(
                item.pii_type,
                item.value,
                window.document_start + item.start,
                window.document_start + item.end,
            )
            for item in local
        )
    return windows, matches, issue_windows


async def _process(source, processor, rule_detectors, rules_has_pii, budget):
    windows, matches, issue_windows = await _detect_document(
        source, processor, budget, rule_detectors
    )
    # Rule safety net sees the original source after LLM analysis, before replacement.
    _, rules = run_detectors(source, list(rule_detectors))
    matches = await merge_with_selection(
        source, [*matches, *rules], processor, budget, windows, required=tuple(rules)
    )
    for round_number in range(1 + budget.policy.max_residual_rounds):
        matches = join_land_numbers_with_addresses(source, matches)
        result = redact(source, matches)
        rules_found = run_verification_checker(
            result.redacted_markdown, rules_has_pii, checker_name="Rules"
        )
        response, verification_windows = await verify_redacted(
            processor, result.redacted_markdown, budget
        )
        if not rules_found and not response.has_pii:
            # Explicit acceptance policy: full fresh independent final verification
            # can clear preliminary extraction issues. No error is converted to [].
            budget.emit(
                "FINAL_VERIFIED",
                residual_rounds=round_number,
                preliminary_issue_windows=issue_windows,
                role_calls=budget.calls,
                recovery_calls=budget.recovery_calls,
                conflict_selection_calls=budget.conflict_selection_calls,
            )
            return result
        if (
            round_number == budget.policy.max_residual_rounds
            or not budget.can_recover()
        ):
            raise VerificationError("Residual PII remains after bounded recovery")
        # Fixed types and flags only: why a residual round may fail.
        budget.emit(
            "RESIDUAL_RECOVERY_STARTED",
            round_number=round_number + 1,
            finding_types=sorted({finding.pii_type for finding in response.findings}),
            rules_found=bool(rules_found),
        )
        additions = await residual_additions(
            source,
            matches,
            result.redacted_markdown,
            response,
            verification_windows,
            rules_found,
            processor,
            rule_detectors,
            budget,
        )
        updated = await merge_with_selection(
            source,
            [*matches, *additions],
            processor,
            budget,
            windows,
            required=tuple(matches),
        )
        if updated == matches:
            raise VerificationError("Residual recovery made no progress")
        matches = updated
    raise VerificationError("PII verification failed")


async def process_markdown_with_recovery_async(
    markdown: str,
    processor: LlmDocumentProcessor,
    *,
    rule_detectors: tuple[Detector, ...],
    rules_has_pii: VerificationChecker,
    policy: RecoveryPolicy,
    progress: Callable[[dict], None] | None = None,
) -> RedactionResult:
    """Return only verified output; all recovery occurs within this request."""
    if (
        not isinstance(processor, LlmDocumentProcessor)
        or not isinstance(policy, RecoveryPolicy)
        or not valid_rule_lane(rule_detectors, rules_has_pii)
    ):
        raise TypeError("Invalid recovery configuration")
    if not isinstance(markdown, str) or not markdown.strip():
        raise DetectionError("PII source document is invalid")
    source = normalize_unicode(markdown)
    validate_redaction_source(source)
    try:
        async with asyncio.timeout(policy.deadline_seconds):
            return await _process(
                source,
                processor,
                rule_detectors,
                rules_has_pii,
                Budget(policy, progress),
            )
    except TimeoutError:
        raise TimeoutError("PII processing deadline exceeded") from None
