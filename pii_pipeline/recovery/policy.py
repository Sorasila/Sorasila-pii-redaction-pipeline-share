"""Recovery limits, the per-request call budget and fixed failure classes."""

import math
from dataclasses import dataclass

from ..core.detection import DetectionError

RECOVERY_VERSION = "automatic-recovery-v3"
RECOVERY_MERGE_REASON_CODES = frozenset(
    {
        "invalid_source_match",
        "noncanonical_match",
        "source_span_conflict",
        "conflict_window_unavailable",
        "conflict_selection_unavailable",
        "conflict_selection_rejected",
        "conflict_recovery_limit",
    }
)


@dataclass(frozen=True, slots=True)
class RecoveryPolicy:
    """Role calls include extraction+selection; transport attempts remain bounded.

    The bridge additionally caps every actual proxy request. This budget never
    resets during retries, residual repairs or fresh final verification.

    ``reserved_recovery_calls`` of ``max_recovery_calls`` are unavailable to
    initial-pass window repairs (and their in-window conflict selections). They
    remain for document merge selection, verification retries and residual
    recovery. With a zero repair allowance, initial issues are kept unresolved
    for the fresh final verification instead of being repaired.

    ``blank_response_retries`` re-sends a detection or verification window
    whose reply was blank or not the requested shape (approved 2026-10-06), and
    a merge conflict selection with such a reply (approved 2026-10-12).
    Those calls count toward ``max_role_calls`` and the deadline but not
    ``max_recovery_calls``.
    """

    max_role_calls: int = 64
    max_recovery_calls: int = 4
    window_repair_attempts: int = 2
    verification_retry_attempts: int = 1
    conflict_selection_attempts: int = 1
    max_residual_rounds: int = 1
    deadline_seconds: float = 600.0
    reserved_recovery_calls: int = 0
    blank_response_retries: int = 3

    def __post_init__(self) -> None:
        limits = (
            (self.max_role_calls, 1, 100_000),
            (self.max_recovery_calls, 0, 64),
            (self.reserved_recovery_calls, 0, self.max_recovery_calls),
            (self.window_repair_attempts, 0, 2),
            (self.verification_retry_attempts, 0, 2),
            (self.conflict_selection_attempts, 0, 2),
            (self.max_residual_rounds, 0, 2),
            (self.blank_response_retries, 0, 5),
        )
        if any(
            type(value) is not int or not low <= value <= high
            for value, low, high in limits
        ) or (
            type(self.deadline_seconds) not in (int, float)
            or not math.isfinite(self.deadline_seconds)
            or not 0 < self.deadline_seconds <= 86_400
        ):
            raise ValueError("Invalid recovery policy")


class RecoveryLimitError(DetectionError):
    pass


class RecoveryMergeError(DetectionError):
    """Fixed diagnostic reason; never retain source values or positions."""

    def __init__(self, reason_code):
        if (
            type(reason_code) is not str
            or reason_code not in RECOVERY_MERGE_REASON_CODES
        ):
            raise ValueError("Invalid recovery merge reason")
        self.reason_code = reason_code
        super().__init__("PII source matches could not be merged")


class Budget:
    """Counts role and recovery calls for one request and reports progress.

    Progress events carry only event names, counts and fixed codes; the
    service log line is built from them.
    """

    def __init__(self, policy, progress):
        self.policy = policy
        self.progress = progress
        self.calls = 0
        self.recovery_calls = 0
        self.conflict_selection_calls = 0

    def emit(self, event, **counts):
        if self.progress is not None:
            try:
                self.progress(
                    {
                        "event": event,
                        "role_calls": self.calls,
                        "recovery_calls": self.recovery_calls,
                        **counts,
                    }
                )
            except Exception:  # noqa: BLE001 - external observer failures are sanitized.
                raise DetectionError("Processing observer failed") from None

    def recovery_limit(self, use_reserved=True):
        reserved = 0 if use_reserved else self.policy.reserved_recovery_calls
        return self.policy.max_recovery_calls - reserved

    def can_recover(self, use_reserved=True):
        return self.recovery_calls < self.recovery_limit(use_reserved)

    def can_call(self):
        return self.calls < self.policy.max_role_calls

    def can_resend_blank(self, resends):
        """A blank or wrong-shape reply may be re-sent outside the recovery budget."""
        return resends < self.policy.blank_response_retries and self.can_call()

    def reserve(self, recovery, use_reserved=True):
        if self.calls >= self.policy.max_role_calls or (
            recovery and not self.can_recover(use_reserved)
        ):
            raise RecoveryLimitError("PII recovery call limit exceeded")
        self.calls += 1
        self.recovery_calls += int(recovery)
