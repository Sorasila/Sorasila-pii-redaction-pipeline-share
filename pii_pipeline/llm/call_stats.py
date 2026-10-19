"""Per-request counts of LLM calls, safe to log (names and numbers only).

The service shares one LLM client between concurrent requests, so the counts
live in a context variable that each request opens for itself. Outside an open
collection, recording is a no-op.
"""

from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar


class CallStats(Counter):
    """Counts, plus every HTTP attempt as (role, seconds, outcome) in order.

    Outcome is "ok" (HTTP 200), "http_<status>", "timeout", "error" or "cut"
    (the call's own deadline cancelled the attempt).
    """

    def __init__(self) -> None:
        super().__init__()
        self.attempts: list[tuple[str, float, str]] = []


_current: ContextVar[CallStats | None] = ContextVar("pii_call_stats", default=None)

# Top-level response keys of each structured-output schema -> call role.
_ROLES = {
    frozenset({"candidates"}): "detection",
    frozenset({"has_pii", "findings"}): "verification",
    frozenset({"decisions"}): "selection",
}


@contextmanager
def collect_call_stats() -> Iterator[CallStats]:
    counts = CallStats()
    token = _current.set(counts)
    try:
        yield counts
    finally:
        _current.reset(token)


def record(key: str) -> None:
    counts = _current.get()
    if counts is not None:
        counts[key] += 1


def record_attempt(role: str, seconds: float, outcome: str) -> None:
    counts = _current.get()
    if counts is not None:
        counts.attempts.append((role, seconds, outcome))


def role_of(json_schema: object) -> str:
    properties = (
        json_schema.get("properties") if isinstance(json_schema, dict) else None
    )
    if isinstance(properties, dict):
        return _ROLES.get(frozenset(properties), "other")
    return "other"


# Selection calls by kind and type, and copies of repeated values settled
# without the LLM (proposal 3.1, approved 2026-10-15). Counting only.


def record_selection(kind: str, items) -> None:
    """One selection call: ``kind`` is occurrence or conflict, ``items`` are
    (allowed types, value) of the spans the model is asked about."""
    record(f"sel_{kind}")
    for pii_type in sorted({t for types, _ in items for t in types}):
        record(f"sel_{kind}_type:{pii_type}")


def record_settled(count: int) -> None:
    for _ in range(count):
        record("sel_occurrence_settled")
