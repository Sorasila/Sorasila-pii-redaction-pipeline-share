"""The one-line request log: counts, fixed codes and the cause chain only.

The line never contains document text, values or external error messages.
"""

import asyncio
import logging
from collections import Counter
from uuid import UUID

# Handlers and tests address the log by this name; keep it stable.
logger = logging.getLogger("pii_pipeline.http_api")
_MAX_REASON_DEPTH = 4


def safe_reason(error: BaseException) -> str:
    """Exception classes and fixed codes along the cause chain; never messages.

    Core errors hide causes with ``from None`` but keep them in __context__.
    """
    chain: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if len(chain) == _MAX_REASON_DEPTH:
            break
        seen.add(id(current))
        token = type(current).__name__
        code = getattr(current, "reason_code", None)
        if isinstance(code, str) and code.isidentifier():
            token += f":{code}"
        status = getattr(current, "status_code", None)
        if type(status) is int:
            token += f":http_{status}"
        # This package raises fixed messages only; never log external messages.
        message = str(current)
        if (
            type(current).__module__.startswith("pii_pipeline.")
            and message
            and len(message) <= 100
            and message.isascii()
            and message.isprintable()
        ):
            token += f'("{message}")'
        chain.append(token)
        current = current.__cause__ or current.__context__
    return " <- ".join(chain)


def _counts(items: dict[str, int]) -> str:
    return ",".join(f"{key}:{value}" for key, value in sorted(items.items())) or "-"


def _tokens(values) -> str:
    # Only identifier-like fixed codes reach the log.
    return "+".join(value for value in values if str(value).isidentifier()) or "none"


def residual_summary(events: list[dict]) -> str:
    """Last residual round: verifier finding types and recovery candidate shapes."""
    started = [e for e in events if e.get("event") == "RESIDUAL_RECOVERY_STARTED"]
    if not started:
        return "-"
    parts = [
        f"findings:{_tokens(started[-1].get('finding_types') or ())}",
        f"rules:{'yes' if started[-1].get('rules_found') else 'no'}",
    ]
    found = [e for e in events if e.get("event") == "RESIDUAL_CANDIDATES"]
    if found:
        last = found[-1]
        by_type = last.get("by_type") or {}
        parts += [
            f"candidates:{int(last.get('candidates', 0))}",
            "types:"
            + _tokens(f"{key}_{int(value)}" for key, value in sorted(by_type.items())),
            f"placeholder:{int(last.get('with_placeholder', 0))}",
            f"placeholder_parts:{int(last.get('placeholder_parts', 0))}",
            f"land_prefix_trimmed:{int(last.get('land_prefix_trimmed', 0))}",
            f"unmapped:{int(last.get('unmapped', 0))}",
            f"issues:{_tokens(last.get('issue_codes') or ())}",
        ]
    return ";".join(parts)


def attempt_summary(calls: Counter) -> str:
    """Seconds of each HTTP attempt in order, for tuning the read timeout.

    ``detection:142`` got HTTP 200 after 142 s; ``detection:timeout@300``,
    ``http_504@300``, ``error@`` and ``cut@`` (cancelled by the call
    deadline) did not.
    """
    parts = []
    for role, seconds, outcome in getattr(calls, "attempts", ()):
        shown = f"{seconds:.0f}" if outcome == "ok" else f"{outcome}@{seconds:.0f}"
        parts.append(f"{role}:{shown}")
    return ",".join(parts) or "-"


def repair_summary(calls: Counter) -> str:
    """Why initial windows were detected again: issue code -> repairs it caused.

    A repair counts each code of the attempt it repairs once. Residual-round
    windows are explained by the residual field instead.
    """
    prefix = "repair_reason:"
    reasons = {
        key[len(prefix) :]: value
        for key, value in calls.items()
        if key.startswith(prefix)
    }
    return _counts(reasons)


def selection_summary(calls: Counter) -> str:
    """Selection calls by kind and type, and repeated-value copies settled
    without the LLM (proposal 3.1)."""
    parts = []
    for kind in ("occurrence", "conflict"):
        count = calls.get(f"sel_{kind}", 0)
        if not count:
            continue
        prefix = f"sel_{kind}_type:"
        types = sorted(
            (key[len(prefix) :], value)
            for key, value in calls.items()
            if key.startswith(prefix)
        )
        parts.append(f"{kind}:{count}")
        parts.append(f"{kind}_types:{_tokens(f'{t}_{int(n)}' for t, n in types)}")
    settled = calls.get("sel_occurrence_settled", 0)
    if settled:
        parts.append(f"settled_without_llm:{settled}")
    return ";".join(parts) or "-"


def log_outcome(
    level: int,
    document_id: UUID,
    status_code: int,
    started: float,
    events: list[dict],
    calls: Counter,
    reason: str = "",
) -> None:
    # Progress events and call counts carry only names, counts and fixed codes.
    last = events[-1] if events else {}
    named = Counter(event.get("event") for event in events)
    blank = Counter(
        event.get("role")
        for event in events
        if event.get("event") == "BLANK_RESPONSE_RETRY"
    )
    llm = {key[4:]: value for key, value in calls.items() if key.startswith("llm_")}
    logger.log(
        level,
        "redact document_id=%s status=%d seconds=%.1f llm_calls=%d by_role=%s "
        "http_attempts=%d attempt_seconds=%s repairs=%d repair_reasons=%s "
        "blank_resends=%s "
        "verification_retries=%d "
        "residual_rounds=%d merge_selections=%d role_calls=%s recovery_calls=%s "
        "last_event=%s residual=%s selections=%s reason=%s",
        document_id,
        status_code,
        asyncio.get_running_loop().time() - started,
        sum(llm.values()),
        _counts(llm),
        calls.get("http_attempts", 0),
        attempt_summary(calls),
        sum(
            1
            for event in events
            if event.get("event") == "DETECTION_WINDOW_STARTED"
            and event.get("recovery")
        ),
        repair_summary(calls),
        _counts(blank),
        named["VERIFICATION_RETRY"],
        named["RESIDUAL_RECOVERY_STARTED"],
        named["CONFLICT_SELECTION_STARTED"],
        last.get("role_calls", 0),
        last.get("recovery_calls", 0),
        last.get("event", "-"),
        residual_summary(events),
        selection_summary(calls),
        reason or "-",
    )
