import asyncio
import json
import ssl
import time
import unicodedata
from collections.abc import Awaitable, Callable
from itertools import pairwise
from types import TracebackType
from typing import Self

import httpx

from ..core.models import PiiMatch
from ..selection.conflicts import (
    build_conflict_options_schema,
    plan_conflict_options,
    resolve_conflict_options,
    split_initial_conflicts,
)
from ..selection.land import absorb_initial_land_numbers
from ..selection.occurrences import (
    plan_detection_occurrences,
    resolve_detection_occurrences,
    settle_occurrences,
)
from .call_stats import record as record_call
from .call_stats import record_attempt, record_selection, record_settled, role_of
from .config import LlmProxySettings
from .prompts import (
    build_conflict_selection_prompt,
    build_occurrence_selection_prompt,
)
from .proxy import (
    LlmProxyConfigurationError,
    LlmProxyRequestError,
    LlmProxyTimeoutError,
    LlmProxyTransportError,
    extract_http_structured_output,
    is_recoverable_proxy_error,
    is_retryable_status_code,
)
from .response import (
    DetectionIssue,
    DetectionOutcome,
    DetectionResponseError,
    VerificationResponse,
    parse_detection_candidates,
    parse_detection_outcome,
    parse_verification_response,
)
from .schema import (
    build_detection_response_schema,
    build_occurrence_selection_schema,
    build_verification_response_schema,
)


def _is_retryable_transport_error(error: httpx.TransportError) -> bool:
    """Retry transient transport errors, but never fatal TLS/certificate failures."""

    pending: list[BaseException] = [error]
    visited: set[int] = set()

    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))

        # WantRead/WantWrite are nonblocking I/O signals, not certificate failures.
        # Continue walking their chains so they cannot hide a fatal TLS error.
        if isinstance(current, ssl.SSLError) and not isinstance(
            current, (ssl.SSLWantReadError, ssl.SSLWantWriteError)
        ):
            return False

        for nested in (current.__cause__, current.__context__):
            if nested is not None:
                pending.append(nested)

    return isinstance(error, (httpx.TimeoutException, httpx.NetworkError))


def _build_tls_context(settings: LlmProxySettings) -> ssl.SSLContext:
    try:
        context = ssl.create_default_context()
        if settings.ca_bundle is not None:
            context.load_verify_locations(cafile=str(settings.ca_bundle))
    except (OSError, ssl.SSLError):
        raise LlmProxyConfigurationError(
            "LLM proxy TLS configuration is invalid"
        ) from None

    return context


class LlmProxyClient:
    """Async extraction-only proxy adapter; does not rewrite or deliver documents.

    Transport, clock and sleep injection are trusted test/composition boundaries.
    Use one client per application lifecycle and close it with ``async with`` or
    ``aclose()``. Prompts must come from trusted application configuration, not OCR.
    """

    def __init__(
        self,
        settings: LlmProxySettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._sleep = sleep

        if settings.tls_verify is False:
            tls_verification: bool | ssl.SSLContext = False
        else:
            tls_verification = _build_tls_context(settings)

        self._http = httpx.AsyncClient(
            verify=tls_verification,
            transport=transport,
            follow_redirects=False,
            trust_env=False,
        )

    async def __aenter__(self) -> Self:
        await self._http.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    def _remaining_seconds(self, deadline: float) -> float:
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise LlmProxyTimeoutError("LLM proxy request deadline exceeded") from None
        return remaining

    def _phase_timeouts(self, remaining: float) -> httpx.Timeout:
        return httpx.Timeout(
            connect=min(self._settings.connect_timeout_seconds, remaining),
            read=min(self._settings.read_timeout_seconds, remaining),
            write=min(self._settings.write_timeout_seconds, remaining),
            pool=min(self._settings.pool_timeout_seconds, remaining),
        )

    def _build_form(
        self,
        *,
        context: str,
        json_schema: dict[str, object],
        prompt: str,
        use_thinking: bool,
    ) -> dict[str, str]:
        if (
            not isinstance(context, str)
            or not context.strip()
            or not unicodedata.is_normalized("NFC", context)
            or not isinstance(json_schema, dict)
            or not isinstance(prompt, str)
            or not prompt.strip()
            or type(use_thinking) is not bool
        ):
            raise LlmProxyRequestError("LLM proxy request is invalid")

        try:
            schema_json = json.dumps(json_schema, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError, RecursionError):
            raise LlmProxyRequestError("LLM proxy request is invalid") from None

        return {
            "context": context,
            "json_schema": schema_json,
            "prompt": prompt,
            "model": self._settings.model,
            "use_thinking": str(use_thinking).lower(),
        }

    async def _send_once(
        self, form: dict[str, str], timeout: httpx.Timeout
    ) -> httpx.Response:
        async with self._http.stream(
            "POST",
            self._settings.structured_output_url,
            data=form,
            headers={
                "Authorization": f"Bearer {self._settings.api_key.get_secret_value()}",
                "Accept": "application/json",
            },
            timeout=timeout,
        ) as response:
            # Do not download error bodies; only successful responses need JSON.
            if response.status_code == 200:
                await response.aread()
            return response

    async def _request_with_retries(
        self, form: dict[str, str], deadline: float, role: str
    ) -> dict[str, object]:
        for attempt in range(self._settings.max_attempts):
            remaining = self._remaining_seconds(deadline)
            last_attempt = attempt == self._settings.max_attempts - 1

            record_call("http_attempts")
            started = self._clock()
            try:
                response = await self._send_once(form, self._phase_timeouts(remaining))
            except httpx.TransportError as error:
                timed_out = isinstance(error, httpx.TimeoutException)
                record_attempt(
                    role, self._clock() - started, "timeout" if timed_out else "error"
                )
                self._remaining_seconds(deadline)
                if last_attempt or not _is_retryable_transport_error(error):
                    raise LlmProxyTransportError(
                        "LLM proxy transport failed",
                        retryable=_is_retryable_transport_error(error),
                    ) from None
            except asyncio.CancelledError:
                record_attempt(role, self._clock() - started, "cut")
                raise
            except Exception:  # noqa: BLE001 - sanitize external transport failures.
                record_attempt(role, self._clock() - started, "error")
                # The transport boundary can raise arbitrary exceptions with PII.
                raise LlmProxyTransportError("LLM proxy transport failed") from None
            else:
                status = response.status_code
                outcome = "ok" if status == 200 else f"http_{status}"
                record_attempt(role, self._clock() - started, outcome)
                self._remaining_seconds(deadline)
                if last_attempt or not is_retryable_status_code(response.status_code):
                    output = extract_http_structured_output(
                        response, expected_model=self._settings.model
                    )
                    self._remaining_seconds(deadline)
                    return output

            delay = self._settings.retry_delays_seconds[attempt]
            if delay >= self._remaining_seconds(deadline):
                raise LlmProxyTimeoutError("LLM proxy request deadline exceeded")
            await self._sleep(delay)

        raise LlmProxyTransportError("LLM proxy transport failed")

    async def structured_output(
        self,
        *,
        context: str,
        json_schema: dict[str, object],
        prompt: str,
        use_thinking: bool,
    ) -> dict[str, object]:
        """Return a validated success envelope's payload, never a fallback value.

        This transport-level method does not replace a role-specific local parser.
        The deadline covers every network attempt, body read, JSON parse and backoff.
        External task cancellation remains cancellation, not a retryable failure.
        """

        form = self._build_form(
            context=context,
            json_schema=json_schema,
            prompt=prompt,
            use_thinking=use_thinking,
        )
        role = role_of(json_schema)
        record_call(f"llm_{role}")
        deadline = self._clock() + self._settings.request_deadline_seconds

        try:
            async with asyncio.timeout(self._settings.request_deadline_seconds):
                return await self._request_with_retries(form, deadline, role)
        except TimeoutError:
            raise LlmProxyTimeoutError("LLM proxy request deadline exceeded") from None

    async def detect(self, normalized_text: str, *, prompt: str) -> list[PiiMatch]:
        """Extract exact source spans; the caller performs deterministic redaction."""

        deadline = self._clock() + self._settings.request_deadline_seconds
        output = await self.structured_output(
            context=normalized_text,
            json_schema=build_detection_response_schema(),
            prompt=prompt,
            use_thinking=self._settings.detection_use_thinking,
        )
        candidates = parse_detection_candidates(normalized_text, output)
        plan = plan_detection_occurrences(normalized_text, candidates)
        return await self._resolve_plan(normalized_text, plan, deadline)

    async def _resolve_plan(self, normalized_text, plan, deadline) -> list[PiiMatch]:
        decisions = None
        if plan.occurrences:
            record_selection(
                "occurrence",
                [(item.allowed_types, item.value) for item in plan.occurrences],
            )
            remaining = self._remaining_seconds(deadline)
            try:
                async with asyncio.timeout(remaining):
                    decisions = await self.structured_output(
                        context=plan.context,
                        json_schema=build_occurrence_selection_schema(
                            tuple(item.occurrence_id for item in plan.occurrences)
                        ),
                        prompt=build_occurrence_selection_prompt(plan.marker_prefix),
                        use_thinking=self._settings.detection_use_thinking,
                    )
            except TimeoutError:
                raise LlmProxyTimeoutError(
                    "LLM proxy request deadline exceeded"
                ) from None
        matches = resolve_detection_occurrences(normalized_text, plan, decisions)
        self._remaining_seconds(deadline)
        return matches

    async def detect_outcome(
        self, normalized_text: str, *, prompt: str, rule_matches=None
    ) -> DetectionOutcome:
        """Internal recovery lane: exact matches plus issues, never clean fallback.

        ``rule_matches(text)`` finds the rule matches; it runs only after the
        reply and only when a value repeats. Copies a rule or the approved
        policy settles are not sent to the model for a choice.
        """
        deadline = self._clock() + self._settings.request_deadline_seconds
        output = await self.structured_output(
            context=normalized_text,
            json_schema=build_detection_response_schema(),
            prompt=prompt,
            use_thinking=self._settings.detection_use_thinking,
        )
        parsed = parse_detection_outcome(normalized_text, output)
        plan = plan_detection_occurrences(normalized_text, list(parsed.candidates))
        if plan.occurrences:
            known = rule_matches(normalized_text) if rule_matches else ()
            plan, settled = settle_occurrences(normalized_text, plan, known)
            record_settled(settled)
        split = split_initial_conflicts(plan)
        if split is not None:
            split = absorb_initial_land_numbers(plan, split)
        try:
            if split is None:
                matches = await self._resolve_plan(normalized_text, plan, deadline)
            elif not split.alternatives:
                matches = list(split.kept)
            else:
                matches = await self._select_initial_conflicts(
                    normalized_text, split, deadline
                )
        except Exception as error:
            if isinstance(error, DetectionResponseError):
                issue = DetectionIssue(error.reason_code)
            elif is_recoverable_proxy_error(error):
                issue = DetectionIssue("selection_unavailable")
            else:
                raise
            # Unselected repeated occurrences are never replaced by equality, and
            # unresolved overlapping alternatives are not retained.
            retained = plan.direct_matches if split is None else split.kept
            return DetectionOutcome(retained, (*parsed.issues, issue))
        return DetectionOutcome(tuple(matches), parsed.issues)

    async def _select_initial_conflicts(self, normalized_text, split, deadline):
        """One legal-option selection replaces independent ID/type votes."""
        kept, alternatives = split
        remaining = self._remaining_seconds(deadline)
        try:
            async with asyncio.timeout(remaining):
                selected = await self.select_matches(normalized_text, alternatives)
        except TimeoutError:
            raise LlmProxyTimeoutError("LLM proxy request deadline exceeded") from None
        self._remaining_seconds(deadline)
        matches = sorted(
            [*kept, *selected],
            key=lambda match: (match.start, match.end, match.pii_type),
        )
        if any(right.start < left.end for left, right in pairwise(matches)):
            raise DetectionResponseError(
                "LLM detection response is invalid", reason_code="overlapping_matches"
            )
        return matches

    async def select_matches(self, normalized_text, matches, *, required_matches=()):
        plan = plan_conflict_options(normalized_text, matches, required_matches)
        record_selection("conflict", [((m.pii_type,), m.value) for m in matches])
        output = await self.structured_output(
            context=plan.context,
            json_schema=build_conflict_options_schema(plan),
            prompt=build_conflict_selection_prompt(plan.occurrences.marker_prefix),
            use_thinking=self._settings.detection_use_thinking,
        )
        return resolve_conflict_options(normalized_text, plan, output, required_matches)

    async def verify(
        self, normalized_redacted_text: str, *, prompt: str
    ) -> VerificationResponse:
        """Inspect only redacted text and reject responses that echo PII values."""

        deadline = self._clock() + self._settings.request_deadline_seconds
        output = await self.structured_output(
            context=normalized_redacted_text,
            json_schema=build_verification_response_schema(),
            prompt=prompt,
            use_thinking=self._settings.verification_use_thinking,
        )
        response = parse_verification_response(normalized_redacted_text, output)
        self._remaining_seconds(deadline)
        return response
