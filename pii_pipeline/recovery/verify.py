"""Independent LLM verification of redacted text, window by window."""

from ..core.verification import VerificationError
from ..llm.windows import (
    VerificationWindowResult,
    aggregate_verification_window_results,
    make_text_window,
)
from .replies import is_blank_verification_error, is_recoverable_verification_error


async def _verify_window(processor, window, window_number, budget):
    """Blank replies are re-sent; other recoverable failures get counted retries."""
    attempt, resends, recovery = 0, 0, False
    while True:
        budget.reserve(recovery)
        budget.emit(
            "VERIFICATION_WINDOW_STARTED",
            window_number=window_number,
            attempt=attempt + 1,
        )
        try:
            response = await processor.client.verify(
                window.text, prompt=processor.verification_prompt
            )
            # Validate this local result before any additional network request.
            aggregate_verification_window_results(
                window.text,
                [
                    VerificationWindowResult(
                        make_text_window(window.text, 0, len(window.text)), response
                    )
                ],
            )
        except Exception as error:  # noqa: BLE001 - never disclose verification failures.
            if not is_recoverable_verification_error(error):
                raise VerificationError("LLM verification unavailable") from None
            if is_blank_verification_error(error) and budget.can_resend_blank(resends):
                resends += 1
                recovery = False
                budget.emit(
                    "BLANK_RESPONSE_RETRY",
                    role="verification",
                    window_number=window_number,
                    attempt=attempt + 1,
                    retry=resends,
                )
                continue
            if (
                attempt == budget.policy.verification_retry_attempts
                or not budget.can_recover()
            ):
                raise VerificationError("LLM verification unavailable") from None
            budget.emit("VERIFICATION_RETRY", attempt=attempt + 1)
            attempt += 1
            recovery = True
        else:
            return VerificationWindowResult(window, response)


async def verify_redacted(processor, redacted, budget):
    """Aggregated verification response and the windows it inspected."""
    windows = processor._plan(redacted, processor.verification_window_planner)
    results = [
        await _verify_window(processor, window, window_number, budget)
        for window_number, window in enumerate(windows, 1)
    ]
    return aggregate_verification_window_results(redacted, results), windows
