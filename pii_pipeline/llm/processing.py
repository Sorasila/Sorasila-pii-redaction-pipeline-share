import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from inspect import iscoroutine, iscoroutinefunction
from typing import Protocol

from .prompts import build_detection_prompt, build_verification_prompt
from .response import DetectionOutcome, VerificationResponse
from .windows import (
    TextWindow,
    WindowContractError,
    validate_text_windows,
)

WindowPlanner = Callable[[str], list[TextWindow]]


class LlmWindowClient(Protocol):
    async def detect_outcome(
        self, normalized_text: str, *, prompt: str, rule_matches=None
    ) -> DetectionOutcome: ...

    async def verify(
        self, normalized_redacted_text: str, *, prompt: str
    ) -> VerificationResponse: ...


@dataclass(frozen=True, slots=True)
class LlmDocumentProcessor:
    """The LLM client, trusted window planners and prompts for one service.

    No token/window size is guessed. Verification planning uses the final redacted
    source, not original-source offsets. The recovery pipeline drives the calls.
    Client ownership remains with the caller; this object does not close it.
    """

    client: LlmWindowClient = field(repr=False)
    detection_window_planner: WindowPlanner = field(repr=False)
    verification_window_planner: WindowPlanner = field(repr=False)
    detection_prompt: str = field(default_factory=build_detection_prompt, repr=False)
    verification_prompt: str = field(
        default_factory=build_verification_prompt, repr=False
    )

    def __post_init__(self) -> None:
        planners = (self.detection_window_planner, self.verification_window_planner)
        if (
            not all(callable(planner) for planner in planners)
            or any(
                iscoroutinefunction(planner)
                or iscoroutinefunction(type(planner).__call__)
                for planner in planners
            )
            or not callable(getattr(self.client, "detect_outcome", None))
            or not callable(getattr(self.client, "verify", None))
            or any(
                not isinstance(prompt, str) or not prompt.strip()
                for prompt in (self.detection_prompt, self.verification_prompt)
            )
        ):
            raise WindowContractError("LLM document configuration is invalid")

    def _plan(self, source: str, planner: WindowPlanner) -> tuple[TextWindow, ...]:
        if not isinstance(source, str) or not unicodedata.is_normalized("NFC", source):
            raise WindowContractError("LLM window source is invalid")

        try:
            planned_windows = planner(source)
        except Exception:  # noqa: BLE001 - planner errors may contain document data.
            raise WindowContractError("LLM window planning failed") from None

        if iscoroutine(planned_windows):
            planned_windows.close()

        return validate_text_windows(source, planned_windows)
