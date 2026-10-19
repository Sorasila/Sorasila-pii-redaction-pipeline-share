"""A stand-in LLM client for tests that only care about what the LLM returns.

``detect(text)`` returns the PiiMatch list the model "found" in a window;
``verify(text)`` returns whether residual PII is "seen" in redacted text.
Both may be plain or async functions and may raise to simulate failures.
"""

from inspect import isawaitable

from pii_pipeline.llm.processing import LlmDocumentProcessor
from pii_pipeline.llm.response import (
    DetectionOutcome,
    VerificationFinding,
    VerificationResponse,
)
from pii_pipeline.llm.windows import make_text_window
from pii_pipeline.recovery.process import (
    RecoveryPolicy,
    process_markdown_with_recovery_async,
)
from pii_pipeline.rules.thai import detect_thai_rule_pii
from pii_pipeline.verification import make_detection_checker


async def _call(function, text):
    result = function(text)
    return await result if isawaitable(result) else result


def no_pii(text):
    return []


def clean(text):
    return False


class FakeLlmClient:
    def __init__(self, detect=no_pii, verify=clean):
        self._detect = detect
        self._verify = verify

    async def detect_outcome(self, text, *, prompt, rule_matches=None):
        return DetectionOutcome(tuple(await _call(self._detect, text)), ())

    async def verify(self, text, *, prompt):
        has_pii = await _call(self._verify, text)
        if has_pii is not True and has_pii is not False:
            raise TypeError("fake verification must return a bool")
        findings = (
            (VerificationFinding("NAME", 0, len(text), "window"),) if has_pii else ()
        )
        return VerificationResponse(has_pii, findings)


def whole(text):
    return [make_text_window(text, 0, len(text))]


def fake_processor(detect=no_pii, verify=clean):
    return LlmDocumentProcessor(FakeLlmClient(detect, verify), whole, whole)


def no_rules(source):
    return []


def no_rule_residual(source):
    return False


async def run_recovery(
    source,
    detect=no_pii,
    verify=clean,
    *,
    rule_detectors=None,
    rules_has_pii=None,
    policy=None,
    progress=None,
):
    """The service's recovery pipeline with the fake LLM (Thai rules by default)."""
    rules = rule_detectors or (detect_thai_rule_pii,)
    return await process_markdown_with_recovery_async(
        source,
        fake_processor(detect, verify),
        rule_detectors=rules,
        rules_has_pii=rules_has_pii or make_detection_checker(list(rules)),
        policy=policy or RecoveryPolicy(),
        progress=progress,
    )
