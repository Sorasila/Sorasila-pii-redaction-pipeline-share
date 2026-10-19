import asyncio
import json
from urllib.parse import parse_qs

import httpx
import pytest

from pii_pipeline.core.detection import DetectionError
from pii_pipeline.core.models import PiiMatch
from pii_pipeline.core.verification import VerificationError
from pii_pipeline.llm.client import LlmProxyClient
from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm.processing import LlmDocumentProcessor
from pii_pipeline.llm.response import (
    DetectionResponseError,
    parse_detection_candidates,
    parse_detection_outcome,
)
from pii_pipeline.llm.windows import make_text_window
from pii_pipeline.recovery.process import (
    RecoveryLimitError,
    RecoveryMergeError,
    RecoveryPolicy,
    process_markdown_with_recovery_async,
)


@pytest.fixture(autouse=True)
def isolate_settings(monkeypatch):
    for name in list(__import__("os").environ):
        if name.startswith("LLM_PROXY_"):
            monkeypatch.delenv(name)


def settings():
    return LlmProxySettings(
        base_url="https://proxy.example",
        api_key="synthetic-key",
        max_retries=0,
        _env_file=None,
    )


def success(output):
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": LLM_PROXY_MODEL,
            "structured_output": output,
        },
    )


def candidates(*items):
    return success(
        {"candidates": [{"pii_type": kind, "value": value} for kind, value in items]}
    )


def verification(has_pii=False):
    return success(
        {"has_pii": has_pii, "findings": [{"pii_type": "NAME"}] if has_pii else []}
    )


def form(request):
    data = parse_qs(request.content.decode())
    role = next(iter(json.loads(data["json_schema"][0])["properties"]))
    return role, data["context"][0], data["prompt"][0]


def whole(source):
    return [make_text_window(source, 0, len(source))]


def no_rules(source):
    return []


def clean_rules(source):
    return False


async def run(
    source,
    handler,
    *,
    policy=None,
    planner=whole,
    rules=no_rules,
    checker=clean_rules,
    events=None,
):
    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        processor = LlmDocumentProcessor(client, planner, whole)
        return await process_markdown_with_recovery_async(
            source,
            processor,
            rule_detectors=(rules,),
            rules_has_pii=checker,
            policy=policy or RecoveryPolicy(),
            progress=None if events is None else events.append,
        )


def test_outcome_keeps_good_candidates_on_both_sides_of_bad_one():
    payload = {
        "candidates": [
            {"pii_type": "NAME", "value": "Alice"},
            {"pii_type": "NAME", "value": "Invented Private Value"},
            {"pii_type": "NAME", "value": "Bob"},
        ]
    }
    outcome = parse_detection_outcome("Alice / Bob", payload)
    assert [item.value for item in outcome.candidates] == ["Alice", "Bob"]
    assert [(issue.reason_code, issue.candidate_index) for issue in outcome.issues] == [
        ("value_not_found", 2)
    ]
    assert "Private" not in repr(outcome) and "Alice" not in repr(outcome)
    with pytest.raises(DetectionResponseError):
        parse_detection_candidates("Alice / Bob", payload)


@pytest.mark.asyncio
async def test_copy_error_repair_preserves_valid_results_and_rules_run_after_llm():
    calls, events, order = [], [], []

    def handler(request):
        role, source, prompt = form(request)
        calls.append((role, source, prompt))
        order.append(role)
        if role == "candidates":
            assert source == "Name Alice phone 123"
            if len(calls) == 1:
                return candidates(("PHONE", "123"), ("NAME", "Alicee"))
            assert "Trusted recovery instruction" in prompt
            return candidates(("NAME", "Alice"))
        assert source == "Name [PII_NAME_1] phone [PII_PHONE_1]"
        return verification()

    def rules(source):
        order.append("rules")
        assert source == "Name Alice phone 123"
        return [PiiMatch("PHONE", "123", 17, 20)]

    result = await run("Name Alice phone 123", handler, rules=rules, events=events)
    assert [(entry.placeholder, entry.original_value) for entry in result.entries] == [
        ("[PII_NAME_1]", "Alice"),
        ("[PII_PHONE_1]", "123"),
    ]
    assert order == ["candidates", "candidates", "rules", "has_pii"]
    assert events[-1]["recovery_calls"] == 1
    assert "Alice" not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "504", "shape"])
async def test_first_detection_failure_is_repaired(failure):
    roles = []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if len(roles) == 1:
            if failure == "timeout":
                raise httpx.ReadTimeout("Synthetic sensitive exception")
            if failure == "504":
                return httpx.Response(504, text="Synthetic sensitive body")
            return success({"wrong": "Synthetic sensitive body"})
        return candidates(("NAME", "Alice")) if role == "candidates" else verification()

    assert (await run("Name Alice", handler)).redacted_markdown == "Name [PII_NAME_1]"
    assert roles == ["candidates", "candidates", "has_pii"]


@pytest.mark.asyncio
async def test_successful_windows_not_repeated_when_another_window_needs_repair():
    contexts = []

    def planner(source):
        return [
            make_text_window(source, 0, 6),
            make_text_window(source, 6, len(source)),
        ]

    def handler(request):
        role, source, _ = form(request)
        if role != "candidates":
            return verification()
        contexts.append(source)
        value = (
            "Alice"
            if source == "Alice "
            else "Bobb"
            if contexts.count(source) == 1
            else "Bob"
        )
        return candidates(("NAME", value))

    result = await run("Alice Bob", handler, planner=planner)
    assert contexts == ["Alice ", "Bob", "Bob"]
    assert result.redacted_markdown == "[PII_NAME_1] [PII_NAME_2]"


@pytest.mark.asyncio
async def test_unresolved_extraction_is_only_cleared_by_fresh_full_verification():
    roles, events = [], []

    def handler(request):
        role, source, _ = form(request)
        roles.append(role)
        if role == "candidates":
            return candidates(("NAME", "Invented"))
        assert source == "Public information"
        return verification()

    result = await run("Public information", handler, events=events)
    assert result.entries == () and result.redacted_markdown == "Public information"
    # Default policy: the initial extraction plus two window repairs.
    assert roles == ["candidates", "candidates", "candidates", "has_pii"]
    assert events[-1]["preliminary_issue_windows"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source,initial,repaired",
    [
        ("Alice Smith", ("NAME", "Alice"), ("NAME", "Alice Smith")),
        ("Alice Smith", ("NAME", "Alice Smith"), ("NAME", "Alice")),
        ("Alice Smith", ("NAME", "Alice Smith"), ("ORGANIZATION", "Alice Smith")),
        (
            "Alpha Beta Gamma Delta",
            ("NAME", "Beta Gamma"),
            ("NAME", "Gamma Delta"),
        ),
    ],
)
async def test_repair_span_conflict_is_distinguished_from_remaining_value_issue(
    source, initial, repaired
):
    roles, events = [], []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        assert role == "candidates"
        if len(roles) == 1:
            return candidates(initial, ("NAME", "Absent One"), ("NAME", "Absent Two"))
        return candidates(repaired, ("NAME", "Absent Three"))

    with pytest.raises(RecoveryMergeError) as caught:
        await run(
            source,
            handler,
            events=events,
            policy=RecoveryPolicy(conflict_selection_attempts=0),
        )
    assert caught.value.reason_code == "source_span_conflict"
    assert roles == ["candidates", "candidates"]
    outcome = next(
        event for event in events if event["event"] == "DETECTION_WINDOW_OUTCOME"
    )
    assert outcome["issue_count"] == 2 and outcome["valid_matches"] == 1
    assert events[-1] == {
        "event": "DETECTION_WINDOW_REJECTED",
        "role_calls": 2,
        "recovery_calls": 1,
        "window_number": 1,
        "attempt": 2,
        "recovery": True,
        "reason_code": "source_span_conflict",
        "retained_matches": 1,
        "incoming_matches": 1,
    }
    diagnostics = json.dumps(events) + str(caught.value) + repr(caught.value)
    for private in (source, initial[1], repaired[1], "Absent"):
        assert private not in diagnostics


@pytest.mark.asyncio
async def test_duplicate_repair_match_with_remaining_issue_reaches_final_verification():
    roles, events = [], []

    def handler(request):
        role, source, _ = form(request)
        roles.append(role)
        if role == "candidates":
            missing = [("NAME", "Absent One"), ("NAME", "Absent Two")]
            if len(roles) == 2:
                missing = [("NAME", "Absent Three")]
            return candidates(("NAME", "Alice Smith"), *missing)
        assert source == "[PII_NAME_1]"
        return verification()

    result = await run("Alice Smith", handler, events=events)
    assert len(result.entries) == 1
    assert result.entries[0].original_value == "Alice Smith"
    assert roles == ["candidates", "candidates", "candidates", "has_pii"]
    outcomes = [
        event for event in events if event["event"] == "DETECTION_WINDOW_OUTCOME"
    ]
    assert [event["issue_count"] for event in outcomes] == [2, 1, 2]
    assert [event["valid_matches"] for event in outcomes] == [1, 1, 1]
    assert events[-1]["event"] == "FINAL_VERIFIED"
    assert events[-1]["preliminary_issue_windows"] == 1


def test_merge_reason_cannot_carry_arbitrary_private_text():
    with pytest.raises(ValueError) as caught:
        RecoveryMergeError("Synthetic private source detail")
    assert "private" not in str(caught.value) + repr(caught.value)


@pytest.mark.asyncio
async def test_residual_repair_maps_back_to_original_and_rebuilds_counters():
    calls, events = [], []

    def handler(request):
        role, source, _ = form(request)
        calls.append((role, source))
        if role == "candidates":
            return candidates(("NAME", "Alice" if len(calls) == 1 else "Bob"))
        return verification("Bob" in source)

    result = await run("Bob / Alice", handler, events=events)
    assert result.redacted_markdown == "[PII_NAME_1] / [PII_NAME_2]"
    assert [entry.original_value for entry in result.entries] == ["Bob", "Alice"]
    assert calls == [
        ("candidates", "Bob / Alice"),
        ("has_pii", "Bob / [PII_NAME_1]"),
        ("candidates", "Bob / [PII_NAME_1]"),
        ("has_pii", "[PII_NAME_1] / [PII_NAME_2]"),
    ]
    assert events[-1]["residual_rounds"] == 1


@pytest.mark.asyncio
async def test_equal_non_pii_occurrence_is_preserved():
    def handler(request):
        role, source, _ = form(request)
        if role == "candidates":
            return candidates(("DATE_OF_BIRTH", "01/01/2000"))
        if role == "decisions":
            return success(
                {
                    "decisions": [
                        {"occurrence_id": 1, "pii_type": "DATE_OF_BIRTH"},
                        {"occurrence_id": 2, "pii_type": "NOT_PII"},
                    ]
                }
            )
        assert source == "Born [PII_DATE_OF_BIRTH_1]; document date 01/01/2000"
        return verification()

    result = await run("Born 01/01/2000; document date 01/01/2000", handler)
    assert len(result.entries) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "invalid"])
async def test_verification_retry_is_bounded_and_never_becomes_clean_empty(failure):
    roles = []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates":
            return candidates(("NAME", "Alice"))
        if failure == "timeout":
            raise httpx.ReadTimeout("Synthetic confidential exception")
        return success({"has_pii": False, "findings": [{"pii_type": "NAME"}]})

    with pytest.raises(VerificationError) as caught:
        await run("Alice", handler)
    assert "confidential" not in str(caught.value)
    assert roles == ["candidates", "has_pii", "has_pii"]


@pytest.mark.asyncio
async def test_verification_timeout_then_success():
    roles = []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates":
            return candidates(("NAME", "Alice"))
        if roles.count("has_pii") == 1:
            raise httpx.ReadTimeout("Synthetic failure")
        return verification()

    assert (await run("Alice", handler)).entries[0].original_value == "Alice"
    assert roles == ["candidates", "has_pii", "has_pii"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [401, 403, 404, "model", "unknown", "tls"])
async def test_fatal_errors_do_not_enter_recovery(failure):
    count = 0

    def handler(request):
        nonlocal count
        count += 1
        if isinstance(failure, int):
            return httpx.Response(failure)
        if failure == "model":
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "model": "wrong",
                    "structured_output": {"candidates": []},
                },
            )
        if failure == "tls":
            import ssl

            try:
                raise ssl.SSLCertVerificationError("Synthetic private TLS detail")
            except ssl.SSLError as error:
                raise httpx.ConnectError("Synthetic private exception") from error
        raise RuntimeError("Synthetic private exception")

    with pytest.raises(DetectionError):
        await run("Alice", handler)
    assert count == 1


@pytest.mark.asyncio
async def test_residual_without_progress_cannot_return_partial_output():
    roles = []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        return candidates() if role == "candidates" else verification(True)

    with pytest.raises(VerificationError, match="no progress"):
        await run("Alice", handler)
    assert roles == ["candidates", "has_pii", "candidates"]


@pytest.mark.asyncio
async def test_repair_cannot_replace_a_placeholder_or_span_across_it():
    count = 0

    def handler(request):
        nonlocal count
        count += 1
        role, _, _ = form(request)
        if role != "candidates":
            return verification(True)
        return candidates(("NAME", "Alice" if count == 1 else "[PII_NAME_1]"))

    with pytest.raises(DetectionError, match="protected"):
        await run("Alice Bob", handler)


@pytest.mark.asyncio
async def test_role_cap_prevents_final_success_without_verification():
    count = 0

    def handler(request):
        nonlocal count
        count += 1
        return candidates(("NAME", "Alice"))

    with pytest.raises(RecoveryLimitError):
        await run("Alice", handler, policy=RecoveryPolicy(max_role_calls=1))
    assert count == 1


@pytest.mark.asyncio
async def test_deadline_and_external_cancellation_propagate_without_recovery():
    async def handler(request):
        await asyncio.sleep(1)
        return candidates()

    with pytest.raises(TimeoutError):
        await run("Alice", handler, policy=RecoveryPolicy(deadline_seconds=0.01))
    task = asyncio.create_task(run("Alice", handler))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize(
    "changes",
    [
        {"max_recovery_calls": -1},
        {"window_repair_attempts": True},
        {"max_residual_rounds": 3},
        {"blank_response_retries": 6},
        {"blank_response_retries": True},
        {"deadline_seconds": float("nan")},
        {"max_role_calls": 0},
        {"reserved_recovery_calls": -1},
        {"reserved_recovery_calls": 5},
        {"max_recovery_calls": 1, "reserved_recovery_calls": 2},
        {"reserved_recovery_calls": True},
    ],
)
def test_invalid_policy(changes):
    with pytest.raises(ValueError):
        RecoveryPolicy(**changes)


@pytest.mark.asyncio
async def test_detection_outage_is_not_clean_until_entire_final_text_is_inspected():
    roles = []

    def handler(request):
        role, source, _ = form(request)
        roles.append(role)
        if role == "candidates":
            raise httpx.ReadTimeout("Synthetic error")
        assert source == "Public information"
        return verification()

    result = await run("Public information", handler)
    assert result.entries == ()
    assert roles == ["candidates", "candidates", "candidates", "has_pii"]


@pytest.mark.asyncio
async def test_rule_residual_blocks_success_even_when_llm_says_clean():
    def handler(request):
        role, _, _ = form(request)
        return candidates() if role == "candidates" else verification()

    with pytest.raises(VerificationError):
        await run("Public information", handler, checker=lambda source: True)


@pytest.mark.asyncio
async def test_persistent_residual_stops_at_round_limit():
    roles = []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates":
            return candidates(("NAME", "Alice" if len(roles) == 1 else "Bob"))
        return verification(True)

    with pytest.raises(VerificationError, match="bounded recovery"):
        await run("Alice Bob", handler)
    assert roles == ["candidates", "has_pii", "candidates", "has_pii"]


@pytest.mark.asyncio
async def test_global_role_budget_does_not_reset_after_residual_repair():
    count = 0

    def handler(request):
        nonlocal count
        count += 1
        role, _, _ = form(request)
        return (
            candidates(("NAME", "Alice" if count == 1 else "Bob"))
            if role == "candidates"
            else verification(True)
        )

    with pytest.raises(RecoveryLimitError):
        await run("Alice Bob", handler, policy=RecoveryPolicy(max_role_calls=3))
    assert count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("selection_failure", ["shape", "timeout"])
async def test_selection_failure_retains_direct_matches_without_selecting_repeats(
    selection_failure,
):
    def handler(request):
        role, _, _ = form(request)
        if role == "candidates":
            return candidates(("NAME", "Alice"), ("DATE_OF_BIRTH", "2000"))
        if selection_failure == "timeout":
            raise httpx.ReadTimeout("Synthetic error")
        return success({"decisions": []})

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        outcome = await client.detect_outcome(
            "Alice 2000 2000", prompt="Extract exact PII"
        )
    assert [item.value for item in outcome.matches] == ["Alice"]
    assert outcome.issues


@pytest.mark.asyncio
async def test_invalid_final_coverage_never_reaches_verifier():
    roles = []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        return candidates(("NAME", "Alice"))

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(handler)
    ) as client:
        processor = LlmDocumentProcessor(
            client, whole, lambda source: [make_text_window(source, 1, len(source))]
        )
        with pytest.raises(ValueError, match="cover"):
            await process_markdown_with_recovery_async(
                "Alice",
                processor,
                rule_detectors=(no_rules,),
                rules_has_pii=clean_rules,
                policy=RecoveryPolicy(),
            )
    assert roles == ["candidates"]


def test_default_policy_allows_two_window_repairs():
    # Approved 2026-10-06: fast empty/failed generations are cheap to retry.
    assert RecoveryPolicy().window_repair_attempts == 2


def blank():
    # Seen live: a "success" envelope whose output ignores the schema.
    return success({"extracted_text": ""})


def failed_generation():
    return httpx.Response(200, json={"status": "error", "model": LLM_PROXY_MODEL})


def final_event(events):
    assert events[-1]["event"] == "FINAL_VERIFIED"
    return events[-1]


@pytest.mark.asyncio
@pytest.mark.parametrize("first_reply", [blank, failed_generation])
async def test_blank_detection_reply_is_resent_without_spending_recovery(first_reply):
    roles, events = [], []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates" and len(roles) == 1:
            return first_reply()
        if role == "candidates":
            return candidates(("NAME", "Alice Smith"))
        return verification()

    result = await run("Alice Smith", handler, events=events)
    assert result.redacted_markdown == "[PII_NAME_1]"
    assert roles == ["candidates", "candidates", "has_pii"]
    retries = [e for e in events if e["event"] == "BLANK_RESPONSE_RETRY"]
    assert [(e["role"], e["retry"]) for e in retries] == [("detection", 1)]
    outcomes = [e for e in events if e["event"] == "DETECTION_WINDOW_OUTCOME"]
    assert [e["issue_count"] for e in outcomes] == [0]
    assert final_event(events)["recovery_calls"] == 0
    assert final_event(events)["role_calls"] == 3


@pytest.mark.asyncio
async def test_blank_retries_are_bounded_per_window_then_repairs_continue():
    roles, events = [], []

    def handler(request):
        role, source, _ = form(request)
        roles.append(role)
        if role == "candidates":
            return blank()
        assert source == "Public information"
        return verification()

    result = await run("Public information", handler, events=events)
    assert result.entries == ()
    # Initial call + 3 blank resends, then the two counted repairs.
    assert roles == ["candidates"] * 6 + ["has_pii"]
    retries = [e for e in events if e["event"] == "BLANK_RESPONSE_RETRY"]
    assert [e["retry"] for e in retries] == [1, 2, 3]
    assert final_event(events)["recovery_calls"] == 2
    assert final_event(events)["preliminary_issue_windows"] == 1


@pytest.mark.asyncio
async def test_blank_verification_reply_is_resent_without_spending_recovery():
    roles, events = [], []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates":
            return candidates(("NAME", "Alice Smith"))
        if roles.count("has_pii") == 1:
            return blank()
        return verification()

    result = await run("Alice Smith", handler, events=events)
    assert result.redacted_markdown == "[PII_NAME_1]"
    assert roles == ["candidates", "has_pii", "has_pii"]
    retries = [e for e in events if e["event"] == "BLANK_RESPONSE_RETRY"]
    assert [(e["role"], e["retry"]) for e in retries] == [("verification", 1)]
    assert final_event(events)["recovery_calls"] == 0


@pytest.mark.asyncio
async def test_blank_retries_can_be_disabled_and_respect_the_role_call_cap():
    roles = []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates" and len(roles) == 1:
            return blank()
        if role == "candidates":
            return candidates(("NAME", "Alice Smith"))
        return verification()

    await run("Alice Smith", handler, policy=RecoveryPolicy(blank_response_retries=0))
    # Without blank resends the counted repair handles it, as before.
    assert roles == ["candidates", "candidates", "has_pii"]

    roles.clear()

    def always_blank(request):
        roles.append(form(request)[0])
        return blank()

    with pytest.raises((RecoveryLimitError, VerificationError)):
        await run(
            "Alice Smith",
            always_blank,
            policy=RecoveryPolicy(max_role_calls=3, window_repair_attempts=0),
        )
    assert len(roles) <= 3


@pytest.mark.asyncio
async def test_slow_failures_are_not_resent_as_blank_replies():
    roles, events = [], []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates":
            raise httpx.ReadTimeout("Synthetic error")
        return verification()

    await run("Public information", handler, events=events)
    assert not [e for e in events if e["event"] == "BLANK_RESPONSE_RETRY"]


# Approved 2026-10-12: a land document number followed by the land's location is
# one ADDRESS value; the 'น.ส. 3 ก. เลขที่' label stays outside.
LAND_SOURCE = "ที่ดินตาม น.ส. 3 ก. เลขที่ 123 ตำบลทดสอบ อำเภอสมมุติ จังหวัดตัวอย่าง ต่อมา"
LAND_LOCATION = "ตำบลทดสอบ อำเภอสมมุติ จังหวัดตัวอย่าง"
LAND_REDACTED = "ที่ดินตาม น.ส. 3 ก. เลขที่ [PII_ADDRESS_1] ต่อมา"
# One level only: the land-location rule does not apply, so the LLM must
# find it (used to exercise the residual round).
ONE_LEVEL = "ตำบลทดสอบ"
ONE_LEVEL_SOURCE = f"ที่ดินตาม น.ส. 3 ก. เลขที่ 123 {ONE_LEVEL} ต่อมา"


def land_rules():
    from pii_pipeline.core.verification import make_detection_checker
    from pii_pipeline.rules.thai import detect_thai_rule_pii

    return detect_thai_rule_pii, make_detection_checker([detect_thai_rule_pii])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "llm_values",
    [
        # One ADDRESS that already contains the rule-detected number.
        [("ADDRESS", f"123 {LAND_LOCATION}")],
        # The model splits them; the service joins number and location.
        [("ADDRESS", LAND_LOCATION)],
        [("TITLE_DEED_NUMBER", "123"), ("ADDRESS", LAND_LOCATION)],
    ],
)
async def test_land_number_and_its_location_become_one_address(llm_values):
    rules, checker = land_rules()

    def handler(request):
        role, _, _ = form(request)
        if role == "candidates":
            return candidates(*llm_values)
        return verification()

    result = await run(LAND_SOURCE, handler, rules=rules, checker=checker)
    assert result.redacted_markdown == LAND_REDACTED
    assert [(e.pii_type, e.original_value) for e in result.entries] == [
        ("ADDRESS", f"123 {LAND_LOCATION}")
    ]


@pytest.mark.asyncio
async def test_land_number_inside_the_models_own_address_needs_no_selection():
    rules, checker = land_rules()
    roles, events = [], []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates":
            return candidates(
                ("TITLE_DEED_NUMBER", "123"), ("ADDRESS", f"123 {LAND_LOCATION}")
            )
        return verification()

    result = await run(
        LAND_SOURCE, handler, rules=rules, checker=checker, events=events
    )
    assert result.redacted_markdown == LAND_REDACTED
    assert roles == ["candidates", "has_pii"]
    assert final_event(events)["conflict_selection_calls"] == 0


@pytest.mark.asyncio
async def test_land_number_absorbed_when_a_repair_returns_the_whole_address():
    # Attempt 1 keeps the number; the repair's ADDRESS contains it.
    rules, checker = land_rules()
    roles, events = [], []

    def handler(request):
        role, _, _ = form(request)
        roles.append(role)
        if role == "candidates" and roles.count(role) == 1:
            return candidates(("TITLE_DEED_NUMBER", "123"), ("NAME", "Invented"))
        if role == "candidates":
            return candidates(("ADDRESS", f"123 {LAND_LOCATION}"))
        return verification()

    result = await run(
        LAND_SOURCE, handler, rules=rules, checker=checker, events=events
    )
    assert result.redacted_markdown == LAND_REDACTED
    assert roles == ["candidates", "candidates", "has_pii"]
    absorbed = [e for e in events if e["event"] == "LAND_NUMBERS_ABSORBED"]
    # The rule now yields the same number + location ADDRESS, so the document
    # merge has nothing left to absorb (approved 2026-10-15).
    assert [(e["scope"], e["count"]) for e in absorbed] == [("window", 1)]
    assert final_event(events)["conflict_selection_calls"] == 0


def residual_land_wire(roles, residual_value):
    """First pass misses the location; the residual pass reads the placeholder."""

    def handler(request):
        role, context, _ = form(request)
        roles.append(role)
        if role == "candidates" and "[PII_" not in context:
            return candidates()
        if role == "candidates":
            return candidates(("ADDRESS", residual_value))
        return verification(roles.count("has_pii") == 1)

    return handler


@pytest.mark.asyncio
async def test_residual_address_starting_with_a_land_placeholder_keeps_the_location():
    # Approved 2026-10-12: the placeholder is cut and the join reunites them.
    rules, checker = land_rules()
    roles, events = [], []
    handler = residual_land_wire(roles, f"[PII_TITLE_DEED_NUMBER_1] {ONE_LEVEL}")
    result = await run(
        ONE_LEVEL_SOURCE, handler, rules=rules, checker=checker, events=events
    )
    assert result.redacted_markdown == LAND_REDACTED
    assert [(e.pii_type, e.original_value) for e in result.entries] == [
        ("ADDRESS", f"123 {ONE_LEVEL}")
    ]
    assert roles == ["candidates", "has_pii", "candidates", "has_pii"]
    (started,) = [e for e in events if e["event"] == "RESIDUAL_RECOVERY_STARTED"]
    assert started["finding_types"] == ["NAME"] and started["rules_found"] is False
    (shape,) = [e for e in events if e["event"] == "RESIDUAL_CANDIDATES"]
    assert shape["candidates"] == 1 and shape["by_type"] == {"ADDRESS": 1}
    assert shape["land_prefix_trimmed"] == 1
    assert shape["with_placeholder"] == 0 and shape["unmapped"] == 0
    assert ONE_LEVEL not in json.dumps(events, ensure_ascii=False)


@pytest.mark.asyncio
async def test_residual_value_still_crossing_a_placeholder_fails_closed_with_its_shape():
    rules, checker = land_rules()
    roles, events = [], []
    handler = residual_land_wire(roles, f"เลขที่ [PII_TITLE_DEED_NUMBER_1] {ONE_LEVEL}")
    with pytest.raises(DetectionError, match="protected replacement"):
        await run(
            ONE_LEVEL_SOURCE, handler, rules=rules, checker=checker, events=events
        )
    shape = events[-1]
    assert shape["event"] == "RESIDUAL_CANDIDATES"
    assert shape["land_prefix_trimmed"] == 0
    assert shape["with_placeholder"] == 1 and shape["unmapped"] == 1


def test_only_an_address_starting_with_a_land_placeholder_is_trimmed():
    from pii_pipeline.selection.land import trim_land_placeholder

    value = "[PII_LAND_PARCEL_NUMBER_2]\nตำบลทดสอบ"
    trimmed, cut = trim_land_placeholder(PiiMatch("ADDRESS", value, 5, 5 + len(value)))
    assert cut and trimmed == PiiMatch("ADDRESS", "ตำบลทดสอบ", 32, 41)
    for match in (
        PiiMatch("NAME", value, 0, len(value)),
        PiiMatch("ADDRESS", "[PII_NAME_1] ตำบล", 0, 17),
        PiiMatch("ADDRESS", "[PII_TITLE_DEED_NUMBER_1] ", 0, 26),
    ):
        assert trim_land_placeholder(match) == (match, False)


def test_only_an_address_that_overlaps_nothing_else_absorbs_land_numbers():
    from pii_pipeline.selection.land import absorbed_land_numbers

    address = PiiMatch("ADDRESS", "x" * 20, 10, 30)
    number = PiiMatch("TITLE_DEED_NUMBER", "123", 10, 13)
    assert absorbed_land_numbers([address, number]) == {(10, 13, "TITLE_DEED_NUMBER")}
    # A same-span number, a crossing value or another type keeps the selection.
    assert not absorbed_land_numbers(
        [address, PiiMatch("TITLE_DEED_NUMBER", "x" * 20, 10, 30)]
    )
    assert not absorbed_land_numbers(
        [address, number, PiiMatch("NAME", "xxxx", 28, 32)]
    )
    assert not absorbed_land_numbers([address, PiiMatch("NAME", "123", 10, 13)])


@pytest.mark.asyncio
async def test_land_number_alone_or_far_from_an_address_keeps_its_own_type():
    rules, checker = land_rules()
    source = f"น.ส. 3 ก. เลขที่ 123\n\nผู้ร้องอยู่ {LAND_LOCATION}"

    def handler(request):
        role, _, _ = form(request)
        if role == "candidates":
            return candidates(("ADDRESS", LAND_LOCATION))
        return verification()

    result = await run(source, handler, rules=rules, checker=checker)
    assert result.redacted_markdown == (
        "น.ส. 3 ก. เลขที่ [PII_TITLE_DEED_NUMBER_1]\n\nผู้ร้องอยู่ [PII_ADDRESS_1]"
    )


@pytest.mark.asyncio
async def test_other_types_containing_a_rule_number_still_lose_to_the_rule():
    # A NAME over a rule value is not accepted; here the rule value is the
    # number + location ADDRESS (approved 2026-10-15).
    rules, checker = land_rules()

    def handler(request):
        role, _, _ = form(request)
        if role == "candidates":
            return candidates(("NAME", "เลขที่ 123 ตำบลทดสอบ"))
        return verification()

    result = await run(LAND_SOURCE, handler, rules=rules, checker=checker)
    assert result.redacted_markdown == LAND_REDACTED
    assert "[PII_NAME_1]" not in result.redacted_markdown
