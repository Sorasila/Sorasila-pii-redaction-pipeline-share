import asyncio
import json
import re

import httpx
import pytest
from test_llm_recovery import candidates, form, run, settings, success, verification

from pii_pipeline.core.detection import DetectionError
from pii_pipeline.core.models import PiiCandidate, PiiMatch
from pii_pipeline.core.redaction import redact
from pii_pipeline.core.verification import VerificationError
from pii_pipeline.llm.client import LlmProxyClient
from pii_pipeline.llm.response import DetectionResponseError
from pii_pipeline.llm.windows import make_text_window
from pii_pipeline.recovery.process import RecoveryMergeError, RecoveryPolicy
from pii_pipeline.rules.thai import detect_thai_labeled_numbers
from pii_pipeline.selection.conflicts import split_initial_conflicts
from pii_pipeline.selection.occurrences import plan_detection_occurrences
from pii_pipeline.selection.spans import plan_match_selection, resolve_match_selection


def option_response(context, decisions):
    """Translate the test's semantic oracle to the new trusted option IDs."""
    wanted = {
        (item["occurrence_id"], item["pii_type"])
        for item in decisions
        if item["pii_type"] != "NOT_PII"
    }
    choices = {}
    for group in json.loads(context)["groups"]:
        target = {item for item in wanted if item[0] in group["occurrence_ids"]}
        choices[group["group_id"]] = next(
            (
                option["option_id"]
                for option in group["options"]
                if {
                    (item["occurrence_id"], item["pii_type"])
                    for item in option["selected"]
                }
                == target
            ),
            "option_outside",
        )
    return {"decisions": choices}


def test_match_plan_preserves_original_and_locations_including_repeated_non_pii():
    source = "<PII_OCCURRENCE_1_1> Born 2000; document 2000"
    start = source.index("2000")
    matches = [
        PiiMatch("DATE_OF_BIRTH", "2000", start, start + 4),
        PiiMatch("ID_NUMBER", "2000", start, start + 4),
    ]
    plan = plan_match_selection(source, matches)
    payload = json.loads(plan.context)
    assert plan.marker_prefix == "PII_OCCURRENCE_2_"
    assert (
        re.sub(r"</?PII_OCCURRENCE_2_\d+>", "", payload["annotated_source"]) == source
    )
    assert len(plan.occurrences) == 1
    selected = resolve_match_selection(
        source, plan, {"decisions": [{"occurrence_id": 1, "pii_type": "DATE_OF_BIRTH"}]}
    )
    result = redact(source, selected)
    assert result.redacted_markdown.endswith(
        "Born [PII_DATE_OF_BIRTH_1]; document 2000"
    )
    assert "2000" not in repr(plan)


@pytest.mark.parametrize(
    "failure,reason",
    [
        ("missing", "missing_occurrence_decision"),
        ("duplicate", "duplicate_occurrence_id"),
        ("unknown", "invalid_occurrence_id"),
        ("type", "invalid_selection_type"),
        ("extra", "invalid_selection_shape"),
        ("overlap", "overlapping_matches"),
        ("required", "required_match_omitted"),
    ],
)
def test_closed_conflict_decisions_reject_invalid_or_omitted_required_match(
    failure, reason
):
    source = "Alice Smith"
    required = PiiMatch("NAME", source, 0, len(source))
    plan = plan_match_selection(
        source, [PiiMatch("NAME", "Alice", 0, 5), required], (required,)
    )
    decisions = [
        {"occurrence_id": 1, "pii_type": "NOT_PII"},
        {"occurrence_id": 2, "pii_type": "NAME"},
    ]
    if failure == "missing":
        decisions.pop()
    if failure == "duplicate":
        decisions[1]["occurrence_id"] = 1
    if failure == "unknown":
        decisions[1]["occurrence_id"] = 3
    if failure == "type":
        decisions[1]["pii_type"] = "PHONE"
    if failure == "extra":
        decisions[1]["value"] = source
    if failure == "overlap":
        decisions[0]["pii_type"] = "NAME"
    if failure == "required":
        decisions[1]["pii_type"] = "NOT_PII"
    with pytest.raises(DetectionResponseError) as caught:
        resolve_match_selection(source, plan, {"decisions": decisions}, (required,))
    assert caught.value.reason_code == reason
    assert "Alice" not in str(caught.value) + repr(caught.value.details)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "initial,repaired",
    [
        (("NAME", "Alice"), ("NAME", "Alice Smith")),
        (("NAME", "Alice Smith"), ("NAME", "Alice")),
        (("ORGANIZATION", "Alice Smith"), ("NAME", "Alice Smith")),
    ],
)
async def test_repair_conflict_chooses_complete_contextual_name_and_keeps_good_phone(
    initial, repaired
):
    source = "Name Alice Smith phone 123"
    roles, events = [], []

    def wire(request):
        role, context, _ = form(request)
        roles.append(role)
        if role == "candidates":
            if roles.count(role) == 1:
                return candidates(initial, ("PHONE", "123"), ("NAME", "Absent"))
            return candidates(repaired)
        if role == "decisions":
            items = json.loads(context)["occurrences"]
            if len(items) == 1:
                choices = [{"occurrence_id": 1, "pii_type": "NAME"}]
            else:
                choices = [
                    {"occurrence_id": 1, "pii_type": "NOT_PII"},
                    {"occurrence_id": 2, "pii_type": "NAME"},
                ]
            return success(option_response(context, choices))
        assert context == "Name [PII_NAME_1] phone [PII_PHONE_1]"
        return verification()

    result = await run(source, wire, events=events)
    assert [entry.original_value for entry in result.entries] == ["Alice Smith", "123"]
    assert roles == ["candidates", "candidates", "decisions", "has_pii"]
    assert events[-1]["recovery_calls"] == 2
    assert events[-1]["conflict_selection_calls"] == 1
    assert "Alice" not in json.dumps(events)


@pytest.mark.asyncio
async def test_crossing_boundaries_select_one_supported_span_before_verification():
    roles = []

    def wire(request):
        role, context, _ = form(request)
        roles.append(role)
        if role == "candidates":
            if len(roles) == 1:
                return candidates(("NAME", "Alice Smith"), ("NAME", "Absent"))
            return candidates(("NAME", "Smith Junior"))
        if role == "decisions":
            return success(
                option_response(
                    context,
                    [
                        {"occurrence_id": 1, "pii_type": "NAME"},
                        {"occurrence_id": 2, "pii_type": "NOT_PII"},
                    ],
                )
            )
        assert context == "[PII_NAME_1] Junior"
        return verification()

    result = await run("Alice Smith Junior", wire)
    assert result.entries[0].original_value == "Alice Smith"
    assert roles[-1] == "has_pii"


CASE_SOURCE = "คดีหมายเลขดำที่ 123/2569"
CASE_NAME_SOURCE = "คดีหมายเลขดำที่ 123/2569 Alice Smith"
CASE_NAME_REDACTED = "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1] [PII_NAME_1]"


def case_rule_wire(roles):
    def wire(request):
        role, context, _ = form(request)
        roles.append(role)
        if role == "candidates":
            return candidates(("CASE_NUMBER", context))
        assert role == "has_pii", "A forced choice must not reach the proxy"
        assert context == "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1]"
        return verification()

    return wire


def case_name_planner(source):
    """The second window starts at the case number, so answers can cross."""
    return [
        make_text_window(source, 0, len(source)),
        make_text_window(source, source.index("123"), len(source)),
    ]


def case_name_wire(roles, *, failure=None):
    """LLM spans from two windows cross each other and a mandatory rule span."""

    def wire(request):
        role, context, _ = form(request)
        roles.append(role)
        if role == "candidates":
            if context.startswith("คดี"):
                return candidates(("NAME", "2569 Alice"))
            return candidates(("NAME", "Alice Smith"))
        if role == "decisions":
            items = json.loads(context)["occurrences"]
            assert [item["required_types"] for item in items] == [
                ["CASE_NUMBER"],
                [],
                [],
            ]
            if failure == "timeout" and roles.count(role) == 1:
                raise httpx.ReadTimeout("Synthetic private timeout")
            if failure == "401":
                return httpx.Response(401)
            choices = [
                {"occurrence_id": 1, "pii_type": "CASE_NUMBER"},
                {"occurrence_id": 2, "pii_type": "NOT_PII"},
                {"occurrence_id": 3, "pii_type": "NAME"},
            ]
            if failure == "omit":
                choices[0]["pii_type"] = "NOT_PII"
            if failure == "overlap":
                choices[1]["pii_type"] = "NAME"
            return success(option_response(context, choices))
        assert context == CASE_NAME_REDACTED
        return verification()

    return wire


async def run_case_name(wire, **kwargs):
    return await run(
        CASE_NAME_SOURCE,
        wire,
        planner=case_name_planner,
        rules=detect_thai_labeled_numbers,
        **kwargs,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("max_recovery_calls", [4, 0])
async def test_forced_rule_conflict_resolves_locally_without_budget(
    max_recovery_calls,
):
    roles, events = [], []
    result = await run(
        CASE_SOURCE,
        case_rule_wire(roles),
        rules=detect_thai_labeled_numbers,
        policy=RecoveryPolicy(max_recovery_calls=max_recovery_calls),
        events=events,
    )
    assert result.redacted_markdown == "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1]"
    assert result.entries[0].original_value == "123/2569"
    assert roles == ["candidates", "has_pii"]
    assert events[-1]["recovery_calls"] == 0
    assert events[-1]["conflict_selection_calls"] == 0
    planned = next(e for e in events if e["event"] == "CONFLICT_GROUPS_PLANNED")
    assert planned == {
        "event": "CONFLICT_GROUPS_PLANNED",
        "role_calls": 1,
        "recovery_calls": 0,
        "scope": "document",
        "window_number": 1,
        "group_count": 1,
        "forced_group_count": 1,
        "max_option_count": 1,
        "candidate_count": 2,
        "required_count": 1,
        "selection_required": False,
    }
    names = [event["event"] for event in events]
    assert "CONFLICT_SELECTION_FORCED" in names
    assert "CONFLICT_SELECTION_STARTED" not in names
    assert "123/2569" not in json.dumps(events)


@pytest.mark.asyncio
async def test_open_rule_conflict_still_uses_counted_selection():
    roles, events = [], []
    result = await run_case_name(case_name_wire(roles), events=events)
    assert result.redacted_markdown == CASE_NAME_REDACTED
    assert [entry.original_value for entry in result.entries] == [
        "123/2569",
        "Alice Smith",
    ]
    assert roles == ["candidates", "candidates", "decisions", "has_pii"]
    assert events[-1]["recovery_calls"] == 1
    assert events[-1]["conflict_selection_calls"] == 1
    planned = next(e for e in events if e["event"] == "CONFLICT_GROUPS_PLANNED")
    assert planned["selection_required"] is True
    assert planned["max_option_count"] == 2
    assert "Alice" not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["omit", "overlap"])
async def test_invalid_conflict_choice_cannot_reach_verification(failure):
    roles = []
    with pytest.raises(RecoveryMergeError) as caught:
        await run_case_name(case_name_wire(roles, failure=failure))
    assert caught.value.reason_code == "conflict_selection_rejected"
    assert roles == ["candidates", "candidates", "decisions"]


@pytest.mark.asyncio
async def test_selection_retries_share_recovery_budget_and_fatal_auth_does_not_retry():
    roles, events = [], []
    await run_case_name(
        case_name_wire(roles, failure="timeout"),
        policy=RecoveryPolicy(conflict_selection_attempts=2),
        events=events,
    )
    assert roles == ["candidates", "candidates", "decisions", "decisions", "has_pii"]
    assert events[-1]["recovery_calls"] == 2
    roles.clear()
    with pytest.raises(DetectionError):
        await run_case_name(
            case_name_wire(roles, failure="401"),
            policy=RecoveryPolicy(conflict_selection_attempts=2),
        )
    assert roles == ["candidates", "candidates", "decisions"]


@pytest.mark.asyncio
async def test_conflict_selection_cannot_exceed_shared_budget_or_send_uncovered_document():
    roles, events = [], []
    with pytest.raises(RecoveryMergeError) as caught:
        await run_case_name(
            case_name_wire(roles),
            policy=RecoveryPolicy(max_recovery_calls=0),
            events=events,
        )
    assert caught.value.reason_code == "conflict_recovery_limit"
    assert roles == ["candidates", "candidates"]
    assert events[-1] == {
        "event": "CONFLICT_MERGE_PLANNED",
        "role_calls": 2,
        "recovery_calls": 0,
        "scope": "document",
        "batch_count": 1,
        "forced_batch_count": 0,
        "selection_batch_count": 1,
    }
    roles.clear()

    def planner(source):
        return [
            make_text_window(source, 0, 7),
            make_text_window(source, 3, len(source)),
        ]

    def wire(request):
        role, _context, _ = form(request)
        roles.append(role)
        assert role == "candidates"
        return candidates(("NAME", "Alpha" if len(roles) == 1 else "ha Beta"))

    with pytest.raises(RecoveryMergeError) as caught:
        await run("Alpha Beta", wire, planner=planner)
    assert caught.value.reason_code == "conflict_window_unavailable"
    assert roles == ["candidates", "candidates"]


@pytest.mark.asyncio
async def test_insufficient_budget_for_all_selection_batches_spends_no_call():
    second = "คดีหมายเลขแดงที่ 45/2570 Bobby Jones"
    source = f"{CASE_NAME_SOURCE} | {second}"
    offset = len(CASE_NAME_SOURCE) + 3
    roles, events = [], []

    def planner(text):
        return [
            make_text_window(text, 0, offset),
            make_text_window(text, text.index("123"), offset),
            make_text_window(text, offset, len(text)),
            make_text_window(text, text.index("45/"), len(text)),
        ]

    answers = {
        CASE_NAME_SOURCE + " | ": ("NAME", "2569 Alice"),
        "123/2569 Alice Smith | ": ("NAME", "Alice Smith"),
        second: ("NAME", "2570 Bobby"),
        "45/2570 Bobby Jones": ("NAME", "Bobby Jones"),
    }

    def wire(request):
        role, context, _ = form(request)
        roles.append(role)
        assert role == "candidates"
        return candidates(answers[context])

    with pytest.raises(RecoveryMergeError) as caught:
        await run(
            source,
            wire,
            planner=planner,
            rules=detect_thai_labeled_numbers,
            policy=RecoveryPolicy(max_recovery_calls=1),
            events=events,
        )
    assert caught.value.reason_code == "conflict_recovery_limit"
    assert roles == ["candidates"] * 4
    assert events[-1]["selection_batch_count"] == 2
    assert [e["window_number"] for e in events if "selection_required" in e] == [1, 3]


@pytest.mark.asyncio
async def test_selection_cancellation_never_returns_partial_result():
    roles = []
    base = case_name_wire(roles)

    async def wire(request):
        role, _, _ = form(request)
        if role != "decisions":
            return base(request)
        roles.append(role)
        await asyncio.sleep(1)
        return success({"decisions": {}})

    task = asyncio.create_task(run_case_name(wire))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert roles == ["candidates", "candidates", "decisions"]


@pytest.mark.asyncio
async def test_successful_conflict_choice_still_requires_available_final_verification():
    roles = []
    base = case_name_wire(roles)

    def wire(request):
        role, _, _ = form(request)
        if role == "has_pii":
            roles.append(role)
            raise httpx.ReadTimeout("Synthetic private verification failure")
        return base(request)

    with pytest.raises(VerificationError):
        await run_case_name(wire)
    assert roles == ["candidates", "candidates", "decisions", "has_pii", "has_pii"]


INITIAL_SOURCE = "Name Alice Smith Junior phone 555 note Lee and Lee"


def initial_conflict_wire(roles, contexts, *, failure=None):
    """One response proposes crossing names, a unique phone and a repeated value."""

    def wire(request):
        role, context, prompt = form(request)
        roles.append(role)
        if role == "candidates":
            if roles.count(role) == 1:
                return candidates(
                    ("NAME", "Alice Smith"),
                    ("NAME", "Smith Junior"),
                    ("PHONE", "555"),
                    ("NAME", "Lee"),
                )
            assert "Trusted recovery instruction" in prompt
            return candidates(("NAME", "Alice Smith"))
        if role == "decisions":
            payload = json.loads(context)
            assert "conflict-options-v1" in prompt and "groups" in payload
            contexts.append(payload)
            if failure == "option":
                return success({"decisions": {"group_1": "option_outside"}})
            return success(
                option_response(
                    context,
                    [
                        {"occurrence_id": 1, "pii_type": "NAME"},
                        {"occurrence_id": 2, "pii_type": "NOT_PII"},
                        {"occurrence_id": 3, "pii_type": "NAME"},
                        {"occurrence_id": 4, "pii_type": "NOT_PII"},
                    ],
                )
            )
        return verification()

    return wire


@pytest.mark.asyncio
async def test_initial_overlap_uses_one_option_selection_without_repair():
    roles, contexts, events = [], [], []
    result = await run(
        INITIAL_SOURCE, initial_conflict_wire(roles, contexts), events=events
    )
    assert result.redacted_markdown == (
        "Name [PII_NAME_1] Junior phone [PII_PHONE_1] note [PII_NAME_2] and Lee"
    )
    assert [entry.original_value for entry in result.entries] == [
        "Alice Smith",
        "555",
        "Lee",
    ]
    assert roles == ["candidates", "decisions", "has_pii"]
    assert events[-1]["recovery_calls"] == 0
    assert events[-1]["conflict_selection_calls"] == 0
    # The unique phone is kept outside the choice; the repeated value is decided.
    occurrences = contexts[0]["occurrences"]
    assert [item["candidate_types"] for item in occurrences] == [["NAME"]] * 4
    assert [len(group["occurrence_ids"]) for group in contexts[0]["groups"]] == [
        2,
        1,
        1,
    ]
    assert "Alice" not in json.dumps(events)


@pytest.mark.asyncio
async def test_failed_initial_option_selection_keeps_only_nonconflicting_matches():
    roles, contexts, events = [], [], []
    result = await run(
        INITIAL_SOURCE,
        initial_conflict_wire(roles, contexts, failure="option"),
        events=events,
    )
    outcome = next(e for e in events if e["event"] == "DETECTION_WINDOW_OUTCOME")
    assert outcome["issue_count"] == 1 and outcome["valid_matches"] == 1
    assert roles == ["candidates", "decisions", "candidates", "has_pii"]
    assert events[-1]["recovery_calls"] == 1
    assert result.redacted_markdown == (
        "Name [PII_NAME_1] Junior phone [PII_PHONE_1] note Lee and Lee"
    )


@pytest.mark.asyncio
async def test_strict_detect_still_rejects_initial_overlap():
    roles = []

    def wire(request):
        role, _, _ = form(request)
        roles.append(role)
        return candidates(("NAME", "Alice Smith"), ("NAME", "Smith Junior"))

    async with LlmProxyClient(
        settings(), transport=httpx.MockTransport(wire)
    ) as client:
        with pytest.raises(DetectionResponseError) as caught:
            await client.detect("Alice Smith Junior", prompt="Trusted prompt")
    assert caught.value.reason_code == "overlapping_matches"
    assert roles == ["candidates"]


def test_initial_split_is_absent_without_overlap():
    source = "Alice / Bob / Bob"
    plan = plan_detection_occurrences(
        source, [PiiCandidate("NAME", "Alice"), PiiCandidate("NAME", "Bob")]
    )
    assert split_initial_conflicts(plan) is None


def issue_then_cross_wire(roles):
    """Window 1 also returns an absent value, so it asks for a repair first."""
    base = case_name_wire(roles)

    def wire(request):
        role, context, _ = form(request)
        if role == "candidates" and context.startswith("คดี"):
            roles.append(role)
            return candidates(("NAME", "2569 Alice"), ("NAME", "Absent"))
        return base(request)

    return wire


@pytest.mark.asyncio
async def test_repairs_exhaust_shared_budget_before_document_merge_without_reserve():
    roles, events = [], []
    with pytest.raises(RecoveryMergeError) as caught:
        await run_case_name(
            issue_then_cross_wire(roles),
            policy=RecoveryPolicy(max_recovery_calls=1),
            events=events,
        )
    assert caught.value.reason_code == "conflict_recovery_limit"
    assert roles == ["candidates", "candidates", "candidates"]
    assert events[-1]["selection_batch_count"] == 1


@pytest.mark.asyncio
async def test_reserved_call_is_kept_for_document_merge_selection():
    roles, events = [], []
    result = await run_case_name(
        issue_then_cross_wire(roles),
        policy=RecoveryPolicy(max_recovery_calls=1, reserved_recovery_calls=1),
        events=events,
    )
    assert result.redacted_markdown == CASE_NAME_REDACTED
    assert roles == ["candidates", "candidates", "decisions", "has_pii"]
    skipped = [e for e in events if e["event"] == "WINDOW_REPAIR_SKIPPED"]
    assert skipped == [
        {
            "event": "WINDOW_REPAIR_SKIPPED",
            "role_calls": 1,
            "recovery_calls": 0,
            "window_number": 1,
            "attempt": 2,
            "recovery": False,
            "reserved_recovery_calls": 1,
        }
    ]
    started = next(e for e in events if e["event"] == "RECOVERY_STARTED")
    assert started["max_recovery_calls"] == 1
    assert started["reserved_recovery_calls"] == 1
    assert events[-1]["recovery_calls"] == 1
    assert events[-1]["preliminary_issue_windows"] == 1


@pytest.mark.asyncio
async def test_reserved_call_is_available_for_residual_recovery():
    roles, events = [], []

    def wire(request):
        role, context, _ = form(request)
        roles.append(role)
        if role == "candidates":
            if roles.count(role) == 1:
                return candidates(("NAME", "Alicee"))
            assert context == "Name Alice"
            return candidates(("NAME", "Alice"))
        return verification(has_pii=roles.count(role) == 1)

    result = await run(
        "Name Alice",
        wire,
        policy=RecoveryPolicy(max_recovery_calls=1, reserved_recovery_calls=1),
        events=events,
    )
    assert result.redacted_markdown == "Name [PII_NAME_1]"
    assert roles == ["candidates", "has_pii", "candidates", "has_pii"]
    assert events[-1]["recovery_calls"] == 1
    assert events[-1]["residual_rounds"] == 1


def blank_selection_wire(roles, blank_replies):
    """The merge selection first gets ``blank_replies`` replies of the wrong shape."""
    base = case_name_wire(roles)

    def wire(request):
        role, _, _ = form(request)
        if role == "decisions" and roles.count("decisions") < blank_replies:
            roles.append(role)
            # Seen live: a "success" envelope whose output ignores the schema.
            return success({"extracted_text": ""})
        return base(request)

    return wire


@pytest.mark.asyncio
async def test_blank_merge_selection_reply_is_resent_without_spending_recovery():
    # Approved 2026-10-12: one wrong-shape reply no longer fails the request.
    roles, events = [], []
    result = await run_case_name(blank_selection_wire(roles, 1), events=events)
    assert result.redacted_markdown == CASE_NAME_REDACTED
    assert roles == ["candidates", "candidates", "decisions", "decisions", "has_pii"]
    retries = [e for e in events if e["event"] == "BLANK_RESPONSE_RETRY"]
    assert [(e["role"], e["scope"], e["retry"]) for e in retries] == [
        ("selection", "document", 1)
    ]
    assert events[-1]["recovery_calls"] == 1
    assert events[-1]["role_calls"] == 5


@pytest.mark.asyncio
async def test_blank_merge_selection_resends_are_bounded():
    roles = []
    with pytest.raises(RecoveryMergeError) as caught:
        await run_case_name(blank_selection_wire(roles, 99))
    assert caught.value.reason_code == "conflict_selection_rejected"
    # One counted selection + 3 blank resends.
    assert roles == ["candidates", "candidates"] + ["decisions"] * 4

    roles.clear()
    with pytest.raises(RecoveryMergeError):
        await run_case_name(
            blank_selection_wire(roles, 99),
            policy=RecoveryPolicy(blank_response_retries=0),
        )
    assert roles == ["candidates", "candidates", "decisions"]
