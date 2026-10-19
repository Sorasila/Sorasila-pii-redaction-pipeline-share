import asyncio
import json
import re
from urllib.parse import parse_qs

import httpx
import pytest

from pii_pipeline.llm_client import LlmProxyClient
from pii_pipeline.llm_config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm_occurrences import (
    plan_detection_occurrences,
    resolve_detection_occurrences,
)
from pii_pipeline.llm_response import (
    DetectionResponseError,
    parse_detection_candidates,
    parse_detection_response,
)
from pii_pipeline.models import PiiCandidate
from pii_pipeline.redaction import redact


def test_equal_birth_and_document_dates_select_only_birth_and_trace_each_copy():
    source = "Birth: 2000-01-01\nDocument: 2000-01-01\nBirth: 2000-01-01"
    wire = {"candidates": [{"pii_type": "DATE_OF_BIRTH", "value": "2000-01-01"}]}
    matches = parse_detection_response(
        source,
        wire,
        occurrence_decisions={
            "decisions": [
                {"occurrence_id": 3, "pii_type": "DATE_OF_BIRTH"},
                {"occurrence_id": 2, "pii_type": "NOT_PII"},
                {"occurrence_id": 1, "pii_type": "DATE_OF_BIRTH"},
            ]
        },
    )
    result = redact(source, matches)
    assert result.redacted_markdown == (
        "Birth: [PII_DATE_OF_BIRTH_1]\nDocument: 2000-01-01\nBirth: [PII_DATE_OF_BIRTH_2]"
    )
    assert [(entry.placeholder, entry.original_value) for entry in result.entries] == [
        ("[PII_DATE_OF_BIRTH_1]", "2000-01-01"),
        ("[PII_DATE_OF_BIRTH_2]", "2000-01-01"),
    ]


def test_ids_preserve_source_and_cannot_be_forged_by_source_marker_text():
    source = "<PII_OCCURRENCE_1_1> Name: Alpha\t\tAlpha\r\n"
    plan = plan_detection_occurrences(source, [PiiCandidate("NAME", "Alpha")])
    assert plan.marker_prefix == "PII_OCCURRENCE_2_"
    context = json.loads(plan.context)
    recovered = re.sub(r"</?PII_OCCURRENCE_2_\d+>", "", context["annotated_source"])
    assert recovered == source
    assert len(plan.occurrences) == 2
    assert source not in repr(plan)
    assert "Alpha" not in repr(plan.occurrences)


def test_equal_value_can_have_different_types_at_different_occurrences():
    source = "Phone: 12345; Parcel: 12345; Document: 12345"
    wire = {
        "candidates": [
            {"pii_type": "PHONE", "value": "12345"},
            {"pii_type": "LAND_PARCEL_NUMBER", "value": "12345"},
        ]
    }
    matches = parse_detection_response(
        source,
        wire,
        occurrence_decisions={
            "decisions": [
                {"occurrence_id": 1, "pii_type": "PHONE"},
                {"occurrence_id": 2, "pii_type": "LAND_PARCEL_NUMBER"},
                {"occurrence_id": 3, "pii_type": "NOT_PII"},
            ]
        },
    )
    assert [match.pii_type for match in matches] == ["PHONE", "LAND_PARCEL_NUMBER"]
    assert redact(source, matches).redacted_markdown.endswith("Document: 12345")


@pytest.mark.parametrize(
    "decisions,reason",
    [
        (None, "occurrence_selection_required"),
        ({"decisions": []}, "missing_occurrence_decision"),
        (
            {"decisions": [{"occurrence_id": True, "pii_type": "NAME"}]},
            "invalid_occurrence_id",
        ),
        (
            {"decisions": [{"occurrence_id": 3, "pii_type": "NAME"}]},
            "invalid_occurrence_id",
        ),
        (
            {"decisions": [{"occurrence_id": 1, "pii_type": "PHONE"}]},
            "invalid_selection_type",
        ),
        (
            {"decisions": [{"occurrence_id": 1, "pii_type": "NAME", "value": "Alpha"}]},
            "invalid_selection_shape",
        ),
        (
            {"decisions": [{"occurrence_id": 1, "pii_type": "NAME"}] * 2},
            "duplicate_occurrence_id",
        ),
        ({"decisions": [], "error": "Alpha"}, "invalid_selection_shape"),
    ],
)
def test_bad_or_incomplete_selection_rejects_without_partial_results(decisions, reason):
    source = "Alpha Alpha"
    plan = plan_detection_occurrences(source, [PiiCandidate("NAME", "Alpha")])
    with pytest.raises(DetectionResponseError) as caught:
        resolve_detection_occurrences(source, plan, decisions)
    assert caught.value.reason_code == reason
    assert "Alpha" not in str(caught.value)
    assert "Alpha" not in repr(caught.value.details)


def test_self_overlapping_occurrences_are_not_missed_and_selected_overlap_rejects():
    source = "aaaa"
    plan = plan_detection_occurrences(source, [PiiCandidate("NAME", "aaa")])
    assert [(item.start, item.end) for item in plan.occurrences] == [(0, 3), (1, 4)]
    with pytest.raises(DetectionResponseError) as caught:
        resolve_detection_occurrences(
            source,
            plan,
            {
                "decisions": [
                    {"occurrence_id": 1, "pii_type": "NAME"},
                    {"occurrence_id": 2, "pii_type": "NAME"},
                ]
            },
        )
    assert caught.value.reason_code == "overlapping_matches"


def test_repeated_proposals_deduplicate_but_do_not_select_all_occurrences():
    wire = {"candidates": [{"pii_type": "NAME", "value": "Alpha"}] * 2}
    assert len(parse_detection_candidates("Alpha Alpha", wire)) == 1
    with pytest.raises(DetectionResponseError) as caught:
        parse_detection_response("Alpha Alpha", wire)
    assert caught.value.reason_code == "occurrence_selection_required"


@pytest.mark.asyncio
async def test_client_uses_two_requests_for_contextual_selection_without_any_anchor():
    forms = []

    def handler(request):
        form = parse_qs(request.content.decode())
        forms.append(form)
        if len(forms) == 1:
            output = {
                "candidates": [{"pii_type": "DATE_OF_BIRTH", "value": "2000-01-01"}]
            }
        else:
            context = json.loads(form["context"][0])
            assert len(context["occurrences"]) == 2
            output = {
                "decisions": [
                    {"occurrence_id": 1, "pii_type": "DATE_OF_BIRTH"},
                    {"occurrence_id": 2, "pii_type": "NOT_PII"},
                ]
            }
        assert form["use_thinking"] == ["false"]
        return httpx.Response(
            200,
            json={
                "status": "success",
                "model": LLM_PROXY_MODEL,
                "structured_output": output,
            },
        )

    settings = LlmProxySettings(
        base_url="https://example.invalid", api_key="test", _env_file=None
    )
    async with LlmProxyClient(
        settings, transport=httpx.MockTransport(handler)
    ) as client:
        matches = await client.detect(
            "Birth: 2000-01-01\nDocument: 2000-01-01", prompt="Extract"
        )
    assert len(forms) == 2
    assert len(matches) == 1
    schema = json.loads(forms[0]["json_schema"][0])
    assert schema["properties"]["candidates"]["items"]["required"] == [
        "pii_type",
        "value",
    ]
    schema = json.loads(forms[1]["json_schema"][0])
    assert schema["properties"]["decisions"]["items"]["properties"]["occurrence_id"][
        "enum"
    ] == [1, 2]


@pytest.mark.asyncio
async def test_cancellation_during_selection_does_not_return_direct_partial_matches():
    started = asyncio.Event()
    release = asyncio.Event()

    class Client(LlmProxyClient):
        async def structured_output(self, **kwargs):
            if "candidates" in kwargs["json_schema"]["properties"]:
                return {
                    "candidates": [
                        {"pii_type": "NAME", "value": "Alpha"},
                        {"pii_type": "NAME", "value": "Beta"},
                    ]
                }
            started.set()
            await release.wait()
            raise AssertionError("Cancelled selection must not complete")

    settings = LlmProxySettings(
        base_url="https://example.invalid", api_key="test", _env_file=None
    )
    async with Client(settings) as client:
        task = asyncio.create_task(client.detect("Alpha Alpha Beta", prompt="Extract"))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


# Approved 2026-10-15 (proposal 3.1): copies settled without the LLM.
def test_rule_matched_copies_are_settled_and_the_rest_renumbered():
    from pii_pipeline.models import PiiCandidate, PiiMatch
    from pii_pipeline.selection.occurrences import (
        plan_detection_occurrences,
        settle_occurrences,
    )

    source = "โฉนดเลขที่ 4567 และ 4567 และโฉนดเลขที่ 4567"
    plan = plan_detection_occurrences(
        source, [PiiCandidate("TITLE_DEED_NUMBER", "4567")]
    )
    starts = [m.start() for m in re.finditer("4567", source)]
    rules = [
        PiiMatch("TITLE_DEED_NUMBER", "4567", s, s + 4) for s in (starts[0], starts[2])
    ]
    settled_plan, settled = settle_occurrences(source, plan, rules)
    assert settled == 2
    assert [(m.start, m.pii_type) for m in settled_plan.direct_matches] == [
        (starts[0], "TITLE_DEED_NUMBER"),
        (starts[2], "TITLE_DEED_NUMBER"),
    ]
    # Only the unlabelled copy is left for the model, with a fresh ID.
    assert [(o.occurrence_id, o.start) for o in settled_plan.occurrences] == [
        (1, starts[1])
    ]
    context = json.loads(settled_plan.context)
    assert [o["occurrence_id"] for o in context["occurrences"]] == [1]
    assert context["annotated_source"].count("<" + settled_plan.marker_prefix) == 1


@pytest.mark.parametrize(
    "pii_type,value,settled",
    [
        ("NAME", "นายสมชาย ใจดี", True),
        ("NAME", "นางสาวสมศรี ใจดี", True),
        ("NAME", "สมชาย ใจดี", False),  # no title
        ("ADDRESS", "ตำบลทดสอบ อำเภอสมมุติ จังหวัดตัวอย่าง", True),
        ("ADDRESS", "ตำบลทดสอบ", False),  # short
        ("ORGANIZATION", "บริษัท ตัวอย่างการค้า จำกัด มหาชน", False),
    ],
)
def test_titled_names_and_long_addresses_are_settled(pii_type, value, settled):
    from pii_pipeline.models import PiiCandidate
    from pii_pipeline.selection.occurrences import (
        plan_detection_occurrences,
        settle_occurrences,
    )

    source = f"{value} และ {value}"
    plan = plan_detection_occurrences(source, [PiiCandidate(pii_type, value)])
    settled_plan, count = settle_occurrences(source, plan)
    assert count == (2 if settled else 0)
    assert bool(settled_plan.occurrences) is not settled


def test_two_proposed_types_are_left_to_the_model():
    from pii_pipeline.models import PiiCandidate
    from pii_pipeline.selection.occurrences import (
        plan_detection_occurrences,
        settle_occurrences,
    )

    value = "นายสมชาย ใจดี"
    source = f"{value} และ {value}"
    plan = plan_detection_occurrences(
        source, [PiiCandidate("NAME", value), PiiCandidate("ORGANIZATION", value)]
    )
    settled_plan, count = settle_occurrences(source, plan)
    assert count == 0 and settled_plan is plan
