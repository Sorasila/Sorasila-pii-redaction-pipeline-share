import json
from itertools import product

import pytest

from pii_pipeline.core.models import PiiMatch
from pii_pipeline.core.pii_types import CANONICAL_PII_TYPES
from pii_pipeline.core.redaction import redact
from pii_pipeline.llm.prompts import build_conflict_selection_prompt
from pii_pipeline.llm.response import DetectionResponseError
from pii_pipeline.selection.conflicts import (
    build_conflict_options_schema,
    plan_conflict_options,
    resolve_conflict_options,
)


def response(*options):
    return {"decisions": {f"group_{i}": choice for i, choice in enumerate(options, 1)}}


def test_conflict_prompt_keeps_approved_scopes_and_restricts_output_to_option_ids():
    prompt = build_conflict_selection_prompt("PII_OCCURRENCE_1_")
    assert all(kind in prompt for kind in CANONICAL_PII_TYPES)
    assert "untrusted data" in prompt
    assert "exactly one listed option_id" in prompt
    assert "Do not return occurrence decisions" in prompt
    assert "non-overlapping set" in prompt


@pytest.mark.parametrize(
    "prefix", ["OTHER", "PII_OCCURRENCE_1_\ninject", "PII_OCCURRENCE_ไทย"]
)
def test_conflict_prompt_rejects_untrusted_marker_configuration(prefix):
    with pytest.raises(ValueError, match="Invalid conflict marker configuration"):
        build_conflict_selection_prompt(prefix)


def test_every_schema_valid_choice_excludes_simultaneous_overlapping_boundaries():
    source = "Alice Smith"
    plan = plan_conflict_options(
        source,
        [PiiMatch("NAME", "Alice", 0, 5), PiiMatch("NAME", source, 0, len(source))],
    )
    assert len(plan.groups) == 1
    assert len(plan.groups[0].options) == 3
    decision_schema = build_conflict_options_schema(plan)["properties"]["decisions"]
    assert decision_schema["type"] == "object"
    assert decision_schema["required"] == ["group_1"]
    assert decision_schema["additionalProperties"] is False
    group_schema = decision_schema["properties"]["group_1"]
    assert group_schema["type"] == "string"
    selected_values = set()
    for option_id in group_schema["enum"]:
        payload = response(option_id)
        selected = resolve_conflict_options(source, plan, payload)
        assert len(selected) <= 1
        selected_values.add(tuple(item.value for item in selected))
    assert selected_values == {(), ("Alice",), ("Alice Smith",)}
    invalid_both = response(["option_2", "option_3"])
    assert invalid_both["decisions"]["group_1"] not in group_schema["enum"]
    with pytest.raises(DetectionResponseError) as caught:
        resolve_conflict_options(source, plan, invalid_both)
    assert caught.value.reason_code == "invalid_conflict_option"
    assert "Alice" not in repr(plan) + str(caught.value)


def test_independent_groups_type_alternatives_and_not_pii_keep_original_mapping():
    source = "Alice Smith; born 2000; document 2000"
    start = source.index("2000")
    plan = plan_conflict_options(
        source,
        [
            PiiMatch("NAME", "Alice", 0, 5),
            PiiMatch("NAME", "Alice Smith", 0, 11),
            PiiMatch("DATE_OF_BIRTH", "2000", start, start + 4),
            PiiMatch("ID_NUMBER", "2000", start, start + 4),
        ],
    )
    assert len(plan.groups) == 2
    decision_schema = build_conflict_options_schema(plan)["properties"]["decisions"]
    assert decision_schema["required"] == ["group_1", "group_2"]
    for options in product(
        *(item["enum"] for item in decision_schema["properties"].values())
    ):
        payload = response(*options)
        resolved = resolve_conflict_options(source, plan, payload)
        result = redact(source, resolved)
        assert result.redacted_markdown.endswith("document 2000")
        assert len(result.entries) <= 2
        assert all(item.original_value in source for item in result.entries)
    long_name = next(
        item.option_id
        for item in plan.groups[0].options
        if item.selected == ((2, "NAME"),)
    )
    birth = next(
        item.option_id
        for item in plan.groups[1].options
        if item.selected == ((3, "DATE_OF_BIRTH"),)
    )
    result = redact(
        source, resolve_conflict_options(source, plan, response(long_name, birth))
    )
    assert (
        result.redacted_markdown
        == "[PII_NAME_1]; born [PII_DATE_OF_BIRTH_1]; document 2000"
    )


def test_mandatory_numeric_rule_cannot_be_omitted_or_overlap_in_any_listed_option():
    source = "คดีหมายเลขดำที่ 123/2569"
    start = source.index("123")
    mandatory = PiiMatch("CASE_NUMBER", source[start:], start, len(source))
    plan = plan_conflict_options(
        source,
        [PiiMatch("CASE_NUMBER", source, 0, len(source)), mandatory],
        (mandatory,),
    )
    assert len(plan.groups[0].options) == 1
    payload = response(plan.groups[0].options[0].option_id)
    resolved = resolve_conflict_options(source, plan, payload, (mandatory,))
    assert resolved == [mandatory]
    result = redact(source, resolved)
    assert result.redacted_markdown == "คดีหมายเลขดำที่ [PII_CASE_NUMBER_1]"
    assert result.entries[0].original_value == "123/2569"


@pytest.mark.parametrize(
    "payload,reason",
    [
        ({"decisions": []}, "invalid_conflict_decisions"),
        ({"decisions": {}}, "invalid_conflict_decisions"),
        ({"decisions": {"group_2": "option_1"}}, "invalid_conflict_decisions"),
        (response("option_99"), "invalid_conflict_option"),
        (response(1), "invalid_conflict_option"),
        (response(True), "invalid_conflict_option"),
        (response({"value": "PRIVATE"}), "invalid_conflict_option"),
        (
            {"decisions": {"group_1": "option_1"}, "value": "PRIVATE"},
            "invalid_selection_shape",
        ),
        (
            {"decisions": [{"occurrence_id": 1, "pii_type": "NAME"}]},
            "invalid_conflict_decisions",
        ),
    ],
)
def test_invalid_choices_and_old_occurrence_shape_never_fall_back(payload, reason):
    source = "Alice Smith"
    plan = plan_conflict_options(
        source,
        [PiiMatch("NAME", "Alice", 0, 5), PiiMatch("NAME", source, 0, len(source))],
    )
    with pytest.raises(DetectionResponseError) as caught:
        resolve_conflict_options(source, plan, payload)
    assert caught.value.reason_code == reason
    assert "PRIVATE" not in str(caught.value) + repr(caught.value.details)


@pytest.mark.parametrize("limit", ["spans", "groups", "options"])
def test_choice_generation_has_fixed_bounds_before_any_proxy_call(limit):
    if limit == "spans":
        source = "abcdefghijklmn"
        matches = [PiiMatch("NAME", source[:size], 0, size) for size in range(1, 14)]
    elif limit == "groups":
        source = "ab " * 65
        matches = [
            PiiMatch(kind, "ab", index * 3, index * 3 + 2)
            for index in range(65)
            for kind in ("NAME", "ORGANIZATION")
        ]
    else:
        source = "a b c d e f g h i j k"
        matches = [PiiMatch("NAME", source, 0, len(source))]
        matches.extend(
            PiiMatch(kind, source[index], index, index + 1)
            for index in range(0, len(source), 2)
            for kind in ("NAME", "ORGANIZATION")
        )
    with pytest.raises(DetectionResponseError) as caught:
        plan_conflict_options(source, matches)
    assert caught.value.reason_code == "conflict_options_exceeded"


def test_conflicting_mandatory_spans_have_no_legal_option():
    source = "Alice Smith"
    required = [
        PiiMatch("NAME", "Alice", 0, 5),
        PiiMatch("NAME", source, 0, len(source)),
    ]
    with pytest.raises(DetectionResponseError) as caught:
        plan_conflict_options(source, required, required)
    assert caught.value.reason_code == "required_match_omitted"


def test_schema_and_choice_context_have_only_service_generated_group_and_option_ids():
    source = "<PII_OCCURRENCE_1_1> Alice Smith"
    start = source.index("Alice")
    plan = plan_conflict_options(
        source,
        [
            PiiMatch("NAME", "Alice", start, start + 5),
            PiiMatch("NAME", "Alice Smith", start, len(source)),
        ],
    )
    schema = build_conflict_options_schema(plan)
    assert "Alice" not in json.dumps(schema)
    payload = json.loads(plan.context)
    assert payload["groups"][0]["occurrence_ids"] == [1, 2]
    assert plan.occurrences.marker_prefix == "PII_OCCURRENCE_2_"
