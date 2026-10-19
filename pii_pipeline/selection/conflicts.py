"""Precompute bounded nonoverlapping choices instead of independent span votes."""

import json
from dataclasses import dataclass, field
from typing import NamedTuple

from ..core.models import PiiMatch
from ..llm.errors import DetectionResponseError
from .occurrences import OccurrencePlan
from .spans import match_key, plan_match_selection, resolve_match_selection

MAX_GROUP_SPANS = 12
MAX_GROUP_OPTIONS = 64
MAX_BATCH_GROUPS = 64
MAX_ENUMERATION_STEPS = 4096


@dataclass(frozen=True, slots=True)
class ConflictOption:
    option_id: str
    selected: tuple[tuple[int, str], ...]


@dataclass(frozen=True, slots=True)
class ConflictGroup:
    group_id: str
    occurrence_ids: tuple[int, ...]
    options: tuple[ConflictOption, ...]


@dataclass(frozen=True, slots=True)
class ConflictOptionsPlan:
    occurrences: OccurrencePlan = field(repr=False)
    groups: tuple[ConflictGroup, ...]
    context: str = field(repr=False)


def _reject(reason):
    raise DetectionResponseError("LLM conflict choice is invalid", reason_code=reason)


def _enumerate_options(items, required_keys):
    if len(items) > MAX_GROUP_SPANS:
        _reject("conflict_options_exceeded")
    options = []
    steps = 0

    def visit(index, selected, selected_end):
        nonlocal steps
        steps += 1
        if steps > MAX_ENUMERATION_STEPS:
            _reject("conflict_options_exceeded")
        if index == len(items):
            options.append(tuple(selected))
            if len(options) > MAX_GROUP_OPTIONS:
                _reject("conflict_options_exceeded")
            return
        item = items[index]
        mandatory = tuple(
            kind
            for kind in item.allowed_types
            if (item.start, item.end, kind) in required_keys
        )
        if not mandatory:
            visit(index + 1, selected, selected_end)
        if item.start >= selected_end:
            for kind in mandatory or item.allowed_types:
                visit(index + 1, (*selected, (item.occurrence_id, kind)), item.end)

    visit(0, (), -1)
    if not options:
        _reject("required_match_omitted")
    return options


def plan_conflict_options(source, matches, required_matches=()):
    required = tuple(required_matches)
    plan = plan_match_selection(source, matches, required)
    required_keys = {match_key(item) for item in required}
    groups, group, end = [], [], -1
    for item in plan.occurrences:
        if group and item.start >= end:
            groups.append(group)
            group, end = [], -1
        group.append(item)
        end = max(end, item.end)
    groups.append(group)
    if len(groups) > MAX_BATCH_GROUPS:
        _reject("conflict_options_exceeded")
    choices = []
    for number, items in enumerate(groups, 1):
        options = _enumerate_options(items, required_keys)
        choices.append(
            ConflictGroup(
                f"group_{number}",
                tuple(item.occurrence_id for item in items),
                tuple(
                    ConflictOption(f"option_{index}", selected)
                    for index, selected in enumerate(options, 1)
                ),
            )
        )
    payload = json.loads(plan.context)
    payload["groups"] = [
        {
            "group_id": group.group_id,
            "occurrence_ids": list(group.occurrence_ids),
            "options": [
                {
                    "option_id": option.option_id,
                    "selected": [
                        {"occurrence_id": number, "pii_type": kind}
                        for number, kind in option.selected
                    ],
                }
                for option in group.options
            ],
        }
        for group in choices
    ]
    return ConflictOptionsPlan(
        plan, tuple(choices), json.dumps(payload, ensure_ascii=False)
    )


class InitialSplit(NamedTuple):
    """Spans of one detection reply: settled ones, and those still to choose."""

    kept: tuple
    alternatives: list


def split_initial_conflicts(plan):
    """Separate overlapping initial proposals for one legal-option selection.

    Return None when no located span overlaps another; the ID/type selection
    stays unchanged. Otherwise unique non-overlapping direct matches are kept,
    and every other located span (overlapping alternatives and repeated values
    that need a contextual decision) is listed once per candidate type.
    """
    items = [(match.start, match.end, match, None) for match in plan.direct_matches]
    items.extend((item.start, item.end, None, item) for item in plan.occurrences)
    items.sort(key=lambda item: (item[0], item[1]))
    components, component, end = [], [], -1
    for item in items:
        if component and item[0] >= end:
            components.append(component)
            component = []
        component.append(item)
        end = max(end, item[1]) if len(component) > 1 else item[1]
    if component:
        components.append(component)
    if all(len(component) == 1 for component in components):
        return None
    kept, alternatives = [], []
    for component in components:
        for _, _, direct, occurrence in component:
            if direct is not None and len(component) == 1:
                kept.append(direct)
            elif direct is not None:
                alternatives.append(direct)
            else:
                alternatives.extend(
                    PiiMatch(kind, occurrence.value, occurrence.start, occurrence.end)
                    for kind in occurrence.allowed_types
                )
    return InitialSplit(tuple(kept), alternatives)


def build_conflict_options_schema(plan):
    properties = {
        group.group_id: {
            "type": "string",
            "enum": [option.option_id for option in group.options],
        }
        for group in plan.groups
    }
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "decisions": {
                "type": "object",
                "additionalProperties": False,
                "properties": properties,
                "required": list(properties),
            }
        },
        "required": ["decisions"],
    }


def resolve_conflict_options(source, plan, response, required_matches=()):
    if type(response) is not dict or set(response) != {"decisions"}:
        _reject("invalid_selection_shape")
    decisions = response["decisions"]
    if type(decisions) is not dict or set(decisions) != {
        group.group_id for group in plan.groups
    }:
        _reject("invalid_conflict_decisions")
    selected = {item.occurrence_id: "NOT_PII" for item in plan.occurrences.occurrences}
    for group in plan.groups:
        choice = decisions[group.group_id]
        options = {item.option_id: item for item in group.options}
        if type(choice) is not str or choice not in options:
            _reject("invalid_conflict_option")
        selected.update(options[choice].selected)
    return resolve_match_selection(
        source,
        plan.occurrences,
        {
            "decisions": [
                {"occurrence_id": number, "pii_type": kind}
                for number, kind in selected.items()
            ]
        },
        required_matches,
    )
