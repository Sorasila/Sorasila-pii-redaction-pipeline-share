"""Land number + location policy shared by detection selection and merging.

Approved 2026-10-12: a land document number followed by the location of that
land is one ADDRESS value; the document label ('โฉนดเลขที่', 'น.ส. 3 ก.
เลขที่') stays outside. Applies to ADDRESS only.
"""

import re
from itertools import pairwise
from typing import NamedTuple

from ..core.models import PiiMatch
from .conflicts import InitialSplit
from .spans import match_key

LAND_NUMBER_TYPES = frozenset({"TITLE_DEED_NUMBER", "LAND_PARCEL_NUMBER"})
_LAND_PLACEHOLDER_PREFIX = re.compile(
    r"\[PII_(?:TITLE_DEED_NUMBER|LAND_PARCEL_NUMBER)_\d+\]\s*"
)


def absorbed_land_numbers(matches):
    """Keys of land numbers and ADDRESSes strictly inside a larger ADDRESS.

    The larger ADDRESS already covers them, so the overlap needs no LLM
    choice; it must overlap nothing else. Covers a rule's number + location
    inside a longer LLM address (approved 2026-10-15) and the reverse.
    """
    absorbed = set()
    for address in matches:
        if address.pii_type != "ADDRESS":
            continue
        key = match_key(address)
        overlapping = [
            match
            for match in matches
            if match_key(match) != key
            and match.start < address.end
            and address.start < match.end
        ]
        if overlapping and all(
            (match.pii_type in LAND_NUMBER_TYPES or match.pii_type == "ADDRESS")
            and address.start <= match.start
            and match.end <= address.end
            and (match.start, match.end) != (address.start, address.end)
            for match in overlapping
        ):
            absorbed.update(match_key(match) for match in overlapping)
    return absorbed


def absorb_initial_land_numbers(plan, split):
    """Drop absorbed land numbers from one detection reply's conflict split.

    Returns ``(kept, alternatives)``. When only unique, non-overlapping values
    remain, they are all kept and no selection call is needed.
    """
    kept, alternatives = split
    absorbed = absorbed_land_numbers([*kept, *alternatives])
    if not absorbed:
        return split
    alternatives = [item for item in alternatives if match_key(item) not in absorbed]
    direct = {match_key(item) for item in plan.direct_matches}
    ordered = sorted(
        [*kept, *alternatives],
        key=lambda match: (match.start, match.end, match.pii_type),
    )
    if all(match_key(item) in direct for item in alternatives) and not any(
        right.start < left.end for left, right in pairwise(ordered)
    ):
        return InitialSplit(tuple(ordered), [])
    return InitialSplit(kept, alternatives)


class LandTrim(NamedTuple):
    match: PiiMatch
    trimmed: bool


def trim_land_placeholder(match):
    """Residual ADDRESS that starts with a masked land number keeps the location.

    Approved 2026-10-12. The residual pass reads redacted text, so the model
    may return '[PII_TITLE_DEED_NUMBER_1] ตำบล…' as one ADDRESS. The placeholder
    cannot map back to the source; the location can, and the land-number join
    then makes number and location one ADDRESS.
    """
    if match.pii_type != "ADDRESS":
        return LandTrim(match, False)
    prefix = _LAND_PLACEHOLDER_PREFIX.match(match.value)
    if prefix is None or prefix.end() == len(match.value):
        return LandTrim(match, False)
    return LandTrim(
        PiiMatch(
            "ADDRESS",
            match.value[prefix.end() :],
            match.start + prefix.end(),
            match.end,
        ),
        True,
    )


# Approved 2026-10-12: a land number and the ADDRESS right after it (only
# spaces and at most one line break between) become one ADDRESS.
_MAX_JOIN_GAP = 8


def _joins_land_number_and_address(gap):
    return len(gap) <= _MAX_JOIN_GAP and not gap.strip() and gap.count("\n") <= 1


def join_land_numbers_with_addresses(source, matches):
    """Merge a land number directly followed by an ADDRESS into one ADDRESS."""
    ordered = sorted(matches, key=lambda match: (match.start, match.end))
    joined = []
    index = 0
    while index < len(ordered):
        current = ordered[index]
        following = ordered[index + 1] if index + 1 < len(ordered) else None
        if (
            following is not None
            and current.pii_type in LAND_NUMBER_TYPES
            and following.pii_type == "ADDRESS"
            and _joins_land_number_and_address(source[current.end : following.start])
        ):
            joined.append(
                PiiMatch(
                    "ADDRESS",
                    source[current.start : following.end],
                    current.start,
                    following.end,
                )
            )
            index += 2
            continue
        joined.append(current)
        index += 1
    return joined
