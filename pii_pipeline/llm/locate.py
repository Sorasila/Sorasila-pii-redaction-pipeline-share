"""Find the source text an LLM value denotes; only source text is ever returned.

``locate_value`` tries, in order:

1. the exact value;
2. the value with whitespace ignored on both sides (4+ characters), or a near
   copy of 10+ characters with a few OCR "repairs" (``locate_tolerant_value``);
3. 2-4 exact parts of a value the model joined across an OCR page break
   (``locate_value_pieces``).

Anything else stays unlocated and the caller fails closed (value_not_found).
"""

import unicodedata


def is_nfc_text(value: object) -> bool:
    return isinstance(value, str) and unicodedata.normalize("NFC", value) == value


def copy_comparison_details(source: str, value: str) -> dict[str, bool]:
    """Compare disposable copies only; never resolve, repair or return any text."""
    without_whitespace = "".join(value.split())
    without_format = "".join(
        character for character in value if unicodedata.category(character) != "Cf"
    )
    compatibility_value = unicodedata.normalize("NFKC", value)
    return {
        "value_found_without_whitespace": (
            bool(without_whitespace) and without_whitespace in "".join(source.split())
        ),
        "value_found_with_nfkc_comparison": (
            bool(compatibility_value)
            and compatibility_value in unicodedata.normalize("NFKC", source)
        ),
        "value_found_without_format_characters": (
            bool(without_format)
            and without_format
            in "".join(
                character
                for character in source
                if unicodedata.category(character) != "Cf"
            )
        ),
        "value_contains_format_characters": without_format != value,
    }


def _without_whitespace(source: str) -> tuple[list[int], str]:
    """Source positions of non-whitespace characters, and those characters."""
    positions = [
        index for index, character in enumerate(source) if not character.isspace()
    ]
    return positions, "".join(source[index] for index in positions)


# Approved 2026-10-06: models drop CR or line-break indentation when copying
# multi-line values, and "repair" OCR spelling (moved tone marks, added or
# replaced letters) inside long values. Widened 2026-10-12 (one edit per 10
# characters, one exact character at the start): models correct several OCR
# misspellings in one address, including next to its first character.
# Approved 2026-10-15: the last character may differ too; such a match is
# extended to the end of its word (at most one edit budget of characters), so
# a changed final letter can no longer leave the rest of the word visible.
# Approved 2026-10-19: shorter values (10-19 characters) get a smaller budget,
# one edit per 7 characters: models fix one or two OCR letters or tone marks in
# short addresses and letter numbers (full run C10: every repair was
# value_not_found, most of them 13-16 characters one or two edits away).
_MIN_WHITESPACE_TOLERANT = 4
_MIN_EDIT_TOLERANT = 10
_LONG_EDIT_TOLERANT = 20
_CHARACTERS_PER_EDIT = 10
_SHORT_CHARACTERS_PER_EDIT = 7
_MIN_EDIT_BUDGET = 2
_MIN_SHORT_EDIT_BUDGET = 1
_EXACT_EDGE = 1


def _edit_budget(target: str) -> int:
    if len(target) < _LONG_EDIT_TOLERANT:
        return max(_MIN_SHORT_EDIT_BUDGET, len(target) // _SHORT_CHARACTERS_PER_EDIT)
    return max(_MIN_EDIT_BUDGET, len(target) // _CHARACTERS_PER_EDIT)


def _edit_distance_within(left: str, right: str, budget: int) -> int | None:
    """Levenshtein distance when it is at most budget, otherwise None."""
    if abs(len(left) - len(right)) > budget:
        return None
    previous = list(range(len(right) + 1))
    for row, left_character in enumerate(left, 1):
        current = [row] + [budget + 1] * len(right)
        low = max(1, row - budget)
        high = min(len(right), row + budget)
        for column in range(low, high + 1):
            current[column] = min(
                previous[column] + 1,
                current[column - 1] + 1,
                previous[column - 1] + (left_character != right[column - 1]),
            )
        if min(current) > budget:
            return None
        previous = current
    return previous[-1] if previous[-1] <= budget else None


def _near_copy_spans(projected: str, target: str) -> set[tuple[int, int]]:
    """Closest spans starting with the value's first character, within budget.

    Every other span within budget must overlap them, otherwise the location
    is ambiguous and nothing is returned.
    """
    budget = _edit_budget(target)
    head = target[:_EXACT_EDGE]
    scored: list[tuple[int, int, int]] = []
    start = projected.find(head)
    while start >= 0:
        for length in range(len(target) - budget, len(target) + budget + 1):
            end = start + length
            if length < 2 * _EXACT_EDGE or end > len(projected):
                continue
            distance = _edit_distance_within(projected[start:end], target, budget)
            if distance is not None:
                scored.append((distance, start, end))
        start = projected.find(head, start + 1)
    if not scored:
        return set()
    best = min(distance for distance, _, _ in scored)
    winners = {(start, end) for distance, start, end in scored if distance == best}
    first = min(start for start, _ in winners)
    last = max(end for _, end in winners)
    if any(end <= first or start >= last for _, start, end in scored):
        return set()
    return winners


def _is_word_character(character: str) -> bool:
    # Letters, combining vowels and tone marks, digits; not spaces or punctuation.
    return unicodedata.category(character)[0] in "LMN"


def _extend_to_word_end(source: str, end: int, limit: int) -> int | None:
    stop = end
    while stop < len(source) and _is_word_character(source[stop]):
        stop += 1
        if stop - end > limit:
            return None
    return stop


def _near_copy_texts(source, positions, projected, target) -> set[str]:
    """Source texts of the closest spans; a span whose last character differs
    from the value's is extended to the end of its word."""
    texts = set()
    for first, last in _near_copy_spans(projected, target):
        end = positions[last - 1] + 1
        if projected[last - 1] != target[-1]:
            end = _extend_to_word_end(source, end, _edit_budget(target))
            if end is None:
                return set()
        texts.add(source[positions[first] : end])
    return texts


def locate_tolerant_value(source: str, value: str) -> str | None:
    """Return the one source substring a near-copy denotes, never model text.

    Whitespace is ignored on both sides. Failing that, a value of at least
    _MIN_EDIT_TOLERANT non-whitespace characters may differ by up to
    max(2, length / 10) code-point edits (20+ characters) or max(1, length / 7)
    (10-19 characters), provided its first character matches
    exactly and exactly one source text is that close. When the last character
    differs, the text runs to the end of its word. The source text then goes
    through exact location.
    """
    positions, projected = _without_whitespace(source)
    target = "".join(value.split())
    if len(target) < _MIN_WHITESPACE_TOLERANT:
        return None

    spans: set[tuple[int, int]] = set()
    start = projected.find(target)
    while start >= 0:
        spans.add((start, start + len(target)))
        start = projected.find(target, start + 1)
    texts = {
        source[positions[first] : positions[last - 1] + 1] for first, last in spans
    }
    if not spans and len(target) >= _MIN_EDIT_TOLERANT:
        texts = _near_copy_texts(source, positions, projected, target)
    if len(texts) != 1:
        return None
    (text,) = texts
    if "[PII_" in text or not is_nfc_text(text):
        return None
    return text


# Approved 2026-10-07: OCR page-break lines ("---", "|", page numbers, short
# Latin words) can split one value; models then join the parts.
_MIN_PIECE = 4
_MAX_PIECES = 4
_MAX_PIECE_GAP = 120


def _is_page_break_gap(gap: str) -> bool:
    """Separator text only: something visible, no Thai, no placeholder."""
    return (
        bool(gap.strip())
        and len(gap) <= _MAX_PIECE_GAP
        and "[PII_" not in gap
        and not any("฀" <= character <= "๿" for character in gap)
    )


def locate_value_pieces(source: str, value: str) -> list[str] | None:
    """Return the in-order source parts a joined value denotes, never model text.

    The value must be 2 to _MAX_PIECES exact parts (whitespace ignored), each at
    least _MIN_PIECE non-whitespace characters, separated only by page-break
    text. Exactly one such decomposition may exist; each part is then redacted
    as its own value of the same type and the separators stay.
    """
    positions, projected = _without_whitespace(source)
    target = "".join(value.split())
    found: list[tuple[tuple[int, int], ...]] = []

    def common_prefix(start: int, offset: int) -> int:
        length = 0
        limit = min(len(target) - offset, len(projected) - start)
        while length < limit and projected[start + length] == target[offset + length]:
            length += 1
        return length

    def extend(offset: int, spans: tuple[tuple[int, int], ...]) -> None:
        if len(found) > 1:
            return
        if offset == len(target):
            if len(spans) >= 2:
                found.append(spans)
            return
        if len(spans) == _MAX_PIECES:
            return
        head = target[offset : offset + _MIN_PIECE]
        start = projected.find(head, spans[-1][1] if spans else 0)
        while start >= 0:
            if spans:
                gap = source[positions[spans[-1][1] - 1] + 1 : positions[start]]
                if len(gap) > _MAX_PIECE_GAP:
                    return
                if not _is_page_break_gap(gap):
                    start = projected.find(head, start + 1)
                    continue
            length = common_prefix(start, offset)
            if length >= _MIN_PIECE:
                extend(offset + length, (*spans, (start, start + length)))
            start = projected.find(head, start + 1)

    if len(target) >= 2 * _MIN_PIECE:
        extend(0, ())
    if len(found) != 1:
        return None
    pieces = [
        source[positions[first] : positions[last - 1] + 1] for first, last in found[0]
    ]
    if any("[PII_" in piece or not is_nfc_text(piece) for piece in pieces):
        return None
    return pieces


def locate_value(source: str, value: str) -> list[str]:
    """Source texts for one NFC value; the value itself when nothing matches."""
    if value in source:
        return [value]
    located = locate_tolerant_value(source, value)
    if located:
        return [located]
    return locate_value_pieces(source, value) or [value]
