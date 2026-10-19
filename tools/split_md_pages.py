"""Split one Markdown document into page-sized files for /redact requests.

Usage:
    python split_md_pages.py <input.md> --output-dir <new folder> [--max-chars 2000]

Each output file holds at most --max-chars Unicode code points, the same unit the
service counts before NFC normalization. Cut points are chosen in this order:
blank line between paragraphs, end of line, whitespace, and only if none exists a
hard cut. Concatenating the files in order reproduces the input exactly.

The output folder must be new and outside any Git repository. The terminal shows
counts only, never document text. index.json records offsets and cut kinds, not
content.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PLACEHOLDER = re.compile(r"\[PII_[A-Z][A-Z0-9_]*_[0-9]+\]", re.IGNORECASE)


def _last_boundary(text: str, start: int, end: int, kind: str) -> int | None:
    """Return the cut position (exclusive end) of the last boundary in [start, end)."""
    window = text[start:end]
    if kind == "paragraph":
        # \r is allowed so Windows "\r\n\r\n" paragraph breaks are recognized.
        found = [m.end() for m in re.finditer(r"\n[ \t\r]*\n", window)]
    elif kind == "line":
        found = [m.end() for m in re.finditer(r"\n", window)]
    else:  # whitespace inside a line
        found = [m.end() for m in re.finditer(r"[ \t]+", window)]
    found = [start + position for position in found if 0 < position < len(window) + 1]
    return found[-1] if found else None


def plan_pages(text: str, max_chars: int) -> list[tuple[int, int, str]]:
    pages: list[tuple[int, int, str]] = []
    start = 0
    while start < len(text):
        limit = min(start + max_chars, len(text))
        if limit == len(text):
            pages.append((start, limit, "end"))
            break
        cut, kind = None, "hard"
        # Prefer a natural boundary in the second half so pages stay page-sized,
        # then accept one anywhere in the page before cutting inside a word.
        for lower in (start + max_chars // 2, start + 1):
            for candidate in ("paragraph", "line", "whitespace"):
                position = _last_boundary(text, lower, limit, candidate)
                if position is not None and position > start:
                    cut, kind = position, candidate
                    break
            if cut is not None:
                break
        if cut is None:
            cut = limit
        pages.append((start, cut, kind))
        start = cut
    # A whitespace-only tail cannot be sent alone: the service rejects blank input.
    if len(pages) > 1 and not text[pages[-1][0] : pages[-1][1]].strip():
        tail_start, tail_end, _ = pages.pop()
        previous_start, _, previous_kind = pages.pop()
        if tail_end - previous_start <= max_chars:
            pages.append((previous_start, tail_end, previous_kind))
        else:
            pages.extend(
                [
                    (previous_start, tail_start, previous_kind),
                    (tail_start, tail_end, "end"),
                ]
            )
    return pages


def in_git_repository(path: Path) -> bool:
    return any((parent / ".git").exists() for parent in (path, *path.parents))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-chars", type=int, default=2000)
    parser.add_argument("--prefix", default="page")
    args = parser.parse_args(argv)

    if args.max_chars < 100:
        print("STOPPED: --max-chars must be at least 100")
        return 1
    output = args.output_dir.resolve()
    if output.exists():
        print("STOPPED: output folder already exists; choose a new folder")
        return 1
    if in_git_repository(output):
        print("STOPPED: output folder is inside a Git repository; use a private folder")
        return 1

    raw = args.input.read_bytes().decode("utf-8")
    text = raw.removeprefix("﻿")  # BOM is an encoding marker, not content.
    if not text.strip():
        print("STOPPED: input is empty")
        return 1

    pages = plan_pages(text, args.max_chars)
    pieces = [text[start:end] for start, end, _ in pages]
    assert "".join(pieces) == text, "pages must reproduce the input exactly"
    assert all(0 < len(piece) <= args.max_chars for piece in pieces)

    output.mkdir(parents=True)
    width = max(4, len(str(len(pages))))
    index = []
    for number, ((start, end, kind), piece) in enumerate(zip(pages, pieces), 1):
        name = f"{args.prefix}-{number:0{width}d}.md"
        with (output / name).open("x", encoding="utf-8", newline="") as stream:
            stream.write(piece)
        index.append(
            {
                "file": name,
                "start": start,
                "end": end,
                "characters": len(piece),
                "cut": kind,
                "blank": not piece.strip(),
            }
        )
    summary = {
        "source_file": args.input.name,
        "source_characters": len(text),
        "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "max_chars": args.max_chars,
        "pages": index,
    }
    with (output / "index.json").open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, ensure_ascii=False, indent=2)

    sizes = sorted(entry["characters"] for entry in index)
    cuts = {
        kind: sum(entry["cut"] == kind for entry in index)
        for kind in ("paragraph", "line", "whitespace", "hard", "end")
    }
    print(
        json.dumps(
            {
                "status": "SPLIT_COMPLETE",
                "pages": len(index),
                "source_characters": len(text),
                "page_characters_min_median_max": [
                    sizes[0],
                    sizes[len(sizes) // 2],
                    sizes[-1],
                ],
                "cuts": cuts,
                "blank_pages": sum(entry["blank"] for entry in index),
                "existing_placeholders": len(PLACEHOLDER.findall(text)),
                "output_dir": str(output),
            },
            ensure_ascii=True,
        )
    )
    if PLACEHOLDER.search(text):
        print(
            "WARNING: input already contains [PII_...] placeholders; /redact rejects such text"
        )
    if cuts["hard"]:
        print(
            "WARNING: some pages were cut inside a word; check those boundaries before testing"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
