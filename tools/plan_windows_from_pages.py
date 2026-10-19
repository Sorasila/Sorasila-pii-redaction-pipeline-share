"""Write a harness window plan using split_md_pages' cut rules.

Usage: python plan_windows_from_pages.py <work-dir> [--max-chars 2000]

For work dirs where `prepare-md --boundary line` stops with BLOCK_EXCEEDS_WINDOW.
Windows are cut at paragraph, line, whitespace and only then inside a word, are
validated with the harness's own validate_ranges, and leave the source and its
hash untouched. The plan stays unreviewed; a person must still run `review`.
Prints counts only.
"""

import argparse
import json
import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS / "pdf-core-test"))
sys.path.insert(0, str(TOOLS))

import pdf_to_pipeline as bridge
from split_md_pages import plan_pages


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("work_dir", type=Path)
    parser.add_argument("--max-chars", type=int, default=2000)
    args = parser.parse_args(argv)

    plan_path = args.work_dir / "detection-windows.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("reviewed"):
        print("STOPPED: plan is already reviewed; prepare a new work dir instead")
        return 1
    # Read exactly as the harness does: keep \r\n, or offsets drift by one per CR.
    source = bridge.read_text(args.work_dir / "source.md")
    if bridge.digest(source) != plan.get("source_nfc_sha256"):
        print("STOPPED: source.md does not match the plan's source hash")
        return 1
    pages = plan_pages(source, args.max_chars)
    windows = [{"start": start, "end": end} for start, end, _ in pages]
    bridge.validate_ranges(source, windows, args.max_chars, max(len(windows), 1))
    plan.update(
        windows=windows,
        window_chars=args.max_chars,
        max_windows=max(plan.get("max_windows", 0), len(windows)),
        overlap_blocks=0,
        planning_error=None,
    )
    plan_path.write_text(bridge.encoded(plan), encoding="utf-8", newline="")

    lines = source.split("\n")
    sizes = sorted(end - start for start, end, _ in pages)
    cuts = {
        k: sum(kind == k for *_, kind in pages)
        for k in ("paragraph", "line", "whitespace", "hard", "end")
    }
    print(
        json.dumps(
            {
                "status": "PLAN_WRITTEN",
                "source_characters": len(source),
                "lines_over_limit": sum(len(line) > args.max_chars for line in lines),
                "longest_line": max(len(line) for line in lines),
                "windows": len(windows),
                "window_characters_min_median_max": [
                    sizes[0],
                    sizes[len(sizes) // 2],
                    sizes[-1],
                ],
                "cuts": cuts,
                "existing_placeholders": len(
                    re.findall(r"\[PII_[A-Z][A-Z0-9_]*_[0-9]+\]", source, re.IGNORECASE)
                ),
                "reviewed": False,
            }
        )
    )
    if cuts["hard"]:
        print(
            "WARNING: some windows were cut inside a word; check those boundaries during review"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
