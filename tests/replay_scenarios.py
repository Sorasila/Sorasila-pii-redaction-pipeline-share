"""Synthetic replay scenarios: one page each, scripted proxy replies per call.

Every text and value here is invented. Each scenario drives one path through
the service (rules, occurrence and conflict selection, land-number policy,
blank replies, repairs, near copies, page-break pieces, residual recovery,
proxy retries and failures, input rejection).

Build the golden files from the current code (only when the behaviour change
is intended and approved):

    .venv\\Scripts\\python.exe tests\\replay_scenarios.py --write

The golden test (test_replay_golden.py) then replays them against the code.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx

# Runnable as a script from the repository root as well as under pytest.
sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parent.parent)]
from replay_support import (
    RecordingTransport,
    ReplayTransport,
    request_form,
    request_role,
    run_pipeline,
    run_service,
)

from pii_pipeline.llm.config import LLM_PROXY_MODEL

GOLDEN_DIR = Path(__file__).parent / "replay"

ADDRESS = "บ้านเลขที่ 12 ถนนสุขุมวิท แขวงคลองเตย เขตคลองเตย กรุงเทพมหานคร"
LOCATION = "ตำบลทดสอบ อำเภอสมมุติ จังหวัดตัวอย่าง"


def envelope(output):
    return {"status": "success", "model": LLM_PROXY_MODEL, "structured_output": output}


def detect(*items):
    return (
        "candidates",
        {"candidates": [{"pii_type": t, "value": v} for t, v in items]},
    )


def verify(*types):
    return (
        "has_pii",
        {"has_pii": bool(types), "findings": [{"pii_type": t} for t in types]},
    )


AUTO = ("decisions", None)  # pick the first legal option / candidate type
BLANK = ("blank", {"extracted_text": ""})  # seen live: success envelope, wrong shape
FAILED = ("failed", None)  # proxy envelope with status "error"


def status(code):
    return ("status", code)


TIMEOUT = ("timeout", None)


def _auto_decisions(context: str) -> dict:
    payload = json.loads(context)
    if "groups" in payload:
        return {
            "decisions": {
                group["group_id"]: group["options"][0]["option_id"]
                for group in payload["groups"]
            }
        }
    return {
        "decisions": [
            {
                "occurrence_id": item["occurrence_id"],
                "pii_type": item["candidate_types"][0],
            }
            for item in payload["occurrences"]
        ]
    }


def scripted(steps):
    """Reply to each proxy call with the next step; roles are checked."""
    queue = list(steps)

    def send(request: httpx.Request) -> httpx.Response:
        if not queue:
            raise AssertionError("scenario has no reply left for this call")
        kind, value = queue.pop(0)
        form = request_form(request)
        role = request_role(form)
        if kind == "timeout":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        if kind == "status":
            return httpx.Response(value, json={"detail": "synthetic"})
        if kind == "failed":
            return httpx.Response(
                200, json={"status": "error", "model": LLM_PROXY_MODEL}
            )
        if kind == "blank":
            return httpx.Response(200, json=envelope(value))
        if kind != role:
            raise AssertionError(f"scenario expected a {kind} call, got {role}")
        output = _auto_decisions(form["context"]) if value is None else value
        return httpx.Response(200, json=envelope(output))

    send.remaining = queue
    return send


SCENARIOS = {
    "basic_name_address_phone_rule": (
        f"ผู้ร้อง นายสมชาย ใจดี โทร 081-234-5678 อยู่{ADDRESS}",
        [detect(("NAME", "นายสมชาย ใจดี"), ("ADDRESS", ADDRESS)), verify()],
    ),
    # No title: the model chooses which copies are PII.
    "occurrence_selection_for_repeated_name": (
        "สมชาย ใจดี เป็นผู้ร้อง ต่อมาสมชาย ใจดี ได้ยื่นคำร้อง",
        [detect(("NAME", "สมชาย ใจดี")), AUTO, verify()],
    ),
    # Approved 2026-10-15 (proposal 3.1): settled without a selection call.
    "repeated_titled_name_settled_without_llm": (
        "นายสมชาย ใจดี เป็นผู้ร้อง ต่อมานายสมชาย ใจดี ได้ยื่นคำร้อง",
        [detect(("NAME", "นายสมชาย ใจดี")), verify()],
    ),
    "repeated_deed_number_settled_by_rule": (
        "ที่ดินโฉนดเลขที่ 4567 ของผู้ร้อง ต่อมาโฉนดเลขที่ 4567 ถูกโอน",
        [detect(("TITLE_DEED_NUMBER", "4567")), verify()],
    ),
    "unlabelled_copy_still_asks_llm": (
        "ที่ดินโฉนดเลขที่ 4567 ของผู้ร้อง คำร้องฉบับที่ 4567 ยื่นแล้ว",
        [detect(("TITLE_DEED_NUMBER", "4567")), AUTO, verify()],
    ),
    "initial_conflict_selection_for_crossing_names": (
        "ผู้คัดค้าน นายสมชาย ใจดี มีสุข แถลงต่อศาล",
        [detect(("NAME", "นายสมชาย ใจดี"), ("NAME", "ใจดี มีสุข")), AUTO, verify()],
    ),
    "land_number_absorbed_into_address": (
        f"ที่ดินตาม น.ส. 3 ก. เลขที่ 123 {LOCATION} ต่อมา",
        [
            detect(("TITLE_DEED_NUMBER", "123"), ("ADDRESS", f"123 {LOCATION}")),
            verify(),
        ],
    ),
    "land_number_joined_with_location": (
        f"ที่ดินตาม น.ส. 3 ก. เลขที่ 123 {LOCATION} ต่อมา",
        [detect(("ADDRESS", LOCATION)), verify()],
    ),
    "land_number_alone_keeps_its_type": (
        f"โฉนดเลขที่ 4567\n\nผู้ร้องอยู่ {LOCATION}",
        [detect(("ADDRESS", LOCATION)), verify()],
    ),
    "blank_detection_reply_is_resent": (
        "ผู้ร้อง นายสมชาย ใจดี",
        [BLANK, detect(("NAME", "นายสมชาย ใจดี")), verify()],
    ),
    "failed_generation_is_resent": (
        "ผู้ร้อง นายสมชาย ใจดี",
        [FAILED, detect(("NAME", "นายสมชาย ใจดี")), verify()],
    ),
    "blank_verification_reply_is_resent": (
        "ผู้ร้อง นายสมชาย ใจดี",
        [detect(("NAME", "นายสมชาย ใจดี")), BLANK, verify()],
    ),
    "copy_error_is_repaired": (
        "ผู้ร้อง นายสมชาย ใจดี โทร 081-234-5678",
        [
            detect(("NAME", "นายสมชาย ใจดี"), ("NAME", "นางสมศรี ไม่มี")),
            detect(("NAME", "นายสมชาย ใจดี")),
            verify(),
        ],
    ),
    "repair_crossing_earlier_value_needs_window_selection": (
        "ผู้คัดค้าน นายสมชาย ใจดี มีสุข แถลงต่อศาล",
        [
            detect(("NAME", "นายสมชาย ใจดี"), ("NAME", "นางสมศรี ไม่มี")),
            detect(("NAME", "ใจดี มีสุข")),
            AUTO,
            verify(),
        ],
    ),
    "blank_window_selection_is_resent": (
        "ผู้คัดค้าน นายสมชาย ใจดี มีสุข แถลงต่อศาล",
        [
            detect(("NAME", "นายสมชาย ใจดี"), ("NAME", "นางสมศรี ไม่มี")),
            detect(("NAME", "ใจดี มีสุข")),
            BLANK,
            AUTO,
            verify(),
        ],
    ),
    "invalid_window_selection_fails_closed": (
        "ผู้คัดค้าน นายสมชาย ใจดี มีสุข แถลงต่อศาล",
        [
            detect(("NAME", "นายสมชาย ใจดี"), ("NAME", "นางสมศรี ไม่มี")),
            detect(("NAME", "ใจดี มีสุข")),
            ("decisions", {"decisions": {"group_1": "option_outside"}}),
        ],
    ),
    "window_selection_timeouts_fail_closed": (
        "ผู้คัดค้าน นายสมชาย ใจดี มีสุข แถลงต่อศาล",
        [
            detect(("NAME", "นายสมชาย ใจดี"), ("NAME", "นางสมศรี ไม่มี")),
            detect(("NAME", "ใจดี มีสุข")),
            TIMEOUT,
            TIMEOUT,
            TIMEOUT,
        ],
    ),
    "rule_conflict_resolved_without_llm": (
        "คดีหมายเลขดำที่ 123/2569 นายสมชาย ใจดี",
        [detect(("NAME", "2569 นายสมชาย ใจดี")), verify()],
    ),
    "near_copy_with_ocr_corrections": (
        f"ผู้ร้องอยู่{ADDRESS} แจ้งว่า",
        [
            detect(
                (
                    "ADDRESS",
                    ADDRESS.replace("สุขุมวิท", "สุขุมวิธ").replace("คลองเตย ก", "คลองเตยก"),
                )
            ),
            verify(),
        ],
    ),
    # Four edits incl. the second character: needs one edit per 10 characters
    # and only the first character exact (approved 2026-10-12).
    "near_copy_needs_the_wide_budget": (
        f"ผู้ร้องอยู่{ADDRESS} แจ้งว่า",
        [
            detect(
                (
                    "ADDRESS",
                    ADDRESS.replace("บ้าน", "บ่าน")
                    .replace("สุขุมวิท", "สุขุมวิธ")
                    .replace("แขวงคลองเตย", "แขวงคลองเตม")
                    .replace("กรุงเทพ", "กรุงเทบ"),
                )
            ),
            verify(),
        ],
    ),
    # Approved 2026-10-15: a changed last letter must not leave the rest of
    # the last word visible.
    "near_copy_last_letter_changed": (
        f"ผู้ร้องอยู่{ADDRESS} แจ้งว่า",
        [
            detect(
                (
                    "ADDRESS",
                    ADDRESS.replace("สุขุมวิท", "สุขุมวิธ").replace("มหานคร", "มหานคน"),
                )
            ),
            verify(),
        ],
    ),
    "page_break_pieces": (
        "ผู้ร้องอยู่บ้านเลขที่ 12 ถนนสุขุมวิท\n\n---\n\n12\n\nแขวงคลองเตย เขตคลองเตย ต่อมา",
        [detect(("ADDRESS", "บ้านเลขที่ 12 ถนนสุขุมวิท แขวงคลองเตย เขตคลองเตย")), verify()],
    ),
    # One-level locations are not taken by the land-location rule.
    "residual_land_placeholder_trimmed": (
        "ที่ดินตาม น.ส. 3 ก. เลขที่ 123 ตำบลทดสอบ ต่อมา",
        [
            detect(),
            verify("ADDRESS"),
            detect(("ADDRESS", "[PII_TITLE_DEED_NUMBER_1] ตำบลทดสอบ")),
            verify(),
        ],
    ),
    # Approved 2026-10-15: the rule masks a labelled land number and its
    # location even when the model misses the location.
    "land_location_found_by_rule_when_llm_misses_it": (
        f"ที่ดินตาม น.ส. 3 ก. เลขที่ 123 {LOCATION} ต่อมา",
        [detect(), verify()],
    ),
    "land_location_inside_longer_llm_address": (
        f"ที่ดินโฉนดเลขที่ 123 {LOCATION} เนื้อที่ 2 ไร่ ต่อมา",
        [detect(("ADDRESS", f"123 {LOCATION} เนื้อที่ 2 ไร่")), verify()],
    ),
    "residual_no_progress_fails_closed": (
        f"ผู้ร้องอยู่ {LOCATION}",
        [detect(), verify("ADDRESS"), detect()],
    ),
    "residual_value_crossing_placeholder_fails_closed": (
        "ที่ดินตาม น.ส. 3 ก. เลขที่ 123 ตำบลทดสอบ ต่อมา",
        [
            detect(),
            verify("ADDRESS"),
            detect(("ADDRESS", "เลขที่ [PII_TITLE_DEED_NUMBER_1] ตำบลทดสอบ")),
        ],
    ),
    "proxy_504_is_retried": (
        "ผู้ร้อง นายสมชาย ใจดี",
        [status(504), detect(("NAME", "นายสมชาย ใจดี")), verify()],
    ),
    "proxy_timeout_is_retried": (
        "ผู้ร้อง นายสมชาย ใจดี",
        [TIMEOUT, detect(("NAME", "นายสมชาย ใจดี")), verify()],
    ),
    "proxy_rejects_credentials": (
        "ผู้ร้อง นายสมชาย ใจดี",
        [status(401)],
    ),
    "verification_unavailable_fails_closed": (
        "ผู้ร้อง นายสมชาย ใจดี",
        # One reply, three blank resends, one counted retry.
        [detect(("NAME", "นายสมชาย ใจดี")), BLANK, BLANK, BLANK, BLANK, BLANK],
    ),
    "labelled_identifiers_by_rules": (
        (
            "เลขประจำตัวประชาชน 1 2345 67890 12 3 บัญชีเงินฝากเลขที่ 123-4-56789-0 "
            "อีเมล somchai@example.com หนังสือที่ ศย 0001/123 คดีหมายเลขแดงที่ ก/2569"
        ),
        [detect(), verify()],
    ),
    "government_body_is_not_organization": (
        "สำนักงานที่ดินจังหวัดตัวอย่าง แจ้งว่า บริษัท ตัวอย่าง จำกัด เป็นผู้ซื้อ",
        [detect(("ORGANIZATION", "บริษัท ตัวอย่าง จำกัด")), verify()],
    ),
}

# Service-only requests the adapter rejects before any proxy call.
REJECTIONS = {
    "empty_body_is_rejected": {"body": b""},
    "too_long_body_is_rejected": {"body": ("ก" * 2001).encode("utf-8")},
    "wrong_content_type_is_rejected": {"headers": {"content-type": "application/json"}},
    "wrong_token_is_rejected": {"headers": {"authorization": "Bearer " + "x" * 40}},
}


async def build_one(name: str) -> dict:
    if name in REJECTIONS:
        request = REJECTIONS[name]
        transport = RecordingTransport(scripted([]))
        service = await run_service("ผู้ร้อง นายสมชาย ใจดี", transport, **request)
        return {
            "scenario": name,
            "source": "ผู้ร้อง นายสมชาย ใจดี",
            "request": {
                "body_utf8": None
                if "body" not in request
                else request["body"].decode(),
                "headers": request.get("headers", {}),
            },
            "calls": transport.calls,
            "service": service,
        }
    source, steps = SCENARIOS[name]
    service_transport = RecordingTransport(send := scripted(steps))
    service = await run_service(source, service_transport)
    if send.remaining:
        raise AssertionError(f"{name}: {len(send.remaining)} scripted replies unused")
    # The pipeline run must send the same requests; replay proves it.
    replay = ReplayTransport(service_transport.calls)
    pipeline = await run_pipeline(source, replay)
    if replay.mismatches or not replay.finished:
        raise AssertionError(
            f"{name}: pipeline and service requests differ {replay.mismatches}"
        )
    return {
        "scenario": name,
        "source": source,
        "calls": service_transport.calls,
        "service": service,
        "pipeline": pipeline,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build synthetic replay goldens")
    parser.add_argument(
        "--write", action="store_true", help="write tests/replay/*.json"
    )
    parser.add_argument("names", nargs="*")
    args = parser.parse_args()
    names = args.names or [*SCENARIOS, *REJECTIONS]
    GOLDEN_DIR.mkdir(exist_ok=True)
    for name in names:
        golden = asyncio.run(build_one(name))
        outcome = golden["service"]["response"]
        events = [e["event"] for e in golden.get("pipeline", {}).get("events", [])]
        print(
            f"{name}: status={outcome['status']} calls={len(golden['calls'])} "
            f"path={','.join(dict.fromkeys(events))}"
        )
        if args.write:
            (GOLDEN_DIR / f"{name}.json").write_text(
                json.dumps(golden, ensure_ascii=False, indent=1) + "\n",
                encoding="utf-8",
                newline="\n",
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
