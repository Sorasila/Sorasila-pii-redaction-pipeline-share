"""Tools and synthetic pages that let a fresh clone run the service."""

import hashlib
import importlib.util
import json
import os
import unicodedata
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import ValidationError

from pii_pipeline.llm.config import LLM_PROXY_MODEL, LlmProxySettings
from pii_pipeline.llm.response import parse_detection_response
from pii_pipeline.rules.thai import detect_thai_rule_pii
from pii_pipeline.service import ServiceSettings, create_service_app

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "samples" / "synthetic"
TOKEN = "t" * 40


def load_tool(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


setup_env = load_tool("setup_service_env")
client = load_tool("redact_client")


# --- setup_service_env.py -------------------------------------------------


def test_setup_creates_env_from_example_with_a_fresh_token(tmp_path):
    example = tmp_path / ".env.example"
    example.write_text(
        "LLM_PROXY_BASE_URL=https://llm-proxy.example:9001\n"
        "LLM_PROXY_API_KEY=replace-with-a-local-secret\n"
        "# PII_SERVICE_API_TOKEN=\n",
        encoding="utf-8",
    )
    env = tmp_path / ".env"
    notes = setup_env.prepare(env, example)
    values = client.read_env_file(env)
    token = values["PII_SERVICE_API_TOKEN"]
    assert len(token) >= 32 and not token.startswith("replace-with")
    assert values["PII_SERVICE_ALLOW_UNENCRYPTED_TEST_MANIFEST"] == "true"
    assert values["PII_SERVICE_RETURN_MANIFEST"] == "true"
    assert "TODO: set a real LLM_PROXY_BASE_URL in .env" in notes
    assert "TODO: set a real LLM_PROXY_API_KEY in .env" in notes
    assert all(token not in note for note in notes)
    # A second run keeps the real token.
    setup_env.prepare(env, example)
    assert client.read_env_file(env)["PII_SERVICE_API_TOKEN"] == token


def test_setup_replaces_the_example_placeholder_token(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "LLM_PROXY_BASE_URL=https://proxy.internal\nLLM_PROXY_API_KEY=k\n"
        "PII_SERVICE_API_TOKEN=replace-with-at-least-32-random-characters\n",
        encoding="utf-8",
    )
    notes = setup_env.prepare(env, tmp_path / "missing.example")
    token = client.read_env_file(env)["PII_SERVICE_API_TOKEN"]
    assert not token.startswith("replace-with")
    assert any(note.startswith("Replaced the placeholder") for note in notes)
    assert not any(note.startswith("TODO") for note in notes)


def test_service_rejects_the_example_placeholder_token():
    with pytest.raises(ValidationError):
        ServiceSettings(
            api_token="replace-with-at-least-32-random-characters", _env_file=None
        )


# --- redact_client.py -----------------------------------------------------


def test_client_checks_pages_before_sending(tmp_path):
    assert client.page_problem("ก".encode() * 10, 10) is None
    assert client.page_problem("ก".encode() * 11, 10) == "too_long_11_code_points"
    assert client.page_problem(b"\xff", 10) == "not_utf8"
    assert client.page_problem(b"  \n", 10) == "empty"
    repository = tmp_path / "repo"
    (repository / ".git").mkdir(parents=True)
    assert client.inside_git_repository(repository / "results" / "run-1")
    assert not client.inside_git_repository(tmp_path / "outside")


def _wire(request):
    form = {
        key: values[0] for key, values in parse_qs(request.content.decode()).items()
    }
    role = next(iter(json.loads(form["json_schema"])["properties"]))
    output = (
        {"candidates": [{"pii_type": "NAME", "value": "นายสมมุติ ทดลองดี"}]}
        if role == "candidates"
        else {"has_pii": False, "findings": []}
    )
    return httpx.Response(
        200,
        json={
            "status": "success",
            "model": LLM_PROXY_MODEL,
            "structured_output": output,
        },
    )


@pytest.mark.asyncio
async def test_client_saves_the_three_parts_from_a_real_service_response(
    tmp_path, monkeypatch
):
    for name in list(os.environ):
        if name.startswith(("LLM_PROXY_", "PII_SERVICE_")):
            monkeypatch.delenv(name)
    app = create_service_app(
        ServiceSettings(
            api_token=TOKEN,
            allow_unencrypted_test_manifest=True,
            return_manifest=True,
            _env_file=None,
        ),
        LlmProxySettings(
            base_url="https://proxy.example", api_key="k", max_retries=0, _env_file=None
        ),
        llm_transport=httpx.MockTransport(_wire),
    )
    page = (SAMPLES / "page-1.md").read_bytes()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://service.local"
        ) as caller,
    ):
        response = await caller.post(
            "/redact",
            content=page,
            headers={
                "content-type": "text/markdown; charset=utf-8",
                "authorization": f"Bearer {TOKEN}",
            },
        )
    assert response.status_code == 200
    record = client.save_success(tmp_path, "page-1", client.multipart_parts(response))
    assert record["status"] == "VERIFIED" and record["hash_ok"] is True
    assert record["manifest"] == "plaintext_test"
    assert record["entries_by_type"]["NAME"] == 1
    redacted = (tmp_path / "page-1.redacted.md").read_text(encoding="utf-8")
    assert "[PII_NAME_1]" in redacted and "[PII_CASE_NUMBER_2]" in redacted
    assert "นายสมมุติ ทดลองดี" not in redacted
    assert (tmp_path / "page-1.manifest.json").exists()
    assert (tmp_path / "page-1.metadata.json").exists()


# --- samples/synthetic ----------------------------------------------------

EXPECTED_RULES = {
    "page-1.md": {
        "CASE_NUMBER": 2,
        "ID_NUMBER": 1,
        "PHONE": 1,
        "OFFICIAL_LETTER_NUMBER": 2,
    },
    "page-2.md": {
        "TITLE_DEED_NUMBER": 1,
        "FAX": 1,
        "EMAIL": 1,
        "BANK_ACCOUNT_NUMBER": 1,
        "OFFICIAL_LETTER_NUMBER": 1,
    },
    "page-3.md": {
        "CASE_NUMBER": 1,
        "BANK_ACCOUNT_NUMBER": 1,
        "PASSPORT_NUMBER": 1,
        "PHONE": 1,
    },
}


@pytest.mark.parametrize("name", sorted(EXPECTED_RULES))
def test_synthetic_pages_are_valid_requests_with_the_documented_rule_hits(name):
    text = (SAMPLES / name).read_text(encoding="utf-8")
    assert client.page_problem(text.encode("utf-8"), client.DEFAULT_MAX_CODE_POINTS) is None
    assert unicodedata.is_normalized("NFC", text)
    assert "[PII_" not in text
    assert "ข้อมูลสังเคราะห์" in text
    found = Counter(match.pii_type for match in detect_thai_rule_pii(text))
    assert dict(found) == EXPECTED_RULES[name]


def test_page_three_address_joined_across_the_page_break_resolves_in_two_parts():
    text = (SAMPLES / "page-3.md").read_text(encoding="utf-8")
    joined = "ห้องชุดเลขที่ 88/8 ชั้นที่ 8 อาคารเลขที่ 8 แขวงสมมุติ เขตทดลอง กรุงเทพมหานคร"
    matches = parse_detection_response(
        text, {"candidates": [{"pii_type": "ADDRESS", "value": joined}]}
    )
    assert [match.value for match in matches] == [
        "ห้องชุดเลขที่ 88/8\nชั้นที่ 8 อาคารเลขที่ 8",
        "แขวงสมมุติ เขตทดลอง กรุงเทพมหานคร",
    ]


def test_client_saves_a_plain_markdown_response(tmp_path):
    # The default service response: the redacted Markdown alone.
    response = httpx.Response(
        200,
        headers={"content-type": "text/markdown; charset=utf-8"},
        content="ชื่อ [PII_NAME_1]".encode(),
    )
    parts = client.multipart_parts(response)
    assert parts == {"redacted_md": "ชื่อ [PII_NAME_1]".encode()}
    record = client.save_success(tmp_path, "page-1", parts)
    assert record == {
        "status": "VERIFIED",
        "hash_ok": None,
        "manifest": "not_returned",
        "entries_by_type": {},
    }
    assert [p.name for p in tmp_path.iterdir()] == ["page-1.redacted.md"]


def test_client_saves_two_parts_when_no_manifest_is_returned(tmp_path):
    # PII_SERVICE_RETURN_MANIFEST off (the default): no manifest file at all.
    redacted = "ชื่อ [PII_NAME_1]".encode()
    metadata = json.dumps(
        {"redacted_md_sha256": hashlib.sha256(redacted).hexdigest()}
    ).encode()
    record = client.save_success(
        tmp_path, "page-1", {"redacted_md": redacted, "metadata": metadata}
    )
    assert record == {
        "status": "VERIFIED",
        "hash_ok": True,
        "manifest": "not_returned",
        "entries_by_type": {},
    }
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "page-1.metadata.json",
        "page-1.redacted.md",
    ]
