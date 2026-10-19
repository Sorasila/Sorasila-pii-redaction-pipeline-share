"""Prepare .env for a local test run of the service, without printing secrets.

Usage (from the repository root):
    python tools/setup_service_env.py [--env-file .env]

- Creates .env from .env.example when it does not exist yet.
- Sets PII_SERVICE_API_TOKEN to a new random token when it is missing, empty or
  still the example placeholder. An existing real token is kept.
- Adds PII_SERVICE_ALLOW_UNENCRYPTED_TEST_MANIFEST=true and
  PII_SERVICE_RETURN_MANIFEST=true when the keys are absent, so test runs get
  the manifest part to compare with expected values. It is then NOT
  encrypted: test machines only (the service default returns no manifest).
- Reminds you which LLM_PROXY_ values still need real settings.

Values are never printed; only key names are.
"""

import argparse
import secrets
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOKEN_KEY = "PII_SERVICE_API_TOKEN"
FLAG_KEY = "PII_SERVICE_ALLOW_UNENCRYPTED_TEST_MANIFEST"
RETURN_KEY = "PII_SERVICE_RETURN_MANIFEST"
REQUIRED_PROXY_KEYS = ("LLM_PROXY_BASE_URL", "LLM_PROXY_API_KEY")
MIN_TOKEN_LENGTH = 32


def _entries(lines: list[str]) -> dict[str, int]:
    """Key -> line index for active (uncommented) KEY=value lines."""
    found = {}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            found[stripped.split("=", 1)[0].strip()] = index
    return found


def _value(line: str) -> str:
    return line.split("=", 1)[1].strip()


def _needs_token(value: str) -> bool:
    return len(value) < MIN_TOKEN_LENGTH or value.startswith("replace-with")


def prepare(env_file: Path, example: Path) -> list[str]:
    """Update env_file in place; return human-readable notes (no values)."""
    notes = []
    if not env_file.exists():
        if not example.exists():
            raise SystemExit(f"STOPPED: neither {env_file} nor {example} exists")
        shutil.copyfile(example, env_file)
        notes.append(f"Created {env_file.name} from {example.name}")

    lines = env_file.read_text(encoding="utf-8").splitlines()
    entries = _entries(lines)

    token_line = f"{TOKEN_KEY}={secrets.token_urlsafe(32)}"
    if TOKEN_KEY not in entries:
        lines.append(token_line)
        notes.append(f"Added {TOKEN_KEY} (value not shown)")
    elif _needs_token(_value(lines[entries[TOKEN_KEY]])):
        lines[entries[TOKEN_KEY]] = token_line
        notes.append(f"Replaced the placeholder {TOKEN_KEY} (value not shown)")
    else:
        notes.append(f"Kept the existing {TOKEN_KEY}")

    if FLAG_KEY not in entries:
        lines.append(f"{FLAG_KEY}=true")
        notes.append(f"Added {FLAG_KEY}=true (manifest NOT encrypted: test only)")
    else:
        notes.append(f"Kept the existing {FLAG_KEY}={_value(lines[entries[FLAG_KEY]])}")
    if RETURN_KEY not in entries:
        lines.append(f"{RETURN_KEY}=true")
        notes.append(f"Added {RETURN_KEY}=true (responses carry the test manifest)")
    else:
        notes.append(
            f"Kept the existing {RETURN_KEY}={_value(lines[entries[RETURN_KEY]])}"
        )

    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    for key in REQUIRED_PROXY_KEYS:
        index = entries.get(key)
        value = _value(lines[index]) if index is not None else ""
        if not value or "example" in value or value.startswith("replace-with"):
            notes.append(f"TODO: set a real {key} in {env_file.name}")
    return notes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env-file", type=Path, default=REPO / ".env")
    args = parser.parse_args()
    for note in prepare(args.env_file.resolve(), REPO / ".env.example"):
        print(note)


if __name__ == "__main__":
    main()
