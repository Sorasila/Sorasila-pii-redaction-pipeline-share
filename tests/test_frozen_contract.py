"""Values a structural refactor must not change (frozen 2026-10-15, main b0d26bf).

Prompts and schemas go to the LLM verbatim: any change can change its answers.
Update a hash only together with an approved prompt or schema version change.
"""

import dataclasses
import hashlib
import json

from pii_pipeline.llm import prompts as llm_prompts
from pii_pipeline.llm import schema as llm_schema
from pii_pipeline.llm.config import LlmProxySettings
from pii_pipeline.recovery.process import _REPAIR_INSTRUCTION, RecoveryPolicy
from pii_pipeline.service import ServiceSettings


def sha(value):
    text = (
        value
        if isinstance(value, str)
        else json.dumps(value, ensure_ascii=False, sort_keys=True)
    )
    return hashlib.sha256(text.encode()).hexdigest()


def test_prompt_versions_are_frozen():
    assert llm_prompts.DETECTION_PROMPT_VERSION == "pii-detection-v18"
    assert llm_prompts.VERIFICATION_PROMPT_VERSION == "pii-verification-v11"


def test_prompts_and_schemas_are_frozen():
    marker = "PII_OCCURRENCE_1_"
    assert {
        "detection_prompt": sha(llm_prompts.build_detection_prompt()),
        "verification_prompt": sha(llm_prompts.build_verification_prompt()),
        "occurrence_prompt": sha(llm_prompts.build_occurrence_selection_prompt(marker)),
        "conflict_prompt": sha(llm_prompts.build_conflict_selection_prompt(marker)),
        "repair_instruction": sha(_REPAIR_INSTRUCTION),
        "detection_schema": sha(llm_schema.build_detection_response_schema()),
        "verification_schema": sha(llm_schema.build_verification_response_schema()),
        "occurrence_schema": sha(llm_schema.build_occurrence_selection_schema((1, 2))),
    } == {
        "detection_prompt": "ef494cde4203a6da4107a9c56d186d4a485d2f0525b1d19a18d8145ca88ca1b6",
        "verification_prompt": "5b8da0110d9c15d8345366e5fba793c5ea54a3cb83d406952136ed638336a825",
        "occurrence_prompt": "a66233e481c6701200031461c220dcfc3af0f1b9bfe55a284c666a86b3a0c5bb",
        "conflict_prompt": "f510031348adc194a38da2660fd74ed3a1eb3bcb3e9c694adf4ba69dce248d42",
        "repair_instruction": "deb5194cb0001665274eb3a4964183c2e473638c81c7e1f8f81f05f3083b5a18",
        "detection_schema": "5d0fd6e15c53249db6fc31b1f48ae35f965ed064b315a162fdd2f7d803628f50",
        "verification_schema": "8287c602232a14e3a59db7bc0ac9253ef51152912612dd7a2c25b2135f3bb0ec",
        "occurrence_schema": "f9219a1a747ea4da3f94fca140b8af5baf435c1ab41a4608a4ea17025e7b5183",
    }


def test_recovery_policy_defaults_are_frozen():
    assert dataclasses.asdict(RecoveryPolicy()) == {
        "max_role_calls": 64,
        "max_recovery_calls": 4,
        "window_repair_attempts": 2,
        "verification_retry_attempts": 1,
        "conflict_selection_attempts": 1,
        "max_residual_rounds": 1,
        "deadline_seconds": 600.0,
        "reserved_recovery_calls": 0,
        "blank_response_retries": 3,
    }


def test_settings_defaults_and_env_prefixes_are_frozen():
    llm = {name: field.default for name, field in LlmProxySettings.model_fields.items()}
    assert {k: v for k, v in llm.items() if k not in {"base_url", "api_key"}} == {
        "model": "qwen/qwen3.6-27b",
        "ca_bundle": None,
        "verify_tls": True,
        "connect_timeout_seconds": 10,
        "read_timeout_seconds": 1800,
        "write_timeout_seconds": 30,
        "pool_timeout_seconds": 10,
        "request_deadline_seconds": 3600,
        "max_retries": 2,
        "retry_backoff_seconds": 1,
        "retry_backoff_cap_seconds": 10,
        "detection_use_thinking": False,
        "verification_use_thinking": False,
    }
    service = {
        name: field.default for name, field in ServiceSettings.model_fields.items()
    }
    assert {k: v for k, v in service.items() if k != "api_token"} == {
        "request_deadline_seconds": 7200,
        "max_source_characters": 10000,
        "allow_unencrypted_test_manifest": False,
        "return_manifest": False,
        "return_metadata": False,
        "enable_docs": False,
        "docs_username": None,
        "docs_password": None,
        "docs_token_ttl_seconds": 3600,
    }
    assert LlmProxySettings.model_config["env_prefix"] == "LLM_PROXY_"
    assert ServiceSettings.model_config["env_prefix"] == "PII_SERVICE_"
