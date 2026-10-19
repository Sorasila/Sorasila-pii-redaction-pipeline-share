"""Former location of ``pii_pipeline.llm.prompts`` (kept for existing imports)."""

import sys

from .llm import prompts as _module

sys.modules[__name__] = _module
