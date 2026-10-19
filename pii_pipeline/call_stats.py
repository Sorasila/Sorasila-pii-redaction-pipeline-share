"""Former location of ``pii_pipeline.llm.call_stats`` (kept for existing imports)."""

import sys

from .llm import call_stats as _module

sys.modules[__name__] = _module
