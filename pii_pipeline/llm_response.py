"""Former location of ``pii_pipeline.llm.response`` (kept for existing imports)."""

import sys

from .llm import response as _module

sys.modules[__name__] = _module
