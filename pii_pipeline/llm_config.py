"""Former location of ``pii_pipeline.llm.config`` (kept for existing imports)."""

import sys

from .llm import config as _module

sys.modules[__name__] = _module
