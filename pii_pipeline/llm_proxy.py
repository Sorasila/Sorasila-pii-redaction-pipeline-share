"""Former location of ``pii_pipeline.llm.proxy`` (kept for existing imports)."""

import sys

from .llm import proxy as _module

sys.modules[__name__] = _module
