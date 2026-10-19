"""Former location of ``pii_pipeline.llm.schema`` (kept for existing imports)."""

import sys

from .llm import schema as _module

sys.modules[__name__] = _module
