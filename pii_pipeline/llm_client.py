"""Former location of ``pii_pipeline.llm.client`` (kept for existing imports)."""

import sys

from .llm import client as _module

sys.modules[__name__] = _module
