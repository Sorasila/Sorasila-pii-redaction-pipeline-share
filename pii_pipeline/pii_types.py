"""Former location of ``pii_pipeline.core.pii_types`` (kept for existing imports)."""

import sys

from .core import pii_types as _module

sys.modules[__name__] = _module
