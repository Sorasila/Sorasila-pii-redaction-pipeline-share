"""Former location of ``pii_pipeline.core.redaction`` (kept for existing imports)."""

import sys

from .core import redaction as _module

sys.modules[__name__] = _module
