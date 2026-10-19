"""Former location of ``pii_pipeline.core.verification`` (kept for existing imports)."""

import sys

from .core import verification as _module

sys.modules[__name__] = _module
