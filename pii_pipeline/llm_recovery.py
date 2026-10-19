"""Former location of ``pii_pipeline.recovery.process`` (kept for existing imports)."""

import sys

from .recovery import process as _module

sys.modules[__name__] = _module
