"""Former location of ``pii_pipeline.core.models`` (kept for existing imports)."""

import sys

from .core import models as _module

sys.modules[__name__] = _module
