"""Release classifier: which surfaces (core, php, magento) a release P..T changes, from the mirror's ASTs only."""

from .decision import classify_release, decide
from .gating import Level

__all__ = ["Level", "classify_release", "decide"]
