"""QSOL-BLUE-FORGE deterministic defensive reference core."""

from . import core as _core
from ._validation_patch import install as _install_validation

_install_validation(_core)

from .core import (
    BlueForgeError,
    HardeningCase,
    HardeningResult,
    ValidationError,
    canonical_bytes,
    canonical_text,
    digest,
    evaluate,
    loads_strict,
    regression_record,
)

__all__ = [
    "BlueForgeError",
    "ValidationError",
    "HardeningCase",
    "HardeningResult",
    "canonical_bytes",
    "canonical_text",
    "digest",
    "loads_strict",
    "evaluate",
    "regression_record",
]
