"""QSOL-BLUE-FORGE deterministic defensive reference core."""

from . import core as _core
from ._validation_patch import install as _install_validation
from ._json_snapshot_patch import install as _install_json_snapshot
from ._result_provenance_patch import install as _install_result_provenance

_install_validation(_core)
_install_json_snapshot(_core)
_install_result_provenance(_core)

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
