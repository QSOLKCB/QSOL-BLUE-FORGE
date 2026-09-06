"""Executable BLUE-FORGE JSON Schema vocabulary semantics.

This module implements the required cross-field keywords declared by
``schemas/blue-forge-hardening-meta-v1.schema.json``.  It deliberately stays
stdlib-only and can be used alongside any Draft 2020-12 structural validator.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Callable

from .core import ValidationError

VOCABULARY_URI = (
    "https://github.com/QSOLKCB/QSOL-BLUE-FORGE/"
    "vocab/source-uniqueness-v1"
)

KeywordValidator = Callable[[Any], None]


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be an object for BLUE-FORGE vocabulary validation")
    return value


def _unique_source_sha256(verification_value: Any) -> None:
    verification = _require_object(verification_value, "verification")
    evidence_maps: list[dict[str, Any]] = []
    for field in ("original", "variants", "benign_controls"):
        evidence_maps.append(_require_object(verification.get(field), f"verification.{field}"))

    source_digests: list[str] = []
    for evidence_map in evidence_maps:
        for evidence_id, body_value in evidence_map.items():
            body = _require_object(body_value, f"evidence[{evidence_id!r}]")
            digest = body.get("source_sha256")
            if not isinstance(digest, str):
                raise ValidationError(
                    f"evidence[{evidence_id!r}].source_sha256 must be a string"
                )
            source_digests.append(digest)

    if len(set(source_digests)) != len(source_digests):
        raise ValidationError(
            "evidence source_sha256 values must be unique across coverage roles"
        )


def _distinct_producers(case_value: Any) -> None:
    case = _require_object(case_value, "case")
    proposal = _require_object(case.get("proposal"), "proposal")
    verification = _require_object(case.get("verification"), "verification")
    proposal_producer = proposal.get("producer")
    verification_producer = verification.get("producer")
    if not isinstance(proposal_producer, str) or not isinstance(verification_producer, str):
        raise ValidationError("proposal.producer and verification.producer must be strings")
    if proposal_producer == verification_producer:
        raise ValidationError("mitigation proposer cannot be the sole verifier")


def _decision_monotonic(case_value: Any) -> None:
    case = _require_object(case_value, "case")
    proposal = _require_object(case.get("proposal"), "proposal")
    verification = _require_object(case.get("verification"), "verification")
    order = {"ALLOW": 0, "REVIEW": 1, "DENY": 2}
    proposal_decision = proposal.get("decision")
    verification_decision = verification.get("decision")
    if proposal_decision not in order or verification_decision not in order:
        raise ValidationError("proposal.decision and verification.decision must be valid decisions")
    if order[verification_decision] < order[proposal_decision]:
        raise ValidationError(
            "verification decision weakens proposal decision within immutable run"
        )


BLUE_FORGE_VOCABULARY = MappingProxyType({
    "blueForgeUniqueSourceSha256": _unique_source_sha256,
    "blueForgeDistinctProducers": _distinct_producers,
    "blueForgeDecisionMonotonic": _decision_monotonic,
})


def validate_case_schema_vocabulary(value: Any) -> None:
    """Apply every required BLUE-FORGE cross-field keyword to a case instance."""
    case = _require_object(value, "case")
    BLUE_FORGE_VOCABULARY["blueForgeDistinctProducers"](case)
    BLUE_FORGE_VOCABULARY["blueForgeDecisionMonotonic"](case)
    BLUE_FORGE_VOCABULARY["blueForgeUniqueSourceSha256"](
        _require_object(case.get("verification"), "verification")
    )
