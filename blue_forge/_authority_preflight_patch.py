"""Bound direct-case authority containers before deterministic normalization."""

from __future__ import annotations

from typing import Any


def install(core: Any) -> None:
    """Reject malformed authority containers before any sorting or iteration burst."""

    original_case_input_material = core._case_input_material

    def preflight_authority(value: Any, label: str) -> None:
        if type(value) is not frozenset:
            raise core.ValidationError(f"{label} must be an exact frozenset")
        if len(value) > core.MAX_ARRAY_ITEMS:
            raise core.ValidationError(
                f"{label} exceeds {core.MAX_ARRAY_ITEMS} items"
            )
        # Iteration is safe only after the exact built-in container and bounded
        # cardinality have been established. Validate element domain before the
        # original serializer reaches sorted().
        for item in value:
            core._string(item, f"{label} entry")

    def case_input_material(case: Any) -> dict[str, Any]:
        try:
            proposal = case.proposal
            verification = case.verification
        except AttributeError as exc:
            raise core.ValidationError(
                f"invalid directly constructed hardening case: {exc}"
            ) from exc

        preflight_authority(
            proposal.pre_mitigation_authority,
            "proposal.pre_mitigation_authority",
        )
        preflight_authority(
            proposal.requested_authority,
            "proposal.requested_authority",
        )
        preflight_authority(
            proposal.policy_authority,
            "proposal.policy_authority",
        )
        preflight_authority(
            verification.observed_authority,
            "verification.observed_authority",
        )
        return original_case_input_material(case)

    core._case_input_material = case_input_material
