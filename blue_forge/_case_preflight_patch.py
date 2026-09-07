"""Fail-closed programmatic case-container and semantic-size preflight."""

from __future__ import annotations

from typing import Any


def install(core: Any) -> None:
    """Install exact-container and cumulative case-budget checks."""

    def exact_object(value: Any, label: str) -> dict[str, Any]:
        if type(value) is not dict:
            raise core.ValidationError(f"{label} must be an exact object")
        # Exact built-in dict cardinality is safe to inspect in O(1). Enforce the
        # shared object ceiling before _exact_keys() or any downstream scan can
        # traverse attacker-controlled programmatic mappings.
        if len(value) > core.MAX_OBJECT_ITEMS:
            raise core.ValidationError(
                f"{label} exceeds {core.MAX_OBJECT_ITEMS} members"
            )
        return value

    original_case_input_material = core._case_input_material

    def bounded_case_input_material(case: Any) -> dict[str, Any]:
        try:
            proposal = case.proposal
            verification = case.verification
        except AttributeError as exc:
            raise core.ValidationError(
                f"invalid directly constructed hardening case: {exc}"
            ) from exc

        # The original serializer dereferences ``decision.value`` before the
        # reconstructed case reaches HardeningCase.from_dict().  For direct or
        # dataclasses.replace()-modified cases, require the exact enum first so
        # a duck-typed object cannot manufacture a valid decision or execute an
        # attacker-controlled property at the evaluator boundary.
        if type(proposal.decision) is not core.Decision:
            raise core.ValidationError(
                "proposal.decision must be an exact Decision"
            )
        if type(verification.decision) is not core.Decision:
            raise core.ValidationError(
                "verification.decision must be an exact Decision"
            )

        variants = verification.variants
        if type(variants) is not tuple:
            raise core.ValidationError("verification.variants must be an exact tuple")
        if not variants or len(variants) > core.MAX_VARIANT_ITEMS:
            raise core.ValidationError(
                f"verification.variants must contain 1..{core.MAX_VARIANT_ITEMS} evidence entries"
            )

        benign = verification.benign_controls
        if type(benign) is not tuple:
            raise core.ValidationError(
                "verification.benign_controls must be an exact tuple"
            )
        if not benign or len(benign) > core.MAX_ARRAY_ITEMS:
            raise core.ValidationError(
                f"verification.benign_controls must contain 1..{core.MAX_ARRAY_ITEMS} evidence entries"
            )

        # The serializer hashes these IDs for duplicate detection and uses them
        # as mapping keys. Validate the exact bounded string domain first, so a
        # programmatically replaced ID cannot execute __hash__ or __eq__ there.
        core._evidence_id(
            verification.original.evidence_id, "original", "verification.original evidence id"
        )
        for item in variants:
            core._evidence_id(item.evidence_id, "variant", "verification.variants evidence id")
        for item in benign:
            core._evidence_id(item.evidence_id, "benign", "verification.benign_controls evidence id")

        return original_case_input_material(case)

    original_from_dict = core.HardeningCase.from_dict

    def bounded_from_dict(cls: Any, value: Any) -> Any:
        case = original_from_dict(value)
        # A public factory must never return a case outside the same cumulative
        # semantic byte domain enforced by canonicalization, schema vocabulary,
        # strict parsing and the CLI.
        core.canonical_bytes(core._case_input_material(case))
        return case

    core._object = exact_object
    core._case_input_material = bounded_case_input_material
    core.HardeningCase.from_dict = classmethod(bounded_from_dict)
