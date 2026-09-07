"""Fail-closed programmatic case-container and semantic-size preflight."""

from __future__ import annotations

from typing import Any


def install(core: Any) -> None:
    """Install exact-container, record-type, and cumulative case-budget checks."""

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
        # This boundary is reached by evaluate()/regression revalidation before
        # the original serializer reads any fields.  Reject subclasses by exact
        # identity so an overridden __getattribute__ cannot execute first.
        if type(case) is not core.HardeningCase:
            raise core.ValidationError(
                "direct hardening case must be an exact HardeningCase"
            )

        proposal = object.__getattribute__(case, "proposal")
        verification = object.__getattribute__(case, "verification")
        if type(proposal) is not core.Proposal:
            raise core.ValidationError("case.proposal must be an exact Proposal")
        if type(verification) is not core.Verification:
            raise core.ValidationError(
                "case.verification must be an exact Verification"
            )

        # Establish the exact nested record types before reading any of their
        # members.  dataclasses.replace() is a construction mechanism, not a
        # validation boundary, so every directly supplied record is rechecked.
        original = object.__getattribute__(verification, "original")
        if type(original) is not core.Evidence:
            raise core.ValidationError(
                "verification.original must be an exact Evidence"
            )

        variants = object.__getattribute__(verification, "variants")
        if type(variants) is not tuple:
            raise core.ValidationError("verification.variants must be an exact tuple")
        if not variants or len(variants) > core.MAX_VARIANT_ITEMS:
            raise core.ValidationError(
                f"verification.variants must contain 1..{core.MAX_VARIANT_ITEMS} evidence entries"
            )
        for item in variants:
            if type(item) is not core.Evidence:
                raise core.ValidationError(
                    "verification.variants entries must be exact Evidence instances"
                )

        benign = object.__getattribute__(verification, "benign_controls")
        if type(benign) is not tuple:
            raise core.ValidationError(
                "verification.benign_controls must be an exact tuple"
            )
        if not benign or len(benign) > core.MAX_ARRAY_ITEMS:
            raise core.ValidationError(
                f"verification.benign_controls must contain 1..{core.MAX_ARRAY_ITEMS} evidence entries"
            )
        for item in benign:
            if type(item) is not core.Evidence:
                raise core.ValidationError(
                    "verification.benign_controls entries must be exact Evidence instances"
                )

        # The original serializer dereferences ``decision.value`` before the
        # reconstructed case reaches HardeningCase.from_dict().  For direct or
        # dataclasses.replace()-modified cases, require the exact enum first so
        # a duck-typed object cannot manufacture a valid decision or execute an
        # attacker-controlled property at the evaluator boundary.
        proposal_decision = object.__getattribute__(proposal, "decision")
        verification_decision = object.__getattribute__(verification, "decision")
        if type(proposal_decision) is not core.Decision:
            raise core.ValidationError(
                "proposal.decision must be an exact Decision"
            )
        if type(verification_decision) is not core.Decision:
            raise core.ValidationError(
                "verification.decision must be an exact Decision"
            )

        # The serializer hashes these IDs for duplicate detection and uses them
        # as mapping keys. Validate the exact bounded string domain first, so a
        # programmatically replaced ID cannot execute __hash__ or __eq__ there.
        core._evidence_id(
            object.__getattribute__(original, "evidence_id"),
            "original",
            "verification.original evidence id",
        )
        for item in variants:
            core._evidence_id(
                object.__getattribute__(item, "evidence_id"),
                "variant",
                "verification.variants evidence id",
            )
        for item in benign:
            core._evidence_id(
                object.__getattribute__(item, "evidence_id"),
                "benign",
                "verification.benign_controls evidence id",
            )

        return original_case_input_material(case)

    original_from_dict = core.HardeningCase.from_dict

    def bounded_from_dict(cls: Any, value: Any) -> Any:
        case = original_from_dict(value)
        # A public factory must never return a case outside the same cumulative
        # semantic byte domain enforced by canonicalization, schema vocabulary,
        # strict parsing and the CLI.
        core.canonical_bytes(core._case_input_material(case))
        return case

    original_validated_case = core._validated_case

    def exact_validated_case(case: Any) -> Any:
        # Fail before the older isinstance()-based boundary can delegate to any
        # field access on a HardeningCase subclass.
        if type(case) is not core.HardeningCase:
            raise core.ValidationError("evaluate() requires an exact HardeningCase")
        return original_validated_case(case)

    core._object = exact_object
    core._case_input_material = bounded_case_input_material
    core.HardeningCase.from_dict = classmethod(bounded_from_dict)
    core._validated_case = exact_validated_case
