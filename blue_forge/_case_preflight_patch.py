"""Fail-closed programmatic case-container and semantic-size preflight."""

from __future__ import annotations

from typing import Any


def install(core: Any) -> None:
    """Install exact-container and cumulative case-budget checks."""

    def exact_object(value: Any, label: str) -> dict[str, Any]:
        if type(value) is not dict:
            raise core.ValidationError(f"{label} must be an exact object")
        return value

    original_case_input_material = core._case_input_material

    def bounded_case_input_material(case: Any) -> dict[str, Any]:
        try:
            verification = case.verification
        except AttributeError as exc:
            raise core.ValidationError(
                f"invalid directly constructed hardening case: {exc}"
            ) from exc

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
