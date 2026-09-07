"""Case-bound HardeningResult semantics for the reference core."""

from __future__ import annotations

from typing import Any


def _payload_for_validated_case(core: Any, case: Any) -> dict[str, Any]:
    """Recompute the complete deterministic evaluator payload from a validated case."""
    v = case.verification
    p = case.proposal
    all_evidence = case.evidence()

    reference_engine_ids = {
        item.reference_engine_sha256 for item in all_evidence
    }
    predicates = {
        "original_attack_neutralized": (
            v.original.before == "VULNERABLE"
            and v.original.after in {"BLOCKED", "HARMLESS"}
        ),
        "attack_class_invariant_holds": (
            bool(v.variants)
            and all(
                item.before == "VULNERABLE"
                and item.after in {"BLOCKED", "HARMLESS"}
                for item in v.variants
            )
        ),
        "benign_controls_pass": (
            bool(v.benign_controls)
            and all(
                item.before == "ALLOWED"
                and item.after == "PRESERVED"
                for item in v.benign_controls
            )
        ),
        "provenance_valid": all(
            item.provenance == "VERIFIED" for item in all_evidence
        ),
        "verification_complete": (
            bool(v.variants)
            and bool(v.benign_controls)
            and all(item.complete() for item in all_evidence)
        ),
        "replay_exact": (
            len(reference_engine_ids) == 1
            and all(
                item.reference_engine_sha256 == item.replay_engine_sha256
                and item.reference_result_sha256 == item.replay_result_sha256
                for item in all_evidence
            )
        ),
        "authority_not_expanded": (
            v.observed_authority <= (p.requested_authority & p.policy_authority)
            and v.observed_authority <= p.pre_mitigation_authority
        ),
        "reference_equivalence_preserved": (
            v.reference_result_sha256 == v.candidate_result_sha256
        ),
    }
    if tuple(predicates) != core.EXPECTED_PREDICATES:
        raise AssertionError("hardening predicate order changed")

    failed = [name for name, passed in predicates.items() if not passed]
    decision = v.decision
    if not predicates["authority_not_expanded"]:
        decision = core.Decision.DENY
    elif failed and decision is core.Decision.ALLOW:
        decision = core.Decision.REVIEW

    case_sha256 = core.digest(core._case_material(case))
    material: dict[str, Any] = {
        "schema": core.RESULT_SCHEMA,
        "contract": core.CONTRACT,
        "case_id": case.case_id,
        "case_sha256": case_sha256,
        "invariant_id": case.invariant_id,
        "attack_class": case.attack_class,
        "mitigation_id": p.mitigation_id,
        "proposal_producer": p.producer,
        "verification_producer": v.producer,
        "decision": decision.value,
        "effective_authority": sorted(v.observed_authority),
        "predicates": predicates,
        "failed_predicates": failed,
        "status": "BLUE_HARDENED" if not failed else "NOT_HARDENED",
    }
    payload = dict(material)
    payload["receipt_sha256"] = core.digest(material)
    return payload


def install(core: Any) -> None:
    """Install an immutable deterministic result value bound to canonical case bytes.

    A HardeningResult is deliberately not an in-process attestation that a
    particular Python call to evaluate() created the object. Python callers can
    reconstruct immutable tuple values through base allocators, so construction
    history is not used as provenance. Security-relevant consumers instead
    revalidate the embedded canonical case and recompute the complete payload;
    regression_record() additionally requires that recomputation to match its
    independently supplied case.
    """

    def payload_for_validated_case(case: Any) -> dict[str, Any]:
        return _payload_for_validated_case(core, case)

    class HardeningResult(tuple):
        """Immutable case-derived value; construction history is not provenance."""

        __slots__ = ()

        def __new__(
            cls,
            originating_case: Any,
            *,
            _token: object | None = None,
        ) -> Any:
            # Preserve the public factory boundary as an API misuse guard. This
            # token is not treated as security provenance by any result consumer.
            if _token is not core._EVALUATION_TOKEN:
                raise core.ValidationError("HardeningResult must be created by evaluate()")
            if type(originating_case) is not core.HardeningCase:
                raise core.ValidationError(
                    "HardeningResult construction requires an originating HardeningCase"
                )
            validated_case = core._validated_case(originating_case)
            case_material = core._case_input_material(validated_case)
            case_bytes = core.canonical_bytes(case_material)
            return tuple.__new__(cls, (case_bytes,))

        def __init__(
            self,
            originating_case: Any,
            *,
            _token: object | None = None,
        ) -> None:
            del originating_case, _token

        def _bound_case_bytes(self) -> bytes:
            if tuple.__len__(self) != 1:
                raise core.ValidationError("hardening result case binding is invalid")
            case_bytes = tuple.__getitem__(self, 0)
            if type(case_bytes) is not bytes:
                raise core.ValidationError("hardening result case binding is invalid")
            return case_bytes

        @property
        def _case_bytes(self) -> bytes:
            return self._bound_case_bytes()

        @classmethod
        def _from_evaluation(cls, case: Any) -> Any:
            return cls(case, _token=core._EVALUATION_TOKEN)

        def _recomputed_payload(self) -> dict[str, Any]:
            try:
                case_value = core.loads_strict(
                    self._bound_case_bytes().decode("utf-8")
                )
            except (AttributeError, UnicodeDecodeError, IndexError, TypeError) as exc:
                raise core.ValidationError("hardening result case binding is invalid") from exc
            case = core.HardeningCase.from_dict(case_value)
            validated_case = core._validated_case(case)
            payload = payload_for_validated_case(validated_case)
            validator = getattr(core, "_validate_result_payload", None)
            if not callable(validator):
                raise core.ValidationError("hardening result validator is unavailable")
            validator(payload)
            return payload

        @property
        def payload(self) -> dict[str, Any]:
            return self._recomputed_payload()

        @property
        def hardened(self) -> bool:
            return self._recomputed_payload()["status"] == "BLUE_HARDENED"

        @property
        def receipt_sha256(self) -> str:
            return self._recomputed_payload()["receipt_sha256"]

    HardeningResult.__name__ = "HardeningResult"
    HardeningResult.__qualname__ = "HardeningResult"
    HardeningResult.__module__ = core.__name__

    def evaluate(case: Any) -> Any:
        return HardeningResult._from_evaluation(case)

    core._payload_for_validated_case = payload_for_validated_case
    core.HardeningResult = HardeningResult
    core.evaluate = evaluate
