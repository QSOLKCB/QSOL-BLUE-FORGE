"""Case-bound HardeningResult provenance for the reference core."""

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
    """Make all result construction equivalent to evaluation of an originating case."""

    def payload_for_validated_case(case: Any) -> dict[str, Any]:
        return _payload_for_validated_case(core, case)

    def from_evaluation(cls: type[Any], case: Any) -> Any:
        validated_case = core._validated_case(case)
        return cls(validated_case, _token=core._EVALUATION_TOKEN)

    def evaluate(case: Any) -> Any:
        return core.HardeningResult._from_evaluation(case)

    core._payload_for_validated_case = payload_for_validated_case
    core.HardeningResult._from_evaluation = classmethod(from_evaluation)
    core.evaluate = evaluate
