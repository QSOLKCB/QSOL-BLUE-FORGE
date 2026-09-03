"""Deterministic, non-executing BLUE-FORGE reference core."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any

CONTRACT = "blue-forge.core-invariants/v1"
CASE_SCHEMA = "blue-forge.hardening-case/v1"
RESULT_SCHEMA = "blue-forge.hardening-result/v1"
REGRESSION_SCHEMA = "blue-forge.regression-record/v1"

EXPECTED_PREDICATES = (
    "original_attack_neutralized",
    "attack_class_invariant_holds",
    "benign_controls_pass",
    "provenance_valid",
    "verification_complete",
    "replay_exact",
    "authority_not_expanded",
    "reference_equivalence_preserved",
)

COMPLETE_EVIDENCE_STATES = frozenset({
    "VULNERABLE", "BLOCKED", "HARMLESS", "ALLOWED", "PRESERVED",
})
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PRODUCER_ID = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:@/-]{0,127})$")
MAX_JSON_DEPTH = 32
MAX_ARRAY_ITEMS = 256
MAX_STRING_CHARS = 4096
MAX_INTEGER_DIGITS = 128
INVARIANT = re.compile(r"^BF-INV-(?:00[1-9]|01[0-6])$")
_EVALUATED_RESULT_TOKEN = object()


class BlueForgeError(Exception):
    """Base reference-core failure."""


class ValidationError(BlueForgeError):
    """Input violates the narrow BLUE-FORGE data contract."""


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"

    @property
    def rank(self) -> int:
        return {Decision.ALLOW: 0, Decision.REVIEW: 1, Decision.DENY: 2}[self]


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    raise ValidationError(f"floating-point values are not allowed: {value}")


def _reject_constant(value: str) -> Any:
    raise ValidationError(f"non-finite JSON value is not allowed: {value}")


def _parse_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_INTEGER_DIGITS:
        raise ValidationError(
            f"integer exceeds {MAX_INTEGER_DIGITS} decimal digits"
        )
    try:
        return int(value)
    except ValueError as exc:
        raise ValidationError(f"invalid JSON integer: {value!r}") from exc


def _validate_json_value(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValidationError(f"JSON nesting exceeds {MAX_JSON_DEPTH} at {path}")
    if value is None or type(value) in (int, bool):
        return
    if type(value) is str:
        if len(value) > MAX_STRING_CHARS:
            raise ValidationError(f"string exceeds {MAX_STRING_CHARS} characters at {path}")
        return
    if isinstance(value, float):
        raise ValidationError(f"floating-point values are not allowed at {path}")
    if isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise ValidationError(f"array exceeds {MAX_ARRAY_ITEMS} items at {path}")
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise ValidationError(f"object key is not a string at {path}")
            if len(key) > MAX_STRING_CHARS:
                raise ValidationError(
                    f"object key exceeds {MAX_STRING_CHARS} characters at {path}"
                )
            _validate_json_value(item, f"{path}.{key}", depth + 1)
        return
    raise ValidationError(f"unsupported JSON value at {path}: {type(value).__name__}")


def loads_strict(text: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except ValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValidationError(f"invalid or over-deep JSON: {exc}") from exc
    _validate_json_value(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    _validate_json_value(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"cannot canonicalize value: {exc}") from exc


def canonical_text(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{label} must be an array")
    if len(value) > MAX_ARRAY_ITEMS:
        raise ValidationError(f"{label} exceeds {MAX_ARRAY_ITEMS} items")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValidationError(
            f"{label} fields changed: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )


def _string(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or value != value.strip():
        raise ValidationError(f"{label} must be a non-empty trimmed string")
    return value


def _producer_id(value: Any, label: str) -> str:
    text = _string(value, label)
    if not PRODUCER_ID.fullmatch(text):
        raise ValidationError(
            f"{label} must use canonical ASCII producer-id syntax"
        )
    return text


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if not HEX64.fullmatch(text):
        raise ValidationError(f"{label} must be lowercase SHA-256 hex")
    return text


def _authority(value: Any, label: str) -> frozenset[str]:
    items = _array(value, label)
    if any(type(item) is not str or not item.strip() or item != item.strip() for item in items):
        raise ValidationError(f"{label} entries must be non-empty trimmed strings")
    if len(set(items)) != len(items):
        raise ValidationError(f"{label} contains duplicate capabilities")
    return frozenset(items)


def _decision(value: Any, label: str) -> Decision:
    try:
        return Decision(_string(value, label))
    except ValueError as exc:
        raise ValidationError(f"{label} is not a valid decision") from exc


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    kind: str
    before: str
    after: str
    provenance: str
    source_sha256: str
    reference_result_sha256: str
    replay_result_sha256: str

    @classmethod
    def from_dict(cls, value: Any, expected_kind: str) -> "Evidence":
        obj = _object(value, "evidence")
        _exact_keys(obj, {
            "id", "kind", "before", "after", "provenance",
            "source_sha256", "reference_result_sha256", "replay_result_sha256",
        }, "evidence")
        kind = _string(obj["kind"], "evidence.kind")
        if kind != expected_kind:
            raise ValidationError(
                f"evidence.kind must be {expected_kind!r}, got {kind!r}"
            )
        return cls(
            evidence_id=_string(obj["id"], "evidence.id"),
            kind=kind,
            before=_string(obj["before"], "evidence.before"),
            after=_string(obj["after"], "evidence.after"),
            provenance=_string(obj["provenance"], "evidence.provenance"),
            source_sha256=_sha256(obj["source_sha256"], "evidence.source_sha256"),
            reference_result_sha256=_sha256(
                obj["reference_result_sha256"], "evidence.reference_result_sha256"
            ),
            replay_result_sha256=_sha256(
                obj["replay_result_sha256"], "evidence.replay_result_sha256"
            ),
        )

    def complete(self) -> bool:
        return (
            self.before in COMPLETE_EVIDENCE_STATES
            and self.after in COMPLETE_EVIDENCE_STATES
        )


@dataclass(frozen=True)
class Proposal:
    producer: str
    mitigation_id: str
    decision: Decision
    pre_mitigation_authority: frozenset[str]
    requested_authority: frozenset[str]
    policy_authority: frozenset[str]

    @classmethod
    def from_dict(cls, value: Any) -> "Proposal":
        obj = _object(value, "proposal")
        _exact_keys(obj, {
            "producer", "mitigation_id", "decision",
            "pre_mitigation_authority", "requested_authority", "policy_authority",
        }, "proposal")
        return cls(
            producer=_producer_id(obj["producer"], "proposal.producer"),
            mitigation_id=_string(obj["mitigation_id"], "proposal.mitigation_id"),
            decision=_decision(obj["decision"], "proposal.decision"),
            pre_mitigation_authority=_authority(
                obj["pre_mitigation_authority"], "proposal.pre_mitigation_authority"
            ),
            requested_authority=_authority(
                obj["requested_authority"], "proposal.requested_authority"
            ),
            policy_authority=_authority(
                obj["policy_authority"], "proposal.policy_authority"
            ),
        )


@dataclass(frozen=True)
class Verification:
    producer: str
    decision: Decision
    observed_authority: frozenset[str]
    original: Evidence
    variants: tuple[Evidence, ...]
    benign_controls: tuple[Evidence, ...]
    reference_result_sha256: str
    candidate_result_sha256: str

    @classmethod
    def from_dict(cls, value: Any) -> "Verification":
        obj = _object(value, "verification")
        _exact_keys(obj, {
            "producer", "decision", "observed_authority", "original", "variants",
            "benign_controls", "reference_result_sha256", "candidate_result_sha256",
        }, "verification")
        return cls(
            producer=_producer_id(obj["producer"], "verification.producer"),
            decision=_decision(obj["decision"], "verification.decision"),
            observed_authority=_authority(
                obj["observed_authority"], "verification.observed_authority"
            ),
            original=Evidence.from_dict(obj["original"], "hostile"),
            variants=tuple(
                Evidence.from_dict(item, "hostile")
                for item in _array(obj["variants"], "verification.variants")
            ),
            benign_controls=tuple(
                Evidence.from_dict(item, "benign")
                for item in _array(obj["benign_controls"], "verification.benign_controls")
            ),
            reference_result_sha256=_sha256(
                obj["reference_result_sha256"], "verification.reference_result_sha256"
            ),
            candidate_result_sha256=_sha256(
                obj["candidate_result_sha256"], "verification.candidate_result_sha256"
            ),
        )


@dataclass(frozen=True)
class HardeningCase:
    case_id: str
    invariant_id: str
    attack_class: str
    proposal: Proposal
    verification: Verification

    @classmethod
    def from_dict(cls, value: Any) -> "HardeningCase":
        obj = _object(value, "case")
        _exact_keys(obj, {
            "schema", "contract", "case_id", "invariant_id",
            "attack_class", "proposal", "verification",
        }, "case")
        if obj["schema"] != CASE_SCHEMA:
            raise ValidationError(f"unsupported case schema: {obj['schema']!r}")
        if obj["contract"] != CONTRACT:
            raise ValidationError(f"unsupported contract: {obj['contract']!r}")
        invariant = _string(obj["invariant_id"], "case.invariant_id")
        if not INVARIANT.fullmatch(invariant):
            raise ValidationError(f"invalid invariant id: {invariant!r}")
        proposal = Proposal.from_dict(obj["proposal"])
        verification = Verification.from_dict(obj["verification"])
        if proposal.producer == verification.producer:
            raise ValidationError("mitigation proposer cannot be the sole verifier")
        if verification.decision.rank < proposal.decision.rank:
            raise ValidationError(
                "verification decision weakens proposal decision within immutable run"
            )
        evidence_ids = [
            verification.original.evidence_id,
            *[item.evidence_id for item in verification.variants],
            *[item.evidence_id for item in verification.benign_controls],
        ]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValidationError("duplicate evidence id in hardening case")
        return cls(
            case_id=_string(obj["case_id"], "case.case_id"),
            invariant_id=invariant,
            attack_class=_string(obj["attack_class"], "case.attack_class"),
            proposal=proposal,
            verification=verification,
        )

    def evidence(self) -> tuple[Evidence, ...]:
        return (
            self.verification.original,
            *self.verification.variants,
            *self.verification.benign_controls,
        )


@dataclass(frozen=True, init=False)
class HardeningResult:
    """Immutable evaluator-created result with defensive-copy payload access."""

    _payload_bytes: bytes

    def __init__(
        self,
        payload: dict[str, Any],
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not _EVALUATED_RESULT_TOKEN:
            raise ValidationError("HardeningResult must be created by evaluate()")
        object.__setattr__(self, "_payload_bytes", canonical_bytes(payload))

    @classmethod
    def _from_evaluation(cls, payload: dict[str, Any]) -> "HardeningResult":
        return cls(payload, _token=_EVALUATED_RESULT_TOKEN)

    @property
    def payload(self) -> dict[str, Any]:
        value = loads_strict(self._payload_bytes.decode("utf-8"))
        if not isinstance(value, dict):
            raise AssertionError("hardening result payload is not an object")
        return value

    @property
    def hardened(self) -> bool:
        return self.payload["status"] == "BLUE_HARDENED"

    @property
    def receipt_sha256(self) -> str:
        return self.payload["receipt_sha256"]


def evaluate(case: HardeningCase) -> HardeningResult:
    """Derive BLUE_HARDENED from evidence. Nothing in this function executes evidence."""
    v = case.verification
    p = case.proposal
    all_evidence = case.evidence()

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
                item.before == "ALLOWED" and item.after == "PRESERVED"
                for item in v.benign_controls
            )
        ),
        "provenance_valid": all(item.provenance == "VERIFIED" for item in all_evidence),
        "verification_complete": (
            bool(v.variants)
            and bool(v.benign_controls)
            and all(item.complete() for item in all_evidence)
        ),
        "replay_exact": all(
            item.reference_result_sha256 == item.replay_result_sha256
            for item in all_evidence
        ),
        "authority_not_expanded": (
            v.observed_authority <= (p.requested_authority & p.policy_authority)
            and v.observed_authority <= p.pre_mitigation_authority
        ),
        "reference_equivalence_preserved": (
            v.reference_result_sha256 == v.candidate_result_sha256
        ),
    }
    assert tuple(predicates) == EXPECTED_PREDICATES

    failed = [name for name, passed in predicates.items() if not passed]
    decision = v.decision
    if not predicates["authority_not_expanded"]:
        decision = Decision.DENY
    elif failed and decision is Decision.ALLOW:
        decision = Decision.REVIEW

    case_sha256 = digest(_case_material(case))
    material: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "contract": CONTRACT,
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
    payload["receipt_sha256"] = digest(material)
    return HardeningResult._from_evaluation(payload)


def regression_record(case: HardeningCase, result: HardeningResult) -> dict[str, Any]:
    """Create deterministic permanent-regression memory bound to this exact case."""
    result_payload = result.payload
    expected_payload = evaluate(case).payload
    if result_payload != expected_payload:
        raise ValidationError("hardening result does not match supplied case")

    case_sha256 = digest(_case_material(case))
    if result_payload["case_sha256"] != case_sha256:
        raise ValidationError("hardening result case digest does not match supplied case")

    material: dict[str, Any] = {
        "schema": REGRESSION_SCHEMA,
        "contract": CONTRACT,
        "case_id": case.case_id,
        "case_sha256": case_sha256,
        "invariant_id": case.invariant_id,
        "attack_class": case.attack_class,
        "mitigation_id": case.proposal.mitigation_id,
        "hardening_status": result_payload["status"],
        "hardening_receipt_sha256": result.receipt_sha256,
        "hostile_evidence_ids": [
            case.verification.original.evidence_id,
            *[item.evidence_id for item in case.verification.variants],
        ],
        "benign_control_ids": [
            item.evidence_id for item in case.verification.benign_controls
        ],
        "source_sha256": sorted(item.source_sha256 for item in case.evidence()),
        "failed_predicates": list(result_payload["failed_predicates"]),
    }
    record = dict(material)
    record["record_sha256"] = digest(material)
    return record


def _case_material(case: HardeningCase) -> dict[str, Any]:
    p = case.proposal
    v = case.verification
    return {
        "contract": CONTRACT,
        "case_id": case.case_id,
        "invariant_id": case.invariant_id,
        "attack_class": case.attack_class,
        "proposal": {
            "producer": p.producer,
            "mitigation_id": p.mitigation_id,
            "decision": p.decision.value,
            "pre_mitigation_authority": sorted(p.pre_mitigation_authority),
            "requested_authority": sorted(p.requested_authority),
            "policy_authority": sorted(p.policy_authority),
        },
        "verification": {
            "producer": v.producer,
            "decision": v.decision.value,
            "observed_authority": sorted(v.observed_authority),
            "evidence": [
                {
                    "id": item.evidence_id,
                    "kind": item.kind,
                    "before": item.before,
                    "after": item.after,
                    "provenance": item.provenance,
                    "source_sha256": item.source_sha256,
                    "reference_result_sha256": item.reference_result_sha256,
                    "replay_result_sha256": item.replay_result_sha256,
                }
                for item in case.evidence()
            ],
            "reference_result_sha256": v.reference_result_sha256,
            "candidate_result_sha256": v.candidate_result_sha256,
        },
    }