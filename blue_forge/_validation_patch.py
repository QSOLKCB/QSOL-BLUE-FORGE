"""Fail-closed JSON, diagnostic and result hardening for the reference core."""

from __future__ import annotations

import json
from typing import Any

MAX_OBJECT_ITEMS = 512
MAX_EXPANDED_JSON_NODES = 16384
MAX_JSON_BYTES = 1024 * 1024
MAX_CANONICAL_BYTES = MAX_JSON_BYTES
MAX_JSON_TEXT_BYTES = MAX_JSON_BYTES


def _member_path(path: str, key: str) -> str:
    """Render an object member path without allowing control-character log injection."""
    rendered = json.dumps(key, ensure_ascii=True)
    return f"{path}[{rendered}]"


def _has_unpaired_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def install(core: Any) -> None:
    """Install bounded validation and case-bound results into the loaded core."""

    core.MAX_OBJECT_ITEMS = MAX_OBJECT_ITEMS
    core.MAX_EXPANDED_JSON_NODES = MAX_EXPANDED_JSON_NODES
    core.MAX_JSON_BYTES = MAX_JSON_BYTES
    core.MAX_CANONICAL_BYTES = MAX_CANONICAL_BYTES
    core.MAX_JSON_TEXT_BYTES = MAX_JSON_TEXT_BYTES

    def pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len(pairs) > MAX_OBJECT_ITEMS:
            raise core.ValidationError(f"object exceeds {MAX_OBJECT_ITEMS} members")
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise core.ValidationError(f"duplicate JSON key: {key!r}")
            result[key] = value
        return result

    def validate_json_value(
        value: Any,
        path: str = "$",
        depth: int = 0,
        _budget: dict[str, int] | None = None,
    ) -> None:
        if _budget is None:
            _budget = {"nodes": 0, "bytes": 0}

        _budget["nodes"] += 1
        if _budget["nodes"] > MAX_EXPANDED_JSON_NODES:
            raise core.ValidationError(
                f"expanded JSON exceeds {MAX_EXPANDED_JSON_NODES} nodes at {path}"
            )

        def charge_bytes(amount: int) -> None:
            _budget["bytes"] += amount
            if _budget["bytes"] > MAX_CANONICAL_BYTES:
                raise core.ValidationError(
                    f"canonical JSON exceeds {MAX_CANONICAL_BYTES} bytes at {path}"
                )

        if depth > core.MAX_JSON_DEPTH:
            raise core.ValidationError(
                f"JSON nesting exceeds {core.MAX_JSON_DEPTH} at {path}"
            )
        if value is None:
            charge_bytes(4)
            return
        if type(value) is bool:
            charge_bytes(4 if value else 5)
            return
        if type(value) is int:
            if abs(value) > core.MAX_INTEGER_ABS:
                raise core.ValidationError(
                    f"integer exceeds {core.MAX_INTEGER_DIGITS} decimal digits at {path}"
                )
            charge_bytes(len(str(value).encode("ascii")))
            return
        if type(value) is str:
            if len(value) > core.MAX_STRING_CHARS:
                raise core.ValidationError(
                    f"string exceeds {core.MAX_STRING_CHARS} characters at {path}"
                )
            if _has_unpaired_surrogate(value):
                raise core.ValidationError(f"unpaired Unicode surrogate is not allowed at {path}")
            charge_bytes(len(json.dumps(value, ensure_ascii=False).encode("utf-8")))
            return
        if isinstance(value, float):
            raise core.ValidationError(f"floating-point values are not allowed at {path}")
        if isinstance(value, list):
            if len(value) > core.MAX_ARRAY_ITEMS:
                raise core.ValidationError(
                    f"array exceeds {core.MAX_ARRAY_ITEMS} items at {path}"
                )
            charge_bytes(2 + max(0, len(value) - 1))
            for index, item in enumerate(value):
                validate_json_value(item, f"{path}[{index}]", depth + 1, _budget)
            return
        if isinstance(value, dict):
            if len(value) > MAX_OBJECT_ITEMS:
                raise core.ValidationError(
                    f"object exceeds {MAX_OBJECT_ITEMS} members at {path}"
                )
            charge_bytes(2 + max(0, len(value) - 1) + len(value))
            for key, item in value.items():
                if type(key) is not str:
                    raise core.ValidationError(f"object key is not a string at {path}")
                if len(key) > core.MAX_STRING_CHARS:
                    raise core.ValidationError(
                        f"object key exceeds {core.MAX_STRING_CHARS} characters at {path}"
                    )
                if _has_unpaired_surrogate(key):
                    raise core.ValidationError(
                        f"unpaired Unicode surrogate is not allowed in object key at {path}"
                    )
                charge_bytes(len(json.dumps(key, ensure_ascii=False).encode("utf-8")))
                validate_json_value(item, _member_path(path, key), depth + 1, _budget)
            return
        raise core.ValidationError(
            f"unsupported JSON value at {path}: {type(value).__name__}"
        )

    def loads_strict(text: str) -> Any:
        if type(text) is not str:
            raise core.ValidationError("JSON input must be text")
        if len(text) > MAX_JSON_TEXT_BYTES:
            raise core.ValidationError(
                f"JSON text exceeds {MAX_JSON_TEXT_BYTES} characters before parsing"
            )
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise core.ValidationError("JSON text contains an unpaired Unicode surrogate") from exc
        if len(encoded) > MAX_JSON_TEXT_BYTES:
            raise core.ValidationError(
                f"JSON text exceeds {MAX_JSON_TEXT_BYTES} UTF-8 bytes before parsing"
            )
        try:
            value = json.loads(
                text,
                object_pairs_hook=pairs_no_duplicates,
                parse_float=core._reject_float,
                parse_int=core._parse_int,
                parse_constant=core._reject_constant,
            )
        except core.ValidationError:
            raise
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise core.ValidationError(f"invalid or over-deep JSON: {exc}") from exc
        validate_json_value(value)
        return value

    def exact_keys(value: dict[Any, Any], expected: set[str], label: str) -> None:
        if any(type(key) is not str for key in value):
            raise core.ValidationError(f"{label} object keys must be strings")
        actual = set(value)
        if actual != expected:
            raise core.ValidationError(
                f"{label} fields changed: "
                f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
            )

    def bounded_string(value: Any, label: str) -> str:
        if type(value) is not str or not value.strip() or value != value.strip():
            raise core.ValidationError(f"{label} must be a non-empty trimmed string")
        if len(value) > core.MAX_STRING_CHARS:
            raise core.ValidationError(
                f"{label} exceeds {core.MAX_STRING_CHARS} characters"
            )
        if _has_unpaired_surrogate(value):
            raise core.ValidationError(f"{label} contains an unpaired Unicode surrogate")
        return value

    def validate_result_payload(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise core.ValidationError("hardening result payload must be an object")
        expected_fields = {
            "schema", "contract", "case_id", "case_sha256", "invariant_id",
            "attack_class", "mitigation_id", "proposal_producer",
            "verification_producer", "decision", "effective_authority",
            "predicates", "failed_predicates", "status", "receipt_sha256",
        }
        core._exact_keys(payload, expected_fields, "hardening result")
        if payload["schema"] != core.RESULT_SCHEMA:
            raise core.ValidationError("unsupported hardening result schema")
        if payload["contract"] != core.CONTRACT:
            raise core.ValidationError("unsupported hardening result contract")

        core._string(payload["case_id"], "result.case_id")
        core._sha256(payload["case_sha256"], "result.case_sha256")
        invariant = core._string(payload["invariant_id"], "result.invariant_id")
        if not core.INVARIANT.fullmatch(invariant):
            raise core.ValidationError(f"invalid invariant id: {invariant!r}")
        core._string(payload["attack_class"], "result.attack_class")
        core._string(payload["mitigation_id"], "result.mitigation_id")
        proposal_producer = core._producer_id(
            payload["proposal_producer"], "result.proposal_producer"
        )
        verification_producer = core._producer_id(
            payload["verification_producer"], "result.verification_producer"
        )
        if proposal_producer == verification_producer:
            raise core.ValidationError("hardening result violates proposer/verifier separation")
        decision = core._decision(payload["decision"], "result.decision")

        authority = core._array(payload["effective_authority"], "result.effective_authority")
        checked_authority = [
            core._string(item, "result.effective_authority entry") for item in authority
        ]
        if checked_authority != sorted(checked_authority) or len(set(checked_authority)) != len(checked_authority):
            raise core.ValidationError("result.effective_authority must be sorted and unique")

        predicates = payload["predicates"]
        if not isinstance(predicates, dict):
            raise core.ValidationError("result.predicates must be an object")
        core._exact_keys(predicates, set(core.EXPECTED_PREDICATES), "result.predicates")
        for name in core.EXPECTED_PREDICATES:
            if type(predicates[name]) is not bool:
                raise core.ValidationError(f"result predicate {name} must be boolean")

        failed = core._array(payload["failed_predicates"], "result.failed_predicates")
        expected_failed = [
            name for name in core.EXPECTED_PREDICATES if not predicates[name]
        ]
        if failed != expected_failed:
            raise core.ValidationError(
                "result.failed_predicates does not match predicate failures"
            )

        status = core._string(payload["status"], "result.status")
        expected_status = "BLUE_HARDENED" if not expected_failed else "NOT_HARDENED"
        if status != expected_status:
            raise core.ValidationError("result.status does not match predicate failures")
        if not predicates["authority_not_expanded"] and decision is not core.Decision.DENY:
            raise core.ValidationError("authority-expanding result must be DENY")
        if expected_failed and decision is core.Decision.ALLOW:
            raise core.ValidationError("failed hardening result cannot remain ALLOW")

        receipt = core._sha256(payload["receipt_sha256"], "result.receipt_sha256")
        material = dict(payload)
        material.pop("receipt_sha256")
        if core.digest(material) != receipt:
            raise core.ValidationError("hardening result receipt does not match payload")
        return payload

    class SlotHardeningResult:
        """Slot-only evaluator result recomputed from immutable canonical case bytes."""

        __slots__ = ("_case_bytes",)

        def __init__(
            self,
            originating_case: Any,
            *,
            _token: object | None = None,
        ) -> None:
            if _token is not core._EVALUATION_TOKEN:
                raise core.ValidationError("HardeningResult must be created by evaluate()")
            if not isinstance(originating_case, core.HardeningCase):
                raise core.ValidationError(
                    "HardeningResult construction requires an originating HardeningCase"
                )
            validated_case = core._validated_case(originating_case)
            case_material = core._case_input_material(validated_case)
            object.__setattr__(self, "_case_bytes", core.canonical_bytes(case_material))

        def __setattr__(self, name: str, value: Any) -> None:
            raise AttributeError("HardeningResult is immutable")

        @classmethod
        def _from_evaluation(cls, case: Any) -> Any:
            return cls(case, _token=core._EVALUATION_TOKEN)

        def _recomputed_payload(self) -> dict[str, Any]:
            try:
                case_value = core.loads_strict(self._case_bytes.decode("utf-8"))
            except (AttributeError, UnicodeDecodeError) as exc:
                raise core.ValidationError("hardening result case provenance is invalid") from exc
            case = core.HardeningCase.from_dict(case_value)
            validated_case = core._validated_case(case)
            payload_builder = getattr(core, "_payload_for_validated_case", None)
            if not callable(payload_builder):
                raise core.ValidationError("hardening evaluator payload builder is unavailable")
            payload = payload_builder(validated_case)
            validate_result_payload(payload)
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

    SlotHardeningResult.__name__ = "HardeningResult"
    SlotHardeningResult.__qualname__ = "HardeningResult"
    SlotHardeningResult.__module__ = core.__name__

    core._pairs_no_duplicates = pairs_no_duplicates
    core._validate_json_value = validate_json_value
    core.loads_strict = loads_strict
    core._exact_keys = exact_keys
    core._string = bounded_string
    core._validate_result_payload = validate_result_payload
    core.HardeningResult = SlotHardeningResult
