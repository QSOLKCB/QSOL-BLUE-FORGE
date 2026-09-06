"""Fail-closed JSON, diagnostic and result hardening for the reference core."""

from __future__ import annotations

import json
from typing import Any

MAX_OBJECT_ITEMS = 512


def _member_path(path: str, key: str) -> str:
    """Render an object member path without allowing control-character log injection."""
    rendered = json.dumps(key, ensure_ascii=True)
    return f"{path}[{rendered}]"


def _has_unpaired_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def install(core: Any) -> None:
    """Install bounded validation and self-validating results into the loaded core."""

    core.MAX_OBJECT_ITEMS = MAX_OBJECT_ITEMS

    def pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len(pairs) > MAX_OBJECT_ITEMS:
            raise core.ValidationError(f"object exceeds {MAX_OBJECT_ITEMS} members")
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise core.ValidationError(f"duplicate JSON key: {key!r}")
            result[key] = value
        return result

    def validate_json_value(value: Any, path: str = "$", depth: int = 0) -> None:
        if depth > core.MAX_JSON_DEPTH:
            raise core.ValidationError(
                f"JSON nesting exceeds {core.MAX_JSON_DEPTH} at {path}"
            )
        if value is None or type(value) is bool:
            return
        if type(value) is int:
            if abs(value) > core.MAX_INTEGER_ABS:
                raise core.ValidationError(
                    f"integer exceeds {core.MAX_INTEGER_DIGITS} decimal digits at {path}"
                )
            return
        if type(value) is str:
            if len(value) > core.MAX_STRING_CHARS:
                raise core.ValidationError(
                    f"string exceeds {core.MAX_STRING_CHARS} characters at {path}"
                )
            if _has_unpaired_surrogate(value):
                raise core.ValidationError(f"unpaired Unicode surrogate is not allowed at {path}")
            return
        if isinstance(value, float):
            raise core.ValidationError(f"floating-point values are not allowed at {path}")
        if isinstance(value, list):
            if len(value) > core.MAX_ARRAY_ITEMS:
                raise core.ValidationError(
                    f"array exceeds {core.MAX_ARRAY_ITEMS} items at {path}"
                )
            for index, item in enumerate(value):
                validate_json_value(item, f"{path}[{index}]", depth + 1)
            return
        if isinstance(value, dict):
            if len(value) > MAX_OBJECT_ITEMS:
                raise core.ValidationError(
                    f"object exceeds {MAX_OBJECT_ITEMS} members at {path}"
                )
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
                validate_json_value(item, _member_path(path, key), depth + 1)
            return
        raise core.ValidationError(
            f"unsupported JSON value at {path}: {type(value).__name__}"
        )

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

    def hardening_result_init(
        self: Any,
        payload: dict[str, Any],
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not core._EVALUATION_TOKEN:
            raise core.ValidationError("HardeningResult must be created by evaluate()")
        validate_result_payload(payload)
        object.__setattr__(self, "_payload_bytes", core.canonical_bytes(payload))

    core._pairs_no_duplicates = pairs_no_duplicates
    core._validate_json_value = validate_json_value
    core._validate_result_payload = validate_result_payload
    core.HardeningResult.__init__ = hardening_result_init
