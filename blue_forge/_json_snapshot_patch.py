"""Exact-container snapshotting for deterministic canonical JSON."""

from __future__ import annotations

import json
from typing import Any


def _member_path(path: str, key: str) -> str:
    return f"{path}[{json.dumps(key, ensure_ascii=True)}]"


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def install(core: Any) -> None:
    """Canonicalize only a validated snapshot of exact built-in JSON values."""

    def snapshot_json_value(
        value: Any,
        path: str = "$",
        depth: int = 0,
        _budget: dict[str, int] | None = None,
    ) -> Any:
        if _budget is None:
            _budget = {"nodes": 0, "bytes": 0}

        _budget["nodes"] += 1
        if _budget["nodes"] > core.MAX_EXPANDED_JSON_NODES:
            raise core.ValidationError(
                f"expanded JSON exceeds {core.MAX_EXPANDED_JSON_NODES} nodes at {path}"
            )

        def charge_bytes(amount: int) -> None:
            _budget["bytes"] += amount
            if _budget["bytes"] > core.MAX_CANONICAL_BYTES:
                raise core.ValidationError(
                    f"canonical JSON exceeds {core.MAX_CANONICAL_BYTES} bytes at {path}"
                )

        if depth > core.MAX_JSON_DEPTH:
            raise core.ValidationError(
                f"JSON nesting exceeds {core.MAX_JSON_DEPTH} at {path}"
            )
        if value is None:
            charge_bytes(4)
            return None
        if type(value) is bool:
            charge_bytes(4 if value else 5)
            return value
        if type(value) is int:
            if abs(value) > core.MAX_INTEGER_ABS:
                raise core.ValidationError(
                    f"integer exceeds {core.MAX_INTEGER_DIGITS} decimal digits at {path}"
                )
            charge_bytes(len(str(value).encode("ascii")))
            return value
        if type(value) is str:
            if len(value) > core.MAX_STRING_CHARS:
                raise core.ValidationError(
                    f"string exceeds {core.MAX_STRING_CHARS} characters at {path}"
                )
            if _has_surrogate(value):
                raise core.ValidationError(
                    f"unpaired Unicode surrogate is not allowed at {path}"
                )
            charge_bytes(len(json.dumps(value, ensure_ascii=False).encode("utf-8")))
            return value
        if type(value) is float:
            raise core.ValidationError(f"floating-point values are not allowed at {path}")
        if type(value) is list:
            if len(value) > core.MAX_ARRAY_ITEMS:
                raise core.ValidationError(
                    f"array exceeds {core.MAX_ARRAY_ITEMS} items at {path}"
                )
            charge_bytes(2 + max(0, len(value) - 1))
            return [
                snapshot_json_value(item, f"{path}[{index}]", depth + 1, _budget)
                for index, item in enumerate(value)
            ]
        if type(value) is dict:
            if len(value) > core.MAX_OBJECT_ITEMS:
                raise core.ValidationError(
                    f"object exceeds {core.MAX_OBJECT_ITEMS} members at {path}"
                )
            charge_bytes(2 + max(0, len(value) - 1) + len(value))
            snapshot: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise core.ValidationError(f"object key is not a string at {path}")
                if len(key) > core.MAX_STRING_CHARS:
                    raise core.ValidationError(
                        f"object key exceeds {core.MAX_STRING_CHARS} characters at {path}"
                    )
                if _has_surrogate(key):
                    raise core.ValidationError(
                        f"unpaired Unicode surrogate is not allowed in object key at {path}"
                    )
                charge_bytes(len(json.dumps(key, ensure_ascii=False).encode("utf-8")))
                snapshot[key] = snapshot_json_value(
                    item,
                    _member_path(path, key),
                    depth + 1,
                    _budget,
                )
            return snapshot
        if isinstance(value, (list, dict)):
            raise core.ValidationError(
                f"JSON containers must be exact built-in list/dict at {path}"
            )
        raise core.ValidationError(
            f"unsupported JSON value at {path}: {type(value).__name__}"
        )

    def canonical_bytes(value: Any) -> bytes:
        snapshot = snapshot_json_value(value)
        try:
            encoded = json.dumps(
                snapshot,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise core.ValidationError(f"cannot canonicalize value: {exc}") from exc
        if len(encoded) > core.MAX_CANONICAL_BYTES:
            raise core.ValidationError(
                f"canonical JSON exceeds {core.MAX_CANONICAL_BYTES} bytes"
            )
        return encoded

    core._snapshot_json_value = snapshot_json_value
    core.canonical_bytes = canonical_bytes
