"""Fail-closed JSON resource and diagnostic hardening for the reference core."""

from __future__ import annotations

import json
from typing import Any

MAX_OBJECT_ITEMS = 512


def _member_path(path: str, key: str) -> str:
    """Render an object member path without allowing control-character log injection."""
    rendered = json.dumps(key, ensure_ascii=True)
    return f"{path}[{rendered}]"


def install(core: Any) -> None:
    """Install bounded object validation into the already-loaded core module."""

    core.MAX_OBJECT_ITEMS = MAX_OBJECT_ITEMS

    def pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len(pairs) > MAX_OBJECT_ITEMS:
            raise core.ValidationError(
                f"object exceeds {MAX_OBJECT_ITEMS} members"
            )
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
                validate_json_value(item, _member_path(path, key), depth + 1)
            return
        raise core.ValidationError(
            f"unsupported JSON value at {path}: {type(value).__name__}"
        )

    core._pairs_no_duplicates = pairs_no_duplicates
    core._validate_json_value = validate_json_value
