"""Bounded duplicate-key diagnostics layered over the reference-core validation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

_ROUND20 = Path(__file__).with_name("_validation_patch_round20.py")
_spec = importlib.util.spec_from_file_location(
    "blue_forge._validation_patch_round20", _ROUND20
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("retained validation implementation is unavailable")
round20 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(round20)

MAX_OBJECT_ITEMS = round20.MAX_OBJECT_ITEMS
MAX_EXPANDED_JSON_NODES = round20.MAX_EXPANDED_JSON_NODES
MAX_JSON_BYTES = round20.MAX_JSON_BYTES
MAX_CANONICAL_BYTES = round20.MAX_CANONICAL_BYTES
MAX_JSON_TEXT_BYTES = round20.MAX_JSON_TEXT_BYTES

_member_path = round20._member_path
_has_unpaired_surrogate = round20._has_unpaired_surrogate


def install(core: Any) -> None:
    """Install the retained validators, then harden parse-time object keys."""
    round20.install(core)

    def validate_object_key(key: Any) -> str:
        if type(key) is not str:
            raise core.ValidationError("object key is not a string")
        if len(key) > core.MAX_STRING_CHARS:
            raise core.ValidationError(
                f"object key exceeds {core.MAX_STRING_CHARS} characters"
            )
        if _has_unpaired_surrogate(key):
            raise core.ValidationError(
                "unpaired Unicode surrogate is not allowed in object key"
            )
        return key

    def pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len(pairs) > MAX_OBJECT_ITEMS:
            raise core.ValidationError(
                f"object exceeds {MAX_OBJECT_ITEMS} members"
            )
        result: dict[str, Any] = {}
        for raw_key, value in pairs:
            key = validate_object_key(raw_key)
            if key in result:
                # The key has passed its size/domain checks, but do not echo it:
                # validation diagnostics are independently bounded output.
                raise core.ValidationError("duplicate JSON key")
            result[key] = value
        return result

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
            raise core.ValidationError(
                "JSON text contains an unpaired Unicode surrogate"
            ) from exc
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
            raise core.ValidationError(
                f"invalid or over-deep JSON: {exc}"
            ) from exc
        core._validate_json_value(value)
        return value

    core._pairs_no_duplicates = pairs_no_duplicates
    core.loads_strict = loads_strict
