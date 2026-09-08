"""Exact built-in array preflight for programmatic BLUE-FORGE inputs."""

from __future__ import annotations

from typing import Any


def install(core: Any) -> None:
    """Require exact bounded list containers before any array iteration."""

    def exact_array(value: Any, label: str) -> list[Any]:
        if type(value) is not list:
            raise core.ValidationError(f"{label} must be an exact list")
        if len(value) > core.MAX_ARRAY_ITEMS:
            raise core.ValidationError(
                f"{label} exceeds {core.MAX_ARRAY_ITEMS} items"
            )
        return value

    core._array = exact_array
