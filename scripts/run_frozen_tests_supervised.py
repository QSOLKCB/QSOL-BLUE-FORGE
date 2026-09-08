#!/usr/bin/env python3
"""Final trusted supervisor hardening for PATH-resolved Python subprocesses.

The retained round-2 supervisor owns the established worker/actor boundary.
This entrypoint adds one narrow final mediation layer: suspicious Python
subprocesses are resolved through the exact PATH supplied to subprocess APIs,
including aliases and alternate versioned Python executable names, before the
round-2 policy decides whether to bridge or reject them.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

_ROUND2 = Path(__file__).with_name("_run_frozen_tests_supervised_round2.py")
_spec = importlib.util.spec_from_file_location(
    "_blue_forge_supervisor_round2", _ROUND2
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted second-stage supervisor is unavailable")
round2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(round2)
base = round2.base

# Descendants must always re-enter this final mediation layer.
base.__file__ = str(Path(__file__).resolve())

_legacy_importer = round2._hardened_test_importer
_legacy_subprocess_self_test = round2._subprocess_policy_self_test


def _python_name(name: str) -> bool:
    """Recognize conventional CPython/PyPy executable basenames."""
    lowered = name.casefold()
    for prefix in ("python", "pypy"):
        if lowered == prefix:
            return True
        if not lowered.startswith(prefix):
            continue
        suffix = lowered[len(prefix):]
        if suffix.endswith("t"):
            suffix = suffix[:-1]
        if suffix and all(part.isdigit() for part in suffix.split(".")):
            return True
    return False


def _env_command_index(items: list[str]) -> tuple[int | None, dict[str, str]]:
    """Return the executable slot and simple GNU-env assignments."""
    if not items:
        return None, {}
    if Path(items[0]).name != "env":
        return 0, {}
    index = 1
    if index < len(items) and items[index] == "--":
        index += 1
    overrides: dict[str, str] = {}
    while index < len(items):
        token = items[index]
        if token.startswith("-"):
            return None, {}
        if "=" not in token:
            break
        key, value = token.split("=", 1)
        if not key:
            return None, {}
        overrides[key] = value
        index += 1
    if index >= len(items):
        return None, {}
    return index, overrides


def _search_path(
    environment: object, overrides: dict[str, str]
) -> str | None:
    if environment is None:
        mapping = os.environ
    else:
        if type(environment) is not dict or not all(
            type(key) is str and type(value) is str
            for key, value in environment.items()
        ):
            return None
        mapping = environment
    try:
        path = os.pathsep.join(os.get_exec_path(mapping))
    except (TypeError, ValueError):
        return None
    if "PATH" in overrides:
        path = overrides["PATH"]
    return path


def _resolved_executable(token: str, search_path: str | None) -> Path | None:
    try:
        if os.path.dirname(token):
            return Path(token).resolve()
        if search_path is None:
            return None
        found = shutil.which(token, path=search_path)
        if found is None:
            return None
        return Path(found).resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _normalize_python_command(command, kwargs, root):
    """Normalize only proposed-code Python launches before round-2 policy."""
    if type(command) not in (list, tuple):
        return command, False
    items = list(command)
    if not items or not all(type(item) is str for item in items):
        return command, False

    executable_index, overrides = _env_command_index(items)
    if executable_index is None:
        return command, False

    candidate_items = items[executable_index:]
    if not any(
        "blue_forge" in item
        or round2._looks_like_proposed_path(item, root)
        for item in candidate_items
    ):
        return command, False

    search_path = _search_path(kwargs.get("env"), overrides)
    token = items[executable_index]
    resolved = _resolved_executable(token, search_path)
    try:
        current = Path(sys.executable).resolve()
    except (OSError, RuntimeError):
        current = None

    is_python = (
        (resolved is not None and current is not None and resolved == current)
        or _python_name(Path(token).name)
        or (resolved is not None and _python_name(resolved.name))
    )
    if not is_python:
        return command, False

    items[executable_index] = sys.executable
    return items, True


def _hardened_test_importer(bridge):
    """Apply PATH-aware Python mediation ahead of the retained facade."""
    importer = _legacy_importer(bridge)
    facades = importer._blue_forge_facades
    process_proxy = facades["subprocess"]

    def wrap(name: str):
        original = getattr(process_proxy, name)

        def mediated(command, *args, **kwargs):
            normalized, changed = _normalize_python_command(
                command, kwargs, bridge.root
            )
            result = original(normalized, *args, **kwargs)
            if changed and name == "run" and isinstance(
                result, subprocess.CompletedProcess
            ):
                result.args = command
            return result

        return mediated

    for name in ("run", "check_output", "check_call", "call", "Popen"):
        setattr(process_proxy, name, wrap(name))
    return importer


def _subprocess_policy_self_test():
    """Retain round-2 checks and cover PATH-resolved interpreter aliases."""
    _legacy_subprocess_self_test()

    class AliasBridge:
        def __init__(self, root):
            self.root = root

        def request(self, action, *arguments):
            base.require(action == "cli", "PATH-alias self-test escaped CLI bridge")
            base.require(
                arguments[0] == ["verify"],
                "PATH-alias self-test lost proposed CLI action",
            )
            return 0, b"alias-bridged", b"", False

    with tempfile.TemporaryDirectory(
        prefix="blue-forge-python-path-alias-"
    ) as temp:
        root = Path(temp)
        case = root / "case.json"
        case.write_bytes(b"{}")
        alias_dir = root / "bin"
        alias_dir.mkdir()
        alias = alias_dir / "trusted-python"
        alias.symlink_to(Path(sys.executable).resolve())
        environment = {"PATH": str(alias_dir)}

        importer = _hardened_test_importer(AliasBridge(root))
        proxy = importer("subprocess")
        alias_cli = [
            "trusted-python",
            "-m",
            "blue_forge",
            "verify",
            str(case),
        ]
        completed = proxy.run(
            alias_cli, env=environment, capture_output=True, check=True
        )
        base.require(
            completed.stdout == b"alias-bridged"
            and completed.args == alias_cli,
            "PATH-resolved Python alias bypassed actor routing",
        )

        try:
            proxy.run(
                ["trusted-python", "-c", "import blue_forge"],
                env=environment,
            )
        except base.SupervisionFailure:
            pass
        else:
            raise base.SupervisionFailure(
                "PATH-resolved Python alias executed proposed code directly"
            )

        alternate = alias_dir / "python9"
        alternate.symlink_to("/bin/false")
        try:
            proxy.run(
                [str(alternate), "-c", "import blue_forge"],
                env=environment,
            )
        except base.SupervisionFailure:
            pass
        else:
            raise base.SupervisionFailure(
                "alternate Python executable escaped proposed-code inspection"
            )


# Round-2 functions resolve these globals dynamically during enumeration,
# execution, and their mandatory self-tests.
round2._hardened_test_importer = _hardened_test_importer
round2.previous._self_test_subprocess_facade = _subprocess_policy_self_test
base._test_importer = _hardened_test_importer

# Keep useful compatibility names available to any trusted diagnostics that
# import the final supervisor as a module.
previous = round2.previous


def _main():
    return round2._main()


if __name__ == "__main__":
    raise SystemExit(_main())