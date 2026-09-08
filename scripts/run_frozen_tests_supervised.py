#!/usr/bin/env python3
"""Final trusted supervisor hardening for executable and source mediation.

The retained round-2 supervisor owns the established worker/actor boundary.
This entrypoint adds final fail-closed mediation for PATH-resolved Python
subprocesses, native os/posix process-launch APIs, and direct execution of code
objects originating beneath the proposed ``blue_forge/`` source tree.
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import types

try:
    import posix as _posix
except ImportError:  # pragma: no cover - governed CI is Linux
    _posix = None

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
_legacy_facades_scope = round2._trusted_test_facades
_legacy_subprocess_self_test = round2._subprocess_policy_self_test
_legacy_boundary_self_test = round2.previous._self_test_dispatch_and_descriptors

_NATIVE_PROCESS_APIS = frozenset({
    "system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve",
    "spawnvp", "spawnvpe", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
})


def _blocked_native_process(*args, **kwargs):
    del args, kwargs
    raise base.SupervisionFailure(
        "native process-launch APIs are unavailable in trusted workers"
    )


def _module_proxy(module, name: str):
    proxy = types.ModuleType(name)
    proxy.__dict__.update(vars(module))
    for api in _NATIVE_PROCESS_APIS:
        if hasattr(module, api):
            setattr(proxy, api, _blocked_native_process)
    return proxy


def _source_execution_guard(event, args):
    """Reject execution of code compiled from the proposed source tree."""
    if event != "exec" or not args:
        return
    bridge = base._ACTIVE_BRIDGE
    if bridge is None:
        return
    code = args[0]
    filename = getattr(code, "co_filename", None)
    if type(filename) is str and round2._looks_like_proposed_path(
        filename, bridge.root
    ):
        raise base.SupervisionFailure(
            "direct proposed source execution is blocked in trusted workers"
        )


# Audit hooks cannot be removed by PR-controlled test code. The guard is inert
# outside a live supervised bridge and therefore does not affect supervisor
# bootstrap or ordinary trusted module execution.
sys.addaudithook(_source_execution_guard)


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
    """Apply executable mediation ahead of the retained facade."""
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

    facades["os"] = _module_proxy(os, "os")
    if _posix is not None:
        facades["posix"] = _module_proxy(_posix, "posix")
    return importer


@contextlib.contextmanager
def _trusted_test_facades(importer):
    """Expose all final facades through sys.modules for spelling-independent use."""
    facades = getattr(importer, "_blue_forge_facades", None)
    base.require(type(facades) is dict, "trusted test importer omitted facades")
    sentinel = object()
    names = [name for name in ("os", "posix") if name in facades]
    prior = {name: sys.modules.get(name, sentinel) for name in names}
    with _legacy_facades_scope(importer):
        for name in names:
            sys.modules[name] = facades[name]
        try:
            yield
        finally:
            for name in names:
                value = prior[name]
                if value is sentinel:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = value


def _source_execution_self_test():
    """Exercise runpy and importlib direct-file execution under the audit guard."""
    with tempfile.TemporaryDirectory(
        prefix="blue-forge-source-execution-"
    ) as temp:
        root = Path(temp)
        (root / "blue_forge").mkdir()
        source = root / "blue_forge/direct.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        prior = base._ACTIVE_BRIDGE
        base._ACTIVE_BRIDGE = types.SimpleNamespace(root=root)
        try:
            probes = [
                lambda: runpy.run_path(str(source)),
                lambda: _exec_file_spec(source),
            ]
            for probe in probes:
                try:
                    probe()
                except base.SupervisionFailure as exc:
                    base.require(
                        "direct proposed source execution" in str(exc),
                        "direct-source guard failed for an unrelated reason",
                    )
                else:
                    raise base.SupervisionFailure(
                        "trusted worker executed proposed source directly"
                    )
        finally:
            base._ACTIVE_BRIDGE = prior


def _exec_file_spec(path: Path):
    spec = importlib.util.spec_from_file_location(
        "_blue_forge_direct_source_probe", path
    )
    base.require(
        spec is not None and spec.loader is not None,
        "direct-source self-test could not construct loader",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


def _subprocess_policy_self_test():
    """Retain prior checks and cover PATH/native-process/source-loader escapes."""
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

        os_proxy = importer("os")
        try:
            os_proxy.system(
                f"{sys.executable} -m blue_forge verify {case}"
            )
        except base.SupervisionFailure:
            pass
        else:
            raise base.SupervisionFailure(
                "os.system escaped trusted-worker process mediation"
            )
        with _trusted_test_facades(importer):
            base.require(
                importlib.import_module("os") is os_proxy,
                "importlib recovered the real os module in trusted scope",
            )

    _source_execution_self_test()
    print(
        "native_process_mediation=PASS "
        "direct_source_execution=PASS"
    )


def _final_boundary_self_test(
    python_bin, timeout_seconds, *, local_test=False
):
    """Retain earlier boundary controls and reproduce encoder-closure forgery."""
    _legacy_boundary_self_test(
        python_bin, timeout_seconds, local_test=local_test
    )
    attack = r'''
for candidate in object.__subclasses__():
    if getattr(candidate, '__name__', None) != '_GraphEncoder':
        continue
    namespace = candidate.encode.__globals__
    encoder = namespace.get('_encode_data')
    if encoder is None or encoder.__closure__ is None:
        continue
    for name, cell in zip(encoder.__code__.co_freevars, encoder.__closure__):
        if name == 'integer_text':
            cell.cell_contents = lambda value: '1'
            break
def probe(): return 0
'''
    with tempfile.TemporaryDirectory(
        prefix="blue-forge-encoder-boundary-"
    ) as temp:
        root = Path(temp)
        root.chmod(0o755)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge/__init__.py").write_text(
            attack, encoding="utf-8"
        )
        (root / "tests/test_encoder_boundary.py").write_text(
            "import unittest\nimport blue_forge\n"
            "class EncoderBoundary(unittest.TestCase):\n"
            " def test_truth(self): self.assertEqual(blue_forge.probe(), 0)\n"
            " def test_forgery(self): self.assertEqual(blue_forge.probe(), 1)\n",
            encoding="utf-8",
        )
        base.run_one(
            root,
            python_bin,
            ("test_encoder_boundary", "EncoderBoundary", "test_truth"),
            timeout_seconds,
            local_test=local_test,
        )
        try:
            base.run_one(
                root,
                python_bin,
                ("test_encoder_boundary", "EncoderBoundary", "test_forgery"),
                timeout_seconds,
                local_test=local_test,
            )
        except base.SupervisionFailure:
            pass
        else:
            raise base.SupervisionFailure(
                "response encoder boundary accepted forged integer observation"
            )
    print("executor_encoder_isolation=PASS")


# Round-2 functions resolve these globals dynamically during enumeration,
# execution, and their mandatory self-tests.
round2._hardened_test_importer = _hardened_test_importer
round2._trusted_test_facades = _trusted_test_facades
round2.previous._self_test_subprocess_facade = _subprocess_policy_self_test
round2.previous._self_test_dispatch_and_descriptors = _final_boundary_self_test
base._test_importer = _hardened_test_importer

# Keep useful compatibility names available to any trusted diagnostics and the
# root-owned current-suite scheduler that import this final supervisor.
previous = round2.previous
_enumerate_module_parent = round2._enumerate_module_parent


def _main():
    return round2._main()


if __name__ == "__main__":
    raise SystemExit(_main())