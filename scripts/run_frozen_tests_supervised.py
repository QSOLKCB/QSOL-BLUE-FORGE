#!/usr/bin/env python3
"""Trusted supervisor for frozen tests executed against proposed source.

The supervisor never imports repository application code. It statically enumerates
trusted unittest methods, then launches one trusted worker process per method. The
worker keeps accounting in its main interpreter and executes proposed code only in
a fresh CPython subinterpreter. A test passes only when the trusted method returns
normally across that interpreter boundary; child text and mutable unittest result
objects are never authority signals.
"""

from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


class SupervisionFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SupervisionFailure(message)


def _is_testcase_base(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "TestCase"
    if isinstance(node, ast.Attribute):
        return node.attr == "TestCase"
    return False


def expected_tests(root: Path) -> list[tuple[str, str, str]]:
    tests_root = root / "tests"
    require(tests_root.is_dir(), f"missing frozen tests directory: {tests_root}")
    expected: list[tuple[str, str, str]] = []
    for path in sorted(tests_root.glob("test*.py")):
        require(path.is_file() and not path.is_symlink(), f"invalid frozen test path: {path}")
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise SupervisionFailure(f"cannot statically inspect frozen test {path}: {exc}") from exc

        module = path.stem
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(_is_testcase_base(base) for base in node.bases):
                continue
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                    expected.append((module, node.name, item.name))

    require(bool(expected), "no frozen unittest methods discovered")
    require(len(set(expected)) == len(expected), "duplicate frozen unittest identity discovered")
    return expected


_SUBINTERPRETER_RUNNER = r'''
import builtins
import importlib.util
import os
import posix
from pathlib import Path
import sys
import types

root = Path(__ROOT__).resolve()
module_name = __MODULE__
class_name = __CLASS__
method_name = __METHOD__

# Capture the runner primitives before any proposed module can mutate the real
# builtins namespace. These direct object references stay in the unregistered
# run-string globals and are never resolved through mutable builtins afterwards.
_trusted_object_getattribute = object.__getattribute__
_trusted_isinstance = isinstance
_trusted_type = type
_trusted_issubclass = issubclass
_trusted_assertion_error = AssertionError


def _blocked(*args, **kwargs):
    raise RuntimeError("supervised frozen test attempted to cross the trusted runner boundary")


# Early-success and process-replacement primitives cannot turn a failed test into
# parent-interpreter success. Signal-based termination remains fail-closed because
# it produces abnormal worker termination rather than a successful return.
os._exit = _blocked
posix._exit = _blocked
for _name in (
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"
):
    if hasattr(os, _name):
        setattr(os, _name, _blocked)
    if hasattr(posix, _name):
        setattr(posix, _name, _blocked)

# Remove straightforward Python-level routes to trusted runner frames or C process
# termination. Keep ordinary stdlib modules importable; frame entry points themselves
# are blocked, so libraries such as dataclasses may still import inspect normally.
for _name in ("_getframe", "_current_frames", "settrace", "setprofile"):
    if hasattr(sys, _name):
        setattr(sys, _name, _blocked)
for _module_name in ("ctypes", "_ctypes", "gc"):
    sys.modules[_module_name] = None

# -I deliberately omits the caller working directory and PYTHONPATH. Add only the
# sterile proposed root and its frozen tests explicitly, never the GitHub checkout.
sys.path.insert(0, str(root / "tests"))
sys.path.insert(0, str(root))

# Proposed code must never be able to import the run-string namespace that owns the
# trusted assertion package. Replace the import-visible __main__ module with an inert
# shell before loading any proposed package. The runner continues executing in its
# private globals, which are not registered in sys.modules.
sys.modules["__main__"] = types.ModuleType("__main__")


def _load_private_unittest():
    """Load a distinct stdlib unittest package object for frozen assertions."""
    spec = importlib.util.find_spec("unittest")
    if spec is None or spec.origin is None:
        raise RuntimeError("stdlib unittest package is unavailable")
    package_dir = Path(spec.origin).resolve().parent
    private_name = "_blueforge_trusted_unittest"
    private_spec = importlib.util.spec_from_file_location(
        private_name,
        spec.origin,
        submodule_search_locations=[str(package_dir)],
    )
    if private_spec is None or private_spec.loader is None:
        raise RuntimeError("cannot construct private unittest package")
    private = importlib.util.module_from_spec(private_spec)
    sys.modules[private_name] = private
    try:
        private_spec.loader.exec_module(private)
    finally:
        # Keep the private module graph reachable only from this runner. Proposed
        # code importing real unittest cannot discover or mutate it through the
        # module registry.
        for name in tuple(sys.modules):
            if name == private_name or name.startswith(private_name + "."):
                sys.modules.pop(name, None)
    return private


_trusted_unittest = _load_private_unittest()
_real_import = builtins.__import__
_test_builtins = dict(vars(builtins))


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and name == "unittest":
        return _trusted_unittest
    return _real_import(name, globals, locals, fromlist, level)


_test_builtins["__import__"] = _guarded_import


def _entry():
    test_path = root / "tests" / f"{module_name}.py"
    source = test_path.read_text(encoding="utf-8")
    code = compile(source, str(test_path), "exec", dont_inherit=True)
    namespace = {
        "__name__": module_name,
        "__file__": str(test_path),
        "__package__": "",
        "__builtins__": _test_builtins,
    }

    # The trusted test module is deliberately not installed in sys.modules, so
    # proposed imports cannot reach its globals through a module registry lookup.
    exec(code, namespace, namespace)
    case_class = namespace.get(class_name)
    if not _trusted_isinstance(case_class, _trusted_type) or not _trusted_issubclass(
        case_class, _trusted_unittest.TestCase
    ):
        raise _trusted_assertion_error(f"frozen test class identity changed: {class_name}")

    case = case_class(method_name)
    setup = _trusted_object_getattribute(case, "setUp")
    method = _trusted_object_getattribute(case, method_name)
    teardown = _trusted_object_getattribute(case, "tearDown")

    setup()
    try:
        # No TestResult exists here. A trusted assertion failure propagates out of
        # this subinterpreter and the parent worker reports failure.
        method()
    finally:
        teardown()


_entry()
'''


def _worker_run(root: Path, identity: tuple[str, str, str]) -> None:
    try:
        import _xxsubinterpreters as interpreters
    except ImportError as exc:
        raise SupervisionFailure("CPython subinterpreter support is unavailable") from exc

    module, class_name, method = identity
    script = (
        _SUBINTERPRETER_RUNNER
        .replace("__ROOT__", repr(str(root)))
        .replace("__MODULE__", repr(module))
        .replace("__CLASS__", repr(class_name))
        .replace("__METHOD__", repr(method))
    )
    interpreter = interpreters.create()
    try:
        interpreters.run_string(interpreter, script)
    except interpreters.RunFailedError as exc:
        raise SupervisionFailure(
            f"frozen test failed in proposed subinterpreter: {module}.{class_name}.{method}: {exc}"
        ) from exc
    finally:
        try:
            interpreters.destroy(interpreter)
        except RuntimeError:
            pass


MAX_DIAGNOSTIC_BYTES = 64 * 1024
_DIAGNOSTIC_CHUNK = 8192


def _run_worker_bounded(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
) -> tuple[int, str, bool]:
    """Drain untrusted worker output while retaining only a fixed diagnostic tail."""
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        raise SupervisionFailure(f"frozen test worker failed to start: {exc}") from exc

    require(process.stdout is not None, "frozen test worker output pipe unavailable")
    tail = bytearray()
    drain_error: list[BaseException] = []

    def drain() -> None:
        try:
            while True:
                chunk = process.stdout.read(_DIAGNOSTIC_CHUNK)
                if not chunk:
                    return
                if len(chunk) >= MAX_DIAGNOSTIC_BYTES:
                    tail[:] = chunk[-MAX_DIAGNOSTIC_BYTES:]
                else:
                    tail.extend(chunk)
                    overflow = len(tail) - MAX_DIAGNOSTIC_BYTES
                    if overflow > 0:
                        del tail[:overflow]
        except (OSError, ValueError) as exc:
            drain_error.append(exc)

    reader = threading.Thread(
        target=drain,
        name="blue-forge-frozen-worker-output",
        daemon=True,
    )
    reader.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()

    reader.join(timeout=2)
    require(not reader.is_alive(), "frozen test worker output drain did not terminate")
    if drain_error:
        raise SupervisionFailure(f"frozen test worker output drain failed: {drain_error[0]}")
    try:
        process.stdout.close()
    except OSError:
        pass
    diagnostic = bytes(tail).decode("utf-8", errors="replace")
    return returncode, diagnostic, timed_out


def run_one(
    root: Path,
    python_bin: str,
    identity: tuple[str, str, str],
    timeout_seconds: int,
) -> None:
    module, class_name, method = identity
    test_id = f"{module}.{class_name}.{method}"
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    supervisor = Path(__file__).resolve()
    command = [
        python_bin,
        "-I",
        str(supervisor),
        "--worker-root",
        str(root),
        "--worker-module",
        module,
        "--worker-class",
        class_name,
        "--worker-method",
        method,
    ]
    returncode, diagnostic, timed_out = _run_worker_bounded(
        command,
        cwd=root,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    require(
        not timed_out,
        f"frozen test worker timed out: {test_id}\n{diagnostic}",
    )
    require(
        returncode == 0,
        f"frozen test did not complete in trusted worker: {test_id}: "
        f"rc={returncode}\n{diagnostic}",
    )


def _self_test_import_path(python_bin: str, timeout_seconds: int) -> None:
    """Prove isolated workers import proposed source from the sterile root."""
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-import-selftest-") as temp:
        root = Path(temp)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge" / "__init__.py").write_text(
            "SENTINEL = 'sterile-proposed-root'\n",
            encoding="utf-8",
        )
        (root / "tests" / "test_importable.py").write_text(
            "import unittest\n"
            "import blue_forge\n\n"
            "class ImportTests(unittest.TestCase):\n"
            "    def test_imports_sterile_root(self):\n"
            "        self.assertEqual(blue_forge.SENTINEL, 'sterile-proposed-root')\n",
            encoding="utf-8",
        )
        run_one(
            root,
            python_bin,
            ("test_importable", "ImportTests", "test_imports_sterile_root"),
            timeout_seconds,
        )


def _self_test_assertion_isolation(python_bin: str, timeout_seconds: int) -> None:
    """Prove proposed code cannot reach or neutralize frozen assertion objects."""
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-assert-selftest-") as temp:
        root = Path(temp)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge" / "__init__.py").write_text(
            "import unittest\n"
            "unittest.TestCase.fail = lambda self, *args, **kwargs: None\n"
            "unittest.TestCase.assertEqual = lambda self, *args, **kwargs: None\n"
            "import __main__\n"
            "trusted = getattr(__main__, '_trusted_unittest', None)\n"
            "if trusted is not None:\n"
            "    trusted.TestCase.fail = lambda self, *args, **kwargs: None\n"
            "    trusted.TestCase.assertEqual = lambda self, *args, **kwargs: None\n",
            encoding="utf-8",
        )
        (root / "tests" / "test_fake.py").write_text(
            "import unittest\n"
            "import blue_forge\n\n"
            "class FakeTests(unittest.TestCase):\n"
            "    def test_must_fail(self):\n"
            "        self.fail('trusted assertion must execute')\n",
            encoding="utf-8",
        )
        try:
            run_one(
                root,
                python_bin,
                ("test_fake", "FakeTests", "test_must_fail"),
                timeout_seconds,
            )
        except SupervisionFailure:
            return
        raise SupervisionFailure(
            "supervisor self-test accepted proposed mutation of trusted assertions"
        )


def _self_test_method_resolution_isolation(python_bin: str, timeout_seconds: int) -> None:
    """Prove proposed mutation of real builtins cannot replace frozen methods."""
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-method-selftest-") as temp:
        root = Path(temp)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge" / "__init__.py").write_text(
            "import builtins\n"
            "real_getattr = builtins.getattr\n"
            "def forged_getattr(obj, name, *default):\n"
            "    if isinstance(name, str) and name.startswith('test'):\n"
            "        return lambda: None\n"
            "    if default:\n"
            "        return real_getattr(obj, name, *default)\n"
            "    return real_getattr(obj, name)\n"
            "builtins.getattr = forged_getattr\n",
            encoding="utf-8",
        )
        (root / "tests" / "test_fake.py").write_text(
            "import unittest\n"
            "import blue_forge\n\n"
            "class FakeTests(unittest.TestCase):\n"
            "    def test_must_fail(self):\n"
            "        self.fail('trusted method must execute')\n",
            encoding="utf-8",
        )
        try:
            run_one(
                root,
                python_bin,
                ("test_fake", "FakeTests", "test_must_fail"),
                timeout_seconds,
            )
        except SupervisionFailure:
            return
        raise SupervisionFailure(
            "supervisor self-test accepted proposed mutation of test-method resolution"
        )


def _self_test_accounting_isolation(python_bin: str, timeout_seconds: int) -> None:
    """Prove proposed code cannot replace trusted accounting through __main__."""
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-accounting-selftest-") as temp:
        root = Path(temp)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge" / "__init__.py").write_text(
            "import sys\n"
            "main = sys.modules.get('__main__')\n"
            "if main is not None:\n"
            "    main._testcase_run = lambda *args, **kwargs: None\n"
            "    main.result = type('ForgedResult', (), {'testsRun': 1, 'failures': [], 'errors': []})()\n",
            encoding="utf-8",
        )
        (root / "tests" / "test_fake.py").write_text(
            "import unittest\n"
            "import blue_forge\n\n"
            "class FakeTests(unittest.TestCase):\n"
            "    def test_must_fail(self):\n"
            "        self.fail('trusted assertion must execute')\n",
            encoding="utf-8",
        )
        try:
            run_one(
                root,
                python_bin,
                ("test_fake", "FakeTests", "test_must_fail"),
                timeout_seconds,
            )
        except SupervisionFailure:
            return
        raise SupervisionFailure(
            "supervisor self-test accepted proposed-code mutation of trusted accounting"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--python")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--worker-root", type=Path)
    parser.add_argument("--worker-module")
    parser.add_argument("--worker-class")
    parser.add_argument("--worker-method")
    args = parser.parse_args(argv)

    worker_values = (
        args.worker_root,
        args.worker_module,
        args.worker_class,
        args.worker_method,
    )
    if any(value is not None for value in worker_values):
        if not all(value is not None for value in worker_values):
            print("frozen_test_supervisor=FAIL reason=incomplete trusted worker arguments", file=sys.stderr)
            return 1
        try:
            _worker_run(
                args.worker_root.resolve(),
                (args.worker_module, args.worker_class, args.worker_method),
            )
        except SupervisionFailure as exc:
            print(f"frozen_test_worker=FAIL reason={exc}", file=sys.stderr)
            return 1
        return 0

    if args.root is None or args.python is None:
        parser.error("--root and --python are required for supervisor mode")

    root = args.root.resolve()
    try:
        _self_test_import_path(args.python, args.timeout_seconds)
        _self_test_assertion_isolation(args.python, args.timeout_seconds)
        _self_test_method_resolution_isolation(args.python, args.timeout_seconds)
        _self_test_accounting_isolation(args.python, args.timeout_seconds)
        tests = expected_tests(root)
        for identity in tests:
            run_one(root, args.python, identity, args.timeout_seconds)
    except SupervisionFailure as exc:
        print(f"frozen_test_supervisor=FAIL reason={exc}", file=sys.stderr)
        return 1

    print(f"frozen_test_supervisor=PASS tests={len(tests)} root={root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
