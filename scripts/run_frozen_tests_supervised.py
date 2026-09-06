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
import os
import posix
from pathlib import Path
import sys
import types
import unittest as _trusted_unittest

root = Path(__ROOT__).resolve()
module_name = __MODULE__
class_name = __CLASS__
method_name = __METHOD__


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

# Remove the straightforward Python-level routes to trusted runner frames or C
# process termination. The frozen BLUE-FORGE tests do not require these modules.
for _name in ("_getframe", "_current_frames", "settrace", "setprofile"):
    if hasattr(sys, _name):
        setattr(sys, _name, _blocked)
for _module_name in ("ctypes", "_ctypes", "gc", "inspect"):
    sys.modules[_module_name] = None

# Give trusted test source a private copy of the unittest module namespace. Proposed
# code importing the real unittest module cannot replace the TestCase reference
# used by subsequent frozen class definitions.
_unittest_proxy = types.ModuleType("unittest")
_unittest_proxy.__dict__.update(dict(_trusted_unittest.__dict__))
_real_import = builtins.__import__
_test_builtins = dict(vars(builtins))


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and name == "unittest":
        return _unittest_proxy
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
    if not isinstance(case_class, type) or not issubclass(case_class, _trusted_unittest.TestCase):
        raise AssertionError(f"frozen test class identity changed: {class_name}")

    case = case_class(method_name)
    setup = case.setUp
    method = getattr(case, method_name)
    teardown = case.tearDown

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

    try:
        completed = subprocess.run(
            [
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
            ],
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SupervisionFailure(f"frozen test worker failed to execute: {test_id}: {exc}") from exc

    require(
        completed.returncode == 0,
        f"frozen test did not complete in trusted worker: {test_id}: "
        f"rc={completed.returncode}\n{completed.stdout}",
    )


def _self_test(python_bin: str, timeout_seconds: int) -> None:
    """Prove proposed code cannot replace trusted accounting through __main__."""
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-selftest-") as temp:
        root = Path(temp)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge" / "__init__.py").write_text(
            "import sys\n"
            "main = sys.modules.get('__main__')\n"
            "if main is not None:\n"
            "    main._testcase_run = lambda case, result: setattr(result, 'testsRun', 1)\n"
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
        _self_test(args.python, args.timeout_seconds)
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
