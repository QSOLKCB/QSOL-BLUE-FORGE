#!/usr/bin/env python3
"""Trusted supervisor for frozen tests executed against proposed source.

The supervisor never imports repository application code. It statically enumerates
expected unittest methods from trusted test files and launches each method in a
fresh child interpreter under a baseline-owned runner. Child stdout/stderr is
strictly diagnostic and never authorizes success. The parent accepts only the
runner's reserved completion exit code, which is emitted after the trusted runner
has observed one completed unittest with no failures or errors.
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


_PASS_EXIT = 73
_FAIL_EXIT = 74

# This runner is baseline-owned source embedded in the trusted supervisor. It is
# intentionally invoked with -I and imports the proposed package only after the
# ordinary Python exit shortcuts have been converted into exceptions. A proposed
# module may print any transcript it likes; the parent ignores it for authority.
_CHILD_RUNNER = r'''
import builtins
import importlib
import os
import posix
from pathlib import Path
import sys
import unittest

PASS_EXIT = 73
FAIL_EXIT = 74
_SystemExit = SystemExit


def _blocked_termination(*args, **kwargs):
    raise RuntimeError("direct interpreter termination is forbidden during supervised frozen tests")


# Block the exact early-success primitive under review and the Python exec family
# that could replace this trusted runner with a process choosing its own status.
os._exit = _blocked_termination
posix._exit = _blocked_termination
for _name in (
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"
):
    if hasattr(os, _name):
        setattr(os, _name, _blocked_termination)
    if hasattr(posix, _name):
        setattr(posix, _name, _blocked_termination)

# ctypes would provide a trivial route back to libc _exit(). Frozen reference
# tests do not require it, so the supervised interpreter removes that escape hatch.
sys.modules["ctypes"] = None
sys.modules["_ctypes"] = None

root = Path(sys.argv[1]).resolve()
test_id = sys.argv[2]
sys.path.insert(0, str(root / "tests"))
sys.path.insert(0, str(root))

# Capture trusted unittest behavior before importing any proposed application code.
_testcase_run = unittest.TestCase.run
_testcase_dict = dict(unittest.TestCase.__dict__)
_testresult_dict = dict(unittest.TestResult.__dict__)
result = unittest.TestResult()


def _restore_class(cls, snapshot):
    for name in list(cls.__dict__):
        if name not in snapshot and not (name.startswith("__") and name.endswith("__")):
            try:
                delattr(cls, name)
            except (AttributeError, TypeError):
                pass
    for name, value in snapshot.items():
        if name in {"__dict__", "__weakref__"}:
            continue
        try:
            setattr(cls, name, value)
        except (AttributeError, TypeError):
            pass


def _run_one():
    try:
        module_name, class_name, method_name = test_id.rsplit(".", 2)
        module = importlib.import_module(module_name)
        _restore_class(unittest.TestCase, _testcase_dict)
        _restore_class(unittest.TestResult, _testresult_dict)
        case_class = getattr(module, class_name)
        case = case_class(method_name)
        _testcase_run(case, result)
        return (
            result.testsRun == 1
            and not result.failures
            and not result.errors
            and not result.unexpectedSuccesses
        )
    except BaseException:
        return False


_ok = _run_one()
raise _SystemExit(PASS_EXIT if _ok else FAIL_EXIT)
'''


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

    try:
        completed = subprocess.run(
            [python_bin, "-I", "-c", _CHILD_RUNNER, str(root), test_id],
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
        raise SupervisionFailure(f"frozen test child failed to execute: {test_id}: {exc}") from exc

    # Child text is diagnostics only. A forged unittest-looking transcript cannot
    # convert rc=0 (or any other status) into the reserved trusted completion code.
    require(
        completed.returncode == _PASS_EXIT,
        f"frozen test did not reach trusted completion: {test_id}: "
        f"rc={completed.returncode}\n{completed.stdout}",
    )


def _self_test(python_bin: str, timeout_seconds: int) -> None:
    """Prove forged text + os._exit(0) cannot authenticate completion."""
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-selftest-") as temp:
        root = Path(temp)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge" / "__init__.py").write_text(
            "import os\n"
            "print('test_must_fail (test_fake.FakeTests.test_must_fail) ... ok')\n"
            "print('Ran 1 test in 0.000s')\n"
            "print('OK')\n"
            "os._exit(0)\n",
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
            "supervisor self-test accepted forged output from early-terminating proposed code"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--python", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args(argv)

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
