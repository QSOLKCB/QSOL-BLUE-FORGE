#!/usr/bin/env python3
"""Trusted supervisor for frozen tests executed against proposed source.

The supervisor never imports repository application code. It statically enumerates
expected unittest methods from trusted test files, launches each test in a fresh
child interpreter, and independently requires the normal unittest completion line
for that exact test. A proposed package calling os._exit(0) during import therefore
cannot turn an incomplete run into supervisor success merely by returning status 0.
"""

from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import re
import subprocess
import sys


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


def run_one(
    root: Path,
    python_bin: str,
    identity: tuple[str, str, str],
    timeout_seconds: int,
) -> None:
    module, class_name, method = identity
    test_id = f"{module}.{class_name}.{method}"
    env = dict(os.environ)
    pythonpath = [str(root), str(root / "tests")]
    existing = env.get("PYTHONPATH")
    if existing:
        pythonpath.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)

    try:
        completed = subprocess.run(
            [python_bin, "-m", "unittest", test_id, "-v"],
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

    output = completed.stdout
    require(completed.returncode == 0, f"frozen test failed: {test_id}: rc={completed.returncode}\n{output}")

    escaped_id = re.escape(test_id)
    escaped_method = re.escape(method)
    completion = re.compile(
        rf"^{escaped_method} \({escaped_id}\) \.\.\. ok$",
        re.MULTILINE,
    )
    require(
        completion.search(output) is not None,
        f"frozen test did not report supervised completion: {test_id}\n{output}",
    )
    require(
        re.search(r"^Ran 1 test in ", output, re.MULTILINE) is not None,
        f"frozen test did not report exactly one executed test: {test_id}\n{output}",
    )
    require(
        re.search(r"^OK$", output, re.MULTILINE) is not None,
        f"frozen test did not report unittest OK: {test_id}\n{output}",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--python", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    try:
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
