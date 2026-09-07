#!/usr/bin/env python3
"""Trusted hardening entrypoint for the frozen-test supervisor.

The transport implementation is retained in a private sibling module.  This
entrypoint installs load-bearing fail-closed fixes before every supervisor,
worker, and actor mode, then makes child processes re-enter this file.
"""
from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types


_IMPL = Path(__file__).with_name("_run_frozen_tests_supervised_impl.py")
_spec = importlib.util.spec_from_file_location("_blue_forge_supervisor_impl", _IMPL)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted supervisor implementation is unavailable")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
# The retained implementation uses its module __file__ to spawn workers/actors.
# Point it at this hardened entrypoint so every descendant installs these fixes.
base.__file__ = str(Path(__file__).resolve())


def _exception_key(exc, exported_validation, exported_blue):
    """Classify by actual class identity/MRO, never by mutable class name."""
    cls = type(exc)
    mro = type.__getattribute__(cls, "__mro__")
    if exported_validation is not None and any(item is exported_validation for item in mro):
        return "blue_forge.ValidationError"
    if exported_blue is not None and any(item is exported_blue for item in mro):
        return "blue_forge.BlueForgeError"
    builtins = {
        AssertionError: "builtins.AssertionError",
        AttributeError: "builtins.AttributeError",
        TypeError: "builtins.TypeError",
        ValueError: "builtins.ValueError",
        KeyError: "builtins.KeyError",
        StopIteration: "builtins.StopIteration",
        RuntimeError: "builtins.RuntimeError",
    }
    return builtins.get(cls)


def _hardened_actor(root):
    """Actor transport with exported-exception identity preserved explicitly."""
    root = root.resolve()
    sys.path.insert(0, str(root))
    os.chdir(root)
    wire_in, wire_out = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr
    handles = {}
    identities = {}
    exported_validation = None
    exported_blue = None

    def result(value):
        if value is None or type(value) in (str, bytes, int, float, bool):
            return ["data", base._encode_data(value)]
        if type(value) is tuple:
            return ["tuple", [result(v) for v in value]]
        oid = id(value)
        if oid not in identities:
            base.require(len(handles) < base.MAX_GRAPH_NODES, "actor handle budget exceeded")
            handle = len(handles)
            identities[oid] = handle
            handles[handle] = value
        return ["handle", [identities[oid], type(value).__name__]]

    def capture_exports():
        nonlocal exported_validation, exported_blue
        package = sys.modules.get("blue_forge")
        if package is None:
            return
        namespace = object.__getattribute__(package, "__dict__")
        validation = namespace.get("ValidationError")
        blue = namespace.get("BlueForgeError")
        if type(validation) is type:
            exported_validation = validation
        if type(blue) is type:
            exported_blue = blue

    for _number in range(base.MAX_OPERATIONS):
        raw = wire_in.readline(base.MAX_FRAME_BYTES + 2)
        if not raw:
            return
        base.require(
            len(raw) <= base.MAX_FRAME_BYTES + 1 and raw.endswith(b"\n"),
            "oversized actor request",
        )
        request = base._wire_load(raw[:-1])
        decoder = base._GraphDecoder(request["nodes"], handles)
        arguments = [decoder.decode(v) for v in request["arguments"]]
        action = request["action"]
        try:
            if action == "module":
                value = base.importlib.import_module(arguments[0])
                capture_exports()
            elif action == "getattr":
                value = getattr(*arguments)
            elif action == "setattr":
                value = setattr(*arguments)
            elif action == "delattr":
                value = delattr(*arguments)
            elif action == "call":
                function, args, kwargs = arguments
                value = function(*args, **kwargs)
            elif action == "getitem":
                value = arguments[0][arguments[1]]
            elif action == "setitem":
                arguments[0][arguments[1]] = arguments[2]
                value = None
            elif action == "delitem":
                del arguments[0][arguments[1]]
                value = None
            elif action == "truth":
                value = bool(arguments[0])
            elif action == "len":
                value = len(arguments[0])
            elif action == "iterate":
                items = tuple(base.itertools.islice(iter(arguments[0]), base.MAX_GRAPH_NODES + 1))
                base.require(len(items) <= base.MAX_GRAPH_NODES, "actor iteration budget exceeded")
                value = items
            elif action == "next":
                value = next(arguments[0])
            elif action == "deepcopy":
                value = base.copy.deepcopy(arguments[0])
            elif action == "replace":
                value = base.dataclasses.replace(arguments[0], **arguments[1])
            elif action == "object_setattr":
                value = object.__setattr__(*arguments)
            elif action == "export":
                value = base._encode_data(arguments[0])
            elif action == "cli":
                cli_args, case_bytes, environment = arguments
                with tempfile.TemporaryDirectory() as temp:
                    path = Path(temp) / "case.json"
                    path.write_bytes(case_bytes)
                    command = [sys.executable, "-m", "blue_forge", cli_args[0], str(path)]
                    value = base._run_cli_bounded(command, root, environment)
            else:
                raise base.SupervisionFailure("unknown actor operation")
            response = {
                "sequence": request["sequence"],
                "ok": True,
                "value": ["data", base._encode_data(value)] if action == "export" else result(value),
            }
        except BaseException as exc:
            response = {
                "sequence": request["sequence"],
                "ok": False,
                "error": _exception_key(exc, exported_validation, exported_blue),
                "message": str(exc),
            }
        states = {}
        for key in request.get("sync", []):
            if key in decoder.cache:
                states[str(key)] = base._encode_data(
                    object.__getattribute__(decoder.cache[key], "__dict__")
                )
        response["states"] = states
        wire_out.write(base._wire_dump(response) + b"\n")
        wire_out.flush()
    raise base.SupervisionFailure("actor operation budget exceeded")


def _hardened_request(self, action, *arguments):
    """Reconstruct only exception identities verified by the actor boundary."""
    base.require(self.fatal is None, "RPC bridge previously failed")
    self.sequence += 1
    encoder = base._GraphEncoder()
    response = None
    try:
        encoded = [encoder.encode(v) for v in arguments]
        request = {
            "sequence": self.sequence,
            "action": action,
            "arguments": encoded,
            "nodes": encoder.nodes,
            "sync": list(encoder.sync),
        }
        response = self._exchange(base._wire_dump(request))
        base.require(
            type(response) is dict and response.get("sequence") == self.sequence,
            "actor response sequence mismatch",
        )
        base.require(
            type(response.get("ok")) is bool and type(response.get("states")) is dict,
            "malformed actor response",
        )
        observation = base._wire_dump({"request": request, "response": response})
        self.last_receipt = base.hmac.new(
            self.signing_key, observation, base.hashlib.sha256
        ).hexdigest()
        for key, state in response["states"].items():
            base.require(
                key.isdecimal() and int(key) in encoder.sync,
                "unexpected fixture-state response",
            )
            target = object.__getattribute__(encoder.sync[int(key)], "__dict__")
            decoded = base._decode_data(state)
            base.require(type(decoded) is dict, "invalid fixture-state response")
            target.clear()
            target.update(decoded)
        if response["ok"]:
            return self._result(response["value"])
    except (
        base.SupervisionFailure,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        self.fatal = str(exc)
        diagnostic = bytes(self.tail).decode("utf-8", errors="replace")
        raise base.SupervisionFailure(f"RPC failed closed: {exc}\n{diagnostic}") from exc

    name = response.get("error")
    message = response.get("message")
    base.require(type(message) is str, "invalid actor exception message")
    known = {
        "blue_forge.ValidationError": base.ValidationError,
        "blue_forge.BlueForgeError": base.BlueForgeError,
        "builtins.AssertionError": AssertionError,
        "builtins.AttributeError": AttributeError,
        "builtins.TypeError": TypeError,
        "builtins.ValueError": ValueError,
        "builtins.KeyError": KeyError,
        "builtins.StopIteration": StopIteration,
        "builtins.RuntimeError": RuntimeError,
    }
    if name not in known:
        self.fatal = f"unexpected actor failure identity: {name!r}"
        raise base.SupervisionFailure(self.fatal)
    raise known[name](message)


def _base_ref(expr, unittest_aliases, symbols, classes):
    if isinstance(expr, ast.Attribute):
        if (
            expr.attr == "TestCase"
            and isinstance(expr.value, ast.Name)
            and expr.value.id in unittest_aliases
        ):
            return ("testcase", None)
        return ("unknown", ast.unparse(expr))
    if isinstance(expr, ast.Name):
        if expr.id == "object":
            return ("object", None)
        if expr.id in symbols:
            return symbols[expr.id]
        if expr.id in classes:
            return ("class", expr.id)
        return ("unknown", expr.id)
    return ("unknown", ast.unparse(expr))


def _hardened_expected_tests(root):
    """Enumerate the same static TestCase floor without silently losing aliases."""
    tests = []
    for path in sorted((root / "tests").glob("test*.py")):
        base.require(path.is_file() and not path.is_symlink(), "invalid frozen test file")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        unittest_aliases = {"unittest"}
        symbols = {}
        classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
        assignments = []

        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "unittest":
                        unittest_aliases.add(alias.asname or "unittest")
            elif isinstance(node, ast.ImportFrom) and node.module == "unittest":
                for alias in node.names:
                    if alias.name == "TestCase":
                        symbols[alias.asname or alias.name] = ("testcase", None)
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                assignments.append((node.targets[0].id, node.value))

        # Resolve simple aliases such as Base = unittest.TestCase and
        # Alias = LocalTestCase.  Anything dynamic remains unsupported rather
        # than being silently omitted from the protected floor.
        changed = True
        while changed:
            changed = False
            for name, value in assignments:
                if name in symbols:
                    continue
                ref = _base_ref(value, unittest_aliases, symbols, classes)
                if ref[0] in {"testcase", "class"}:
                    symbols[name] = ref
                    changed = True

        cache = {}
        visiting = set()

        def is_testcase(name):
            if name in cache:
                return cache[name]
            base.require(name not in visiting, "cyclic frozen test inheritance")
            visiting.add(name)
            node = classes[name]
            refs = [_base_ref(item, unittest_aliases, symbols, classes) for item in node.bases]
            result = False
            for kind, target in refs:
                if kind == "testcase":
                    result = True
                elif kind == "class" and is_testcase(target):
                    result = True
            visiting.remove(name)
            cache[name] = result
            return result

        def local_bases(node):
            refs = [_base_ref(item, unittest_aliases, symbols, classes) for item in node.bases]
            if any(kind == "unknown" for kind, _ in refs):
                # Unknown imported/dynamic bases can contribute tests or alter
                # discovery.  A protected TestCase must not silently proceed.
                if any(
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name.startswith("test")
                    for item in node.body
                ) or any(kind == "testcase" for kind, _ in refs) or any(
                    kind == "class" and is_testcase(target) for kind, target in refs
                ):
                    raise base.SupervisionFailure(
                        f"unsupported frozen TestCase base in {path.name}:{node.name}"
                    )
            return [target for kind, target in refs if kind == "class"]

        method_cache = {}

        def methods(name, stack=()):
            if name in method_cache:
                return dict(method_cache[name])
            base.require(name not in stack, "cyclic frozen test method inheritance")
            node = classes[name]
            found = {}
            for parent in local_bases(node):
                found.update(methods(parent, stack + (name,)))
            for item in node.body:
                if getattr(item, "name", "").startswith("test"):
                    if isinstance(item, ast.AsyncFunctionDef):
                        raise base.SupervisionFailure(
                            "async frozen tests require an explicit trusted runner"
                        )
                    if isinstance(item, ast.FunctionDef):
                        found[item.name] = item
                    else:
                        raise base.SupervisionFailure(
                            f"unsupported frozen test member {node.name}.{item.name}"
                        )
            method_cache[name] = dict(found)
            return found

        for name, node in classes.items():
            if not is_testcase(name):
                continue
            local_bases(node)  # validates unknown bases even with no own tests
            for method_name in sorted(methods(name)):
                tests.append((path.stem, name, method_name))

    base.require(tests and len(tests) == len(set(tests)), "empty or duplicate frozen test floor")
    return tests


def _self_test_enumeration():
    with tempfile.TemporaryDirectory(prefix="blue-forge-enumeration-selftest-") as temp:
        root = Path(temp)
        (root / "tests").mkdir()
        (root / "tests/test_alias.py").write_text(
            "import unittest\n"
            "Base = unittest.TestCase\n"
            "class Parent(Base):\n"
            " def test_inherited(self): pass\n"
            "Alias = Parent\n"
            "class Child(Alias):\n"
            " def test_child(self): pass\n",
            encoding="utf-8",
        )
        actual = set(_hardened_expected_tests(root))
        expected = {
            ("test_alias", "Parent", "test_inherited"),
            ("test_alias", "Child", "test_inherited"),
            ("test_alias", "Child", "test_child"),
        }
        base.require(actual == expected, "aliased/inherited TestCase enumeration self-test failed")


def _self_test_exception_identity(python_bin, timeout_seconds, *, local_test=False):
    with tempfile.TemporaryDirectory(prefix="blue-forge-exception-selftest-") as temp:
        root = Path(temp)
        root.chmod(0o755)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge/__init__.py").write_text(
            "class BlueForgeError(Exception): pass\n"
            "class ValidationError(BlueForgeError): pass\n"
            "class Wrong(Exception): pass\n"
            "Wrong.__name__='ValidationError'\n"
            "def right(): raise ValidationError('right')\n"
            "def wrong(): raise Wrong('wrong')\n",
            encoding="utf-8",
        )
        (root / "tests/test_identity.py").write_text(
            "import unittest\n"
            "from blue_forge import ValidationError, right, wrong\n"
            "class Identity(unittest.TestCase):\n"
            " def test_right(self):\n"
            "  with self.assertRaises(ValidationError): right()\n"
            " def test_wrong(self):\n"
            "  with self.assertRaises(ValidationError): wrong()\n",
            encoding="utf-8",
        )
        base.run_one(
            root,
            python_bin,
            ("test_identity", "Identity", "test_right"),
            timeout_seconds,
            local_test=local_test,
        )
        try:
            base.run_one(
                root,
                python_bin,
                ("test_identity", "Identity", "test_wrong"),
                timeout_seconds,
                local_test=local_test,
            )
        except base.SupervisionFailure:
            return
        raise base.SupervisionFailure("unrelated same-name exception satisfied ValidationError")


_original_self_test = base._self_test


def _combined_self_test(python_bin, timeout_seconds, *, local_test=False):
    _original_self_test(python_bin, timeout_seconds, local_test=local_test)
    _self_test_enumeration()
    _self_test_exception_identity(
        python_bin, timeout_seconds, local_test=local_test
    )


base._actor = _hardened_actor
base._Bridge.request = _hardened_request
base.expected_tests = _hardened_expected_tests
base._self_test = _combined_self_test

# Actor-side proposed imports must not recover this entrypoint's patch globals
# through the ordinary importable __main__ module.
if "--actor-root" in sys.argv:
    sys.modules["__main__"] = types.ModuleType("__main__")


if __name__ == "__main__":
    raise SystemExit(base.main())
