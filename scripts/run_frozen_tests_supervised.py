#!/usr/bin/env python3
"""Trusted hardening entrypoint for the frozen-test supervisor.

The transport implementation is retained in a private sibling module. This
entrypoint installs load-bearing fail-closed fixes before every supervisor,
worker, and actor mode. Worker-facing actor framing is owned by a broker process
that never imports proposed application code; proposed objects live in a
separate executor child within the same kernel sandbox.
"""
from __future__ import annotations

import ast
import importlib.util
import marshal
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import types


_IMPL = Path(__file__).with_name("_run_frozen_tests_supervised_impl.py")
_EXECUTOR = Path(__file__).with_name("run_proposed_executor.py")
_spec = importlib.util.spec_from_file_location("_blue_forge_supervisor_impl", _IMPL)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted supervisor implementation is unavailable")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
# The retained implementation uses its module __file__ to spawn workers/actors.
# Point it at this hardened entrypoint so every descendant installs these fixes.
base.__file__ = str(Path(__file__).resolve())


def _read_exact(stream, count):
    chunks = bytearray()
    while len(chunks) < count:
        chunk = stream.read(count - len(chunks))
        if not chunk:
            raise base.SupervisionFailure("proposed executor channel closed")
        chunks.extend(chunk)
    return bytes(chunks)


def _send_executor(stream, value):
    payload = marshal.dumps(value, 4)
    base.require(
        len(payload) <= base.MAX_FRAME_BYTES,
        "proposed executor request byte budget exceeded",
    )
    stream.write(len(payload).to_bytes(8, "big"))
    stream.write(payload)
    stream.flush()


def _recv_executor(stream):
    header = _read_exact(stream, 8)
    size = int.from_bytes(header, "big")
    base.require(
        0 <= size <= base.MAX_FRAME_BYTES,
        "proposed executor response byte budget exceeded",
    )
    try:
        return marshal.loads(_read_exact(stream, size))
    except (EOFError, TypeError, ValueError) as exc:
        raise base.SupervisionFailure("malformed proposed executor response") from exc


def _stop_executor(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise base.SupervisionFailure("proposed executor did not terminate") from exc


def _protect_broker_process():
    # Closing inherited fds is insufficient if a same-UID descendant can reopen
    # a broker fd through /proc. Apply the native control before spawning it.
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
        raise base.SupervisionFailure("broker descriptor-reopening protection failed")


def _broker_actor(root):
    """Broker worker RPC without importing proposed code in this interpreter."""
    root = root.resolve()
    info = _EXECUTOR.lstat()
    base.require(
        stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
        "proposed executor must be a root-owned non-writable regular file",
    )
    _protect_broker_process()

    wire_in, wire_out = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr
    process = subprocess.Popen(
        [sys.executable, "-I", str(_EXECUTOR), str(root)],
        cwd=root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
        start_new_session=True,
        bufsize=0,
    )
    try:
        for _number in range(base.MAX_OPERATIONS):
            raw = wire_in.readline(base.MAX_FRAME_BYTES + 2)
            if not raw:
                return
            base.require(
                len(raw) <= base.MAX_FRAME_BYTES + 1 and raw.endswith(b"\n"),
                "oversized actor request",
            )
            request = base._wire_load(raw[:-1])
            base.require(type(request) is dict, "actor request is not an object")
            sequence = request.get("sequence")
            base.require(type(sequence) is int, "actor request sequence is invalid")

            _send_executor(process.stdin, request)
            response = _recv_executor(process.stdout)
            base.require(type(response) is dict, "executor response is not an object")
            base.require(
                response.get("sequence") == sequence,
                "executor response sequence mismatch",
            )
            base.require(
                type(response.get("ok")) is bool
                and type(response.get("states")) is dict,
                "malformed executor response",
            )
            if response["ok"]:
                base.require("value" in response, "executor success omitted value")
            else:
                base.require(
                    "error" in response and type(response.get("message")) is str,
                    "executor failure omitted identity",
                )

            # This is the only worker-facing response serialization path. The
            # proposed interpreter is outside this broker and cannot replace the
            # broker's codec, response object, handles, or call-frame globals.
            wire_out.write(base._wire_dump(response) + b"\n")
            wire_out.flush()
        raise base.SupervisionFailure("actor operation budget exceeded")
    finally:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        _stop_executor(process)
        if process.stdout is not None:
            process.stdout.close()


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


def _hardened_close(self):
    """Let the broker reap its executor before using the lifeline as a kill switch."""
    try:
        self.process.stdin.close()
    except OSError:
        pass

    try:
        self.process.wait(timeout=6)
    except subprocess.TimeoutExpired:
        if self.control_fd is not None:
            os.close(self.control_fd)
            self.control_fd = None
        try:
            self.process.wait(timeout=6)
        except subprocess.TimeoutExpired as exc:
            base._kill_group(self.process)
            raise base.SupervisionFailure(
                "isolated actor launcher did not confirm namespace teardown"
            ) from exc
    finally:
        if self.control_fd is not None:
            os.close(self.control_fd)
            self.control_fd = None
        if self.process.poll() is None:
            base._kill_group(self.process)
        self.control_dir.cleanup()
        self.reader.join(timeout=3)
        self.process.stdout.close()
        self.process.stderr.close()

    diagnostic = bytes(self.tail).decode("utf-8", errors="replace")
    base.require(
        self.process.returncode == 0,
        f"isolated actor launcher failed during cleanup: rc={self.process.returncode}\n{diagnostic}",
    )
    base.require(
        not self.reader.is_alive(),
        "actor stderr descendants survived namespace teardown",
    )


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


def _current_suite_only(tree, path):
    """Recognize only an exact literal current-floor classification marker."""
    markers = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "CURRENT_SUITE_ONLY"
        ):
            markers.append(node.value)
    if not markers:
        return False
    base.require(
        len(markers) == 1
        and isinstance(markers[0], ast.Constant)
        and markers[0].value is True,
        f"invalid CURRENT_SUITE_ONLY marker in {path.name}",
    )
    return True


def _hardened_expected_tests(root):
    """Enumerate the static TestCase floor without silently losing aliases."""
    tests = []
    supervised_current = bool(os.environ.get("BLUE_FORGE_SUPERVISED_MARKER"))
    for path in sorted((root / "tests").glob("test*.py")):
        base.require(path.is_file() and not path.is_symlink(), "invalid frozen test file")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if _current_suite_only(tree, path) and not supervised_current:
            continue
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
            local_bases(node)
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
        (root / "tests/test_current_only.py").write_text(
            "import unittest\n"
            "CURRENT_SUITE_ONLY = True\n"
            "class CurrentOnly(unittest.TestCase):\n"
            " def test_kernel_only(self): pass\n",
            encoding="utf-8",
        )
        previous = os.environ.pop("BLUE_FORGE_SUPERVISED_MARKER", None)
        try:
            frozen_actual = set(_hardened_expected_tests(root))
            frozen_expected = {
                ("test_alias", "Parent", "test_inherited"),
                ("test_alias", "Child", "test_inherited"),
                ("test_alias", "Child", "test_child"),
            }
            base.require(
                frozen_actual == frozen_expected,
                "current-only module entered frozen TestCase enumeration",
            )
            os.environ["BLUE_FORGE_SUPERVISED_MARKER"] = "enumeration-selftest"
            current_actual = set(_hardened_expected_tests(root))
            current_expected = set(frozen_expected)
            current_expected.add(("test_current_only", "CurrentOnly", "test_kernel_only"))
            base.require(
                current_actual == current_expected,
                "current-only module was omitted from supervised current enumeration",
            )
        finally:
            if previous is None:
                os.environ.pop("BLUE_FORGE_SUPERVISED_MARKER", None)
            else:
                os.environ["BLUE_FORGE_SUPERVISED_MARKER"] = previous


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


def _self_test_transport_process_boundary(python_bin, timeout_seconds, *, local_test=False):
    """Proposed code must not reach broker or executor response framing."""
    with tempfile.TemporaryDirectory(prefix="blue-forge-transport-selftest-") as temp:
        root = Path(temp)
        root.chmod(0o755)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge/__init__.py").write_text(
            "import inspect\n"
            "import __main__\n"
            "def _forged(*args, **kwargs):\n"
            " return None\n"
            "try:\n"
            " __main__._write_frame=_forged\n"
            "except BaseException:\n"
            " pass\n"
            "def probe():\n"
            " frame=inspect.currentframe().f_back\n"
            " while frame is not None:\n"
            "  namespace=frame.f_globals\n"
            "  candidate=namespace.get('base')\n"
            "  if candidate is not None and hasattr(candidate,'_wire_dump'):\n"
            "   candidate._wire_dump=lambda value: b'{\\\"sequence\\\":1,\\\"ok\\\":true,\\\"value\\\":[\\\"data\\\",[\\\"scalar\\\",\\\"real\\\"]],\\\"states\\\":{}}'\n"
            "  if '_write_frame' in namespace:\n"
            "   namespace['_write_frame']=_forged\n"
            "  frame=frame.f_back\n"
            " return 'wrong'\n",
            encoding="utf-8",
        )
        (root / "tests/test_transport.py").write_text(
            "import unittest\n"
            "from blue_forge import probe\n"
            "class Transport(unittest.TestCase):\n"
            " def test_truth(self): self.assertEqual(probe(), 'wrong')\n"
            " def test_forgery_fails(self): self.assertEqual(probe(), 'real')\n",
            encoding="utf-8",
        )
        base.run_one(
            root,
            python_bin,
            ("test_transport", "Transport", "test_truth"),
            timeout_seconds,
            local_test=local_test,
        )
        try:
            base.run_one(
                root,
                python_bin,
                ("test_transport", "Transport", "test_forgery_fails"),
                timeout_seconds,
                local_test=local_test,
            )
        except base.SupervisionFailure:
            return
        raise base.SupervisionFailure(
            "proposed code rewrote trusted broker/executor observation framing"
        )


def _self_test_dispatch_and_descriptors(python_bin, timeout_seconds, *, local_test=False):
    """Paired reproductions for dispatch poisoning and raw process-fd forgery."""
    dispatch = r'''
import inspect
frame = inspect.currentframe()
while frame is not None:
    namespace = frame.f_globals
    if frame.f_code.co_name == 'execute_action' and 'getattr_fn' in namespace:
        original = namespace['getattr_fn']
        namespace['getattr_fn'] = lambda obj, name: (lambda: 'real') if name == 'probe' else original(obj, name)
    frame = frame.f_back
del frame
def probe(): return 'wrong'
'''
    descriptors = r'''
import os
import marshal
for sequence, value in ((1, ['handle', [0, 'module']]),
                         (2, ['handle', [1, 'function']]),
                         (3, ['data', ['scalar', 'real']])):
    payload = marshal.dumps({'sequence': sequence, 'ok': True, 'value': value, 'states': {}}, 4)
    os.write(1, len(payload).to_bytes(8, 'big') + payload)
os.dup2(2, 1)
def probe(): return 'wrong'
'''
    reopening = r'''
import os
from pathlib import Path
def probe():
    parent = os.getppid()
    # Both the immediate transport parent and its upstream broker must deny
    # same-UID descriptor reopening. No data is written even on failure.
    for _ in range(2):
        try:
            fd = os.open('/proc/%d/fd/1' % parent, os.O_WRONLY)
        except PermissionError:
            pass
        else:
            os.close(fd)
            return 'reopened'
        status = Path('/proc/%d/status' % parent).read_text()
        parent = int(next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:')))
    return 'wrong'
'''
    mutation = r'''
import inspect
frame = inspect.currentframe()
while frame is not None:
    if frame.f_code.co_name == 'execute_action':
        frame.f_globals['getattr_fn'] = lambda *args: (lambda: 'real')
    frame = frame.f_back
del frame
def probe(): return 'wrong'
'''
    for name, source in (("dispatch", dispatch), ("descriptors", descriptors),
                         ("reopening", reopening), ("mutation", mutation)):
        with tempfile.TemporaryDirectory(prefix="blue-forge-boundary-selftest-") as temp:
            root = Path(temp)
            root.chmod(0o755)
            (root / "tests").mkdir()
            (root / "blue_forge").mkdir()
            (root / "blue_forge/__init__.py").write_text(source, encoding="utf-8")
            (root / "tests/test_boundary.py").write_text(
                "import unittest\nimport blue_forge\n"
                "class Boundary(unittest.TestCase):\n"
                " def test_truth(self): self.assertEqual(blue_forge.probe(), 'wrong')\n"
                " def test_forgery(self): self.assertEqual(blue_forge.probe(), 'real')\n",
                encoding="utf-8",
            )
            if name != "mutation":
                base.run_one(root, python_bin, ("test_boundary", "Boundary", "test_truth"),
                             timeout_seconds, local_test=local_test)
            try:
                base.run_one(root, python_bin, ("test_boundary", "Boundary", "test_forgery"),
                             timeout_seconds, local_test=local_test)
            except base.SupervisionFailure as exc:
                if name == "mutation":
                    base.require("mutated its invocation namespace" in str(exc),
                                 "namespace mutation failed for an unrelated reason")
            else:
                raise base.SupervisionFailure("executor boundary self-test accepted " + name)
    print("executor_dispatch_isolation=PASS executor_descriptor_isolation=PASS")


_original_self_test = base._self_test


def _combined_self_test(python_bin, timeout_seconds, *, local_test=False):
    _original_self_test(python_bin, timeout_seconds, local_test=local_test)
    _self_test_enumeration()
    _self_test_exception_identity(
        python_bin, timeout_seconds, local_test=local_test
    )
    _self_test_transport_process_boundary(
        python_bin, timeout_seconds, local_test=local_test
    )
    _self_test_dispatch_and_descriptors(
        python_bin, timeout_seconds, local_test=local_test
    )


base._actor = _broker_actor
base._Bridge.request = _hardened_request
base._Bridge.close = _hardened_close
base.expected_tests = _hardened_expected_tests
base._self_test = _combined_self_test

# ---------------------------------------------------------------------------
# Review-round P1 hardening: dynamic frozen-test membership, subprocess escape,
# and the /proc/self/mem response-mailbox overwrite reproduction.
# ---------------------------------------------------------------------------

def _module_level_nodes(node):
    """Yield executable module-level AST without descending into definitions."""
    yield node
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    for child in ast.iter_child_nodes(node):
        yield from _module_level_nodes(child)


def _target_writes_test_member(target):
    if isinstance(target, ast.Attribute):
        return target.attr.startswith("test")
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_writes_test_member(item) for item in target.elts)
    return False


def _reject_dynamic_test_membership(tree, path):
    """Fail closed when module-level code can mutate TestCase membership."""
    dangerous_names = {"setattr", "delattr", "exec", "eval"}
    dangerous_attrs = {"setattr", "delattr", "__setattr__", "__delattr__"}
    for statement in tree.body:
        for node in _module_level_nodes(statement):
            if isinstance(node, ast.Call):
                function = node.func
                if (
                    isinstance(function, ast.Name) and function.id in dangerous_names
                ) or (
                    isinstance(function, ast.Attribute) and function.attr in dangerous_attrs
                ):
                    raise base.SupervisionFailure(
                        f"dynamic frozen test membership is unsupported in {path.name}"
                    )
            if isinstance(node, ast.Assign):
                if any(_target_writes_test_member(target) for target in node.targets):
                    raise base.SupervisionFailure(
                        f"dynamic frozen test member assignment is unsupported in {path.name}"
                    )
            elif isinstance(node, ast.AnnAssign):
                if _target_writes_test_member(node.target):
                    raise base.SupervisionFailure(
                        f"dynamic frozen test member assignment is unsupported in {path.name}"
                    )
            elif isinstance(node, ast.AugAssign):
                if _target_writes_test_member(node.target):
                    raise base.SupervisionFailure(
                        f"dynamic frozen test member assignment is unsupported in {path.name}"
                    )
            elif isinstance(node, ast.Delete):
                if any(_target_writes_test_member(target) for target in node.targets):
                    raise base.SupervisionFailure(
                        f"dynamic frozen test member deletion is unsupported in {path.name}"
                    )


_previous_expected_tests = base.expected_tests


def _strict_expected_tests(root):
    supervised_current = bool(os.environ.get("BLUE_FORGE_SUPERVISED_MARKER"))
    for path in sorted((root / "tests").glob("test*.py")):
        base.require(path.is_file() and not path.is_symlink(), "invalid frozen test file")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if _current_suite_only(tree, path) and not supervised_current:
            continue
        _reject_dynamic_test_membership(tree, path)
    return _previous_expected_tests(root)


def _hardened_test_importer(bridge):
    """Expose no worker-local process creation path to frozen test modules."""
    real_import = base.builtins.__import__
    json_proxy = types.ModuleType("json")
    json_proxy.__dict__.update(vars(base.json))
    json_proxy.dumps = lambda value, *a, **k: base.json.dumps(base._local(value), *a, **k)
    dc_proxy = types.ModuleType("dataclasses")
    dc_proxy.__dict__.update(vars(base.dataclasses))
    dc_proxy.replace = base._remote_replace
    process_proxy = types.ModuleType("subprocess")

    for name in (
        "PIPE", "STDOUT", "DEVNULL", "CompletedProcess", "CalledProcessError",
        "TimeoutExpired", "SubprocessError",
    ):
        setattr(process_proxy, name, getattr(subprocess, name))

    safe_flags = {"-I", "-E", "-s", "-S", "-B", "-P", "-u"}
    safe_xoptions = {"utf8", "utf8=1", "utf8=0"}

    def cli_details(command):
        base.require(type(command) in (list, tuple), "subprocess command must be an exact sequence")
        items = list(command)
        base.require(items and all(type(item) is str for item in items),
                     "subprocess command entries must be exact strings")
        base.require(Path(items[0]).resolve() == Path(sys.executable).resolve(),
                     "only the current Python executable may invoke proposed CLI")
        index = 1
        while index < len(items) and items[index] != "-m":
            token = items[index]
            if token in safe_flags:
                index += 1
                continue
            if token == "-X":
                base.require(index + 1 < len(items) and items[index + 1] in safe_xoptions,
                             "unsupported Python -X option for proposed CLI")
                index += 2
                continue
            raise base.SupervisionFailure("unsupported Python flag for proposed CLI")
        base.require(index + 1 < len(items) and items[index:index + 2] == ["-m", "blue_forge"],
                     "subprocess invocation is not an explicitly bridged proposed CLI")
        cli = items[index + 2:]
        base.require(len(cli) == 2 and cli[0] in {"verify", "regression"},
                     "unsupported proposed CLI invocation")
        return cli[0], Path(cli[1])

    def run(command, *args, **kwargs):
        base.require(not args, "positional subprocess.run options are unsupported")
        allowed = {
            "env", "check", "text", "universal_newlines", "encoding", "errors",
            "stdout", "stderr", "capture_output", "timeout", "cwd",
        }
        unknown = set(kwargs) - allowed
        base.require(not unknown, "unsupported subprocess.run option: " + ",".join(sorted(unknown)))
        subcommand, path = cli_details(command)
        cwd = kwargs.get("cwd")
        if cwd is not None:
            base.require(Path(cwd).resolve() == Path(bridge.root).resolve(),
                         "proposed CLI cwd must remain the sterile root")
        timeout = kwargs.get("timeout")
        if timeout is not None:
            base.require(type(timeout) in (int, float) and not isinstance(timeout, bool)
                         and 0 < timeout <= 15,
                         "proposed CLI timeout exceeds actor budget")
        capture_output = kwargs.get("capture_output", False)
        base.require(type(capture_output) is bool, "capture_output must be boolean")
        stdout_mode = kwargs.get("stdout")
        stderr_mode = kwargs.get("stderr")
        if capture_output:
            base.require(stdout_mode is None and stderr_mode is None,
                         "capture_output conflicts with stdout/stderr")
            stdout_mode = subprocess.PIPE
            stderr_mode = subprocess.PIPE
        base.require(stdout_mode in (None, subprocess.PIPE, subprocess.DEVNULL),
                     "unsupported stdout target for proposed CLI")
        base.require(stderr_mode in (None, subprocess.PIPE, subprocess.DEVNULL, subprocess.STDOUT),
                     "unsupported stderr target for proposed CLI")
        env_value = kwargs.get("env")
        if env_value is None:
            env = dict(os.environ)
        else:
            base.require(type(env_value) is dict and all(
                type(key) is str and type(value) is str for key, value in env_value.items()
            ), "proposed CLI environment must be an exact string mapping")
            env = dict(env_value)
        env = {key: value for key, value in env.items() if not key.startswith("BLUE_FORGE_")}
        base.require(path.is_file(), "proposed CLI case path is not a regular file")
        with path.open("rb") as handle:
            payload = handle.read(2 * 1024 * 1024)
        base.require(len(payload) <= 2 * 1024 * 1024,
                     "proposed CLI case transport budget exceeded")
        rc, stdout, stderr = bridge.request("cli", [subcommand], payload, env)
        if stderr_mode == subprocess.STDOUT:
            stdout = stdout + stderr
            stderr = b""
        text_mode = bool(
            kwargs.get("text") or kwargs.get("universal_newlines")
            or kwargs.get("encoding") is not None or kwargs.get("errors") is not None
        )
        if text_mode:
            encoding = kwargs.get("encoding") or "utf-8"
            errors = kwargs.get("errors") or "strict"
            base.require(type(encoding) is str and type(errors) is str,
                         "invalid proposed CLI text decoding options")
            stdout = stdout.decode(encoding, errors)
            stderr = stderr.decode(encoding, errors)
        returned_stdout = stdout if stdout_mode == subprocess.PIPE else None
        returned_stderr = stderr if stderr_mode == subprocess.PIPE else None
        completed = subprocess.CompletedProcess(command, rc, returned_stdout, returned_stderr)
        if kwargs.get("check"):
            completed.check_returncode()
        return completed

    def check_output(command, *args, **kwargs):
        base.require("stdout" not in kwargs, "stdout argument not allowed for check_output")
        kwargs = dict(kwargs)
        kwargs["stdout"] = subprocess.PIPE
        kwargs["check"] = True
        return run(command, *args, **kwargs).stdout

    def check_call(command, *args, **kwargs):
        kwargs = dict(kwargs)
        kwargs["check"] = True
        return run(command, *args, **kwargs).returncode

    def call(command, *args, **kwargs):
        kwargs = dict(kwargs)
        kwargs.pop("check", None)
        return run(command, *args, **kwargs).returncode

    def blocked_popen(*args, **kwargs):
        del args, kwargs
        raise base.SupervisionFailure(
            "subprocess.Popen is not available in trusted frozen-test workers"
        )

    def blocked_shell_helper(*args, **kwargs):
        del args, kwargs
        raise base.SupervisionFailure(
            "shell subprocess helpers are not available in trusted frozen-test workers"
        )

    process_proxy.run = run
    process_proxy.check_output = check_output
    process_proxy.check_call = check_call
    process_proxy.call = call
    process_proxy.Popen = blocked_popen
    process_proxy.getoutput = blocked_shell_helper
    process_proxy.getstatusoutput = blocked_shell_helper
    facades = {"json": json_proxy, "dataclasses": dc_proxy, "subprocess": process_proxy}

    def trusted_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in facades:
            return facades[name]
        return real_import(name, globals, locals, fromlist, level)

    return trusted_import


def _self_test_dynamic_membership():
    with tempfile.TemporaryDirectory(prefix="blue-forge-dynamic-enumeration-") as temp:
        root = Path(temp)
        (root / "tests").mkdir()
        path = root / "tests/test_dynamic.py"
        path.write_text(
            "import unittest\n"
            "class Dynamic(unittest.TestCase): pass\n"
            "def generated(self): self.fail('must be enumerated or rejected')\n"
            "setattr(Dynamic, 'test_generated', generated)\n"
            "class Control(unittest.TestCase):\n"
            " def test_control(self): pass\n",
            encoding="utf-8",
        )
        try:
            _strict_expected_tests(root)
        except base.SupervisionFailure as exc:
            base.require("dynamic frozen test membership" in str(exc),
                         "dynamic test rejection failed for an unrelated reason")
            return
        raise base.SupervisionFailure("dynamic frozen test installation was silently omitted")


def _self_test_subprocess_facade():
    class FakeBridge:
        def __init__(self, root):
            self.root = root
        def request(self, action, *arguments):
            base.require(action == "cli", "subprocess self-test escaped CLI bridge")
            base.require(arguments[0] == ["verify"], "subprocess self-test lost CLI action")
            return 0, b"bridged", b"diagnostic"

    with tempfile.TemporaryDirectory(prefix="blue-forge-subprocess-facade-") as temp:
        root = Path(temp)
        case = root / "case.json"
        case.write_bytes(b"{}")
        proxy = _hardened_test_importer(FakeBridge(root))("subprocess")
        command = [
            sys.executable, "-I", "-X", "utf8", "-m", "blue_forge", "verify", str(case)
        ]
        completed = proxy.run(command, capture_output=True, check=True)
        base.require(completed.stdout == b"bridged" and completed.stderr == b"diagnostic",
                     "bridged subprocess.run lost captured output")
        base.require(proxy.check_output(command) == b"bridged",
                     "bridged subprocess.check_output failed")
        base.require(proxy.check_call(command) == 0 and proxy.call(command) == 0,
                     "bridged subprocess call helpers failed")
        for operation in (
            lambda: proxy.Popen(command),
            lambda: proxy.check_output(["/bin/echo", "escape"]),
        ):
            try:
                operation()
            except base.SupervisionFailure:
                pass
            else:
                raise base.SupervisionFailure("unbridged subprocess creation reached trusted worker")


def _self_test_proc_memory_boundary(python_bin, timeout_seconds, *, local_test=False):
    if local_test:
        return
    with tempfile.TemporaryDirectory(prefix="blue-forge-proc-memory-selftest-") as temp:
        root = Path(temp)
        root.chmod(0o755)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge/__init__.py").write_text(
            "import os\n"
            "def probe():\n"
            " try:\n"
            "  fd=os.open('/proc/self/mem', os.O_RDWR)\n"
            " except OSError:\n"
            "  return 'blocked'\n"
            " else:\n"
            "  os.close(fd)\n"
            "  return 'open'\n",
            encoding="utf-8",
        )
        (root / "tests/test_memory.py").write_text(
            "import unittest\nfrom blue_forge import probe\n"
            "class Memory(unittest.TestCase):\n"
            " def test_blocked(self): self.assertEqual(probe(), 'blocked')\n"
            " def test_open_fails(self): self.assertEqual(probe(), 'open')\n",
            encoding="utf-8",
        )
        base.run_one(root, python_bin, ("test_memory", "Memory", "test_blocked"),
                     timeout_seconds, local_test=local_test)
        try:
            base.run_one(root, python_bin, ("test_memory", "Memory", "test_open_fails"),
                         timeout_seconds, local_test=local_test)
        except base.SupervisionFailure:
            print("executor_memory_isolation=PASS")
            return
        raise base.SupervisionFailure("actor exposed /proc/self/mem to proposed Python")


_previous_p1_self_test = base._self_test


def _p1_self_test(python_bin, timeout_seconds, *, local_test=False):
    _previous_p1_self_test(python_bin, timeout_seconds, local_test=local_test)
    _self_test_dynamic_membership()
    _self_test_subprocess_facade()
    _self_test_proc_memory_boundary(
        python_bin, timeout_seconds, local_test=local_test
    )
    print("dynamic_test_enumeration=PASS subprocess_actor_routing=PASS")


base.expected_tests = _strict_expected_tests
base._test_importer = _hardened_test_importer
base._self_test = _p1_self_test

# The broker imports no proposed module, but keep its importable __main__ inert so
# application code in descendants never gains a stable reference to this wrapper.
if "--actor-root" in sys.argv:
    sys.modules["__main__"] = types.ModuleType("__main__")


if __name__ == "__main__":
    raise SystemExit(base.main())
