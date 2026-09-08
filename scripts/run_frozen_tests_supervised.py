#!/usr/bin/env python3
"""Second-stage trusted supervisor hardening for BLUE-FORGE PR #2.

The first-stage supervisor is preserved in a sibling baseline-owned module. This
entrypoint layers runtime test enumeration, exhaustive subprocess interception,
and corrected procfs-denial controls without weakening any earlier isolation
checks. Proposed BLUE-FORGE application code remains actor-separated.
"""
from __future__ import annotations

import ast
import base64
import builtins
import contextlib
import hashlib
import hmac
import importlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types

_ROUND1 = Path(__file__).with_name("_run_frozen_tests_supervised_round1.py")
_spec = importlib.util.spec_from_file_location("_blue_forge_supervisor_round1", _ROUND1)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted first-stage supervisor is unavailable")
previous = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(previous)
base = previous.base

# Descendants must re-enter this final entrypoint, not the retained first stage.
base.__file__ = str(Path(__file__).resolve())


def _corrected_dispatch_and_descriptors(
    python_bin, timeout_seconds, *, local_test=False
):
    """Retain earlier negative controls while accepting stronger procfs denial."""
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
# Also exercise the exact class-recovery decoder attack without adding another
# expensive supervised process launch. Either mutation must make test_truth fail.
target = None
for candidate in object.__subclasses__():
    if getattr(candidate, '__name__', None) == '_GraphDecoder':
        target = candidate
        break
if target is not None:
    original_decode = target.decode
    def replacement(self, value):
        observed = original_decode(self, value)
        if observed == 'probe':
            return 'forged'
        return observed
    target.decode = replacement
def probe(): return 'wrong'
def forged(): return 'real'
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
    for _ in range(2):
        try:
            fd = os.open('/proc/%d/fd/1' % parent, os.O_WRONLY)
        except OSError:
            try:
                status = Path('/proc/%d/status' % parent).read_text()
            except OSError:
                # Actor procfs can be intentionally absent. That is a stronger
                # denial than an unreadable parent descriptor.
                return 'wrong'
            parent = int(next(line.split()[1] for line in status.splitlines()
                              if line.startswith('PPid:')))
            continue
        else:
            os.close(fd)
            return 'reopened'
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
    for name, candidate_source in (
        ("dispatch", dispatch),
        ("descriptors", descriptors),
        ("reopening", reopening),
        ("mutation", mutation),
    ):
        with tempfile.TemporaryDirectory(
            prefix="blue-forge-boundary-selftest-"
        ) as temp:
            root = Path(temp)
            root.chmod(0o755)
            (root / "tests").mkdir()
            (root / "blue_forge").mkdir()
            (root / "blue_forge/__init__.py").write_text(
                candidate_source, encoding="utf-8"
            )
            (root / "tests/test_boundary.py").write_text(
                "import unittest\nimport blue_forge\n"
                "class Boundary(unittest.TestCase):\n"
                " def test_truth(self): self.assertEqual(blue_forge.probe(), 'wrong')\n"
                " def test_forgery(self): self.assertEqual(blue_forge.probe(), 'real')\n",
                encoding="utf-8",
            )
            if name != "mutation":
                base.run_one(
                    root,
                    python_bin,
                    ("test_boundary", "Boundary", "test_truth"),
                    timeout_seconds,
                    local_test=local_test,
                )
            try:
                base.run_one(
                    root,
                    python_bin,
                    ("test_boundary", "Boundary", "test_forgery"),
                    timeout_seconds,
                    local_test=local_test,
                )
            except base.SupervisionFailure as exc:
                if name == "mutation":
                    base.require(
                        "mutated its invocation namespace" in str(exc),
                        "namespace mutation failed for an unrelated reason",
                    )
            else:
                raise base.SupervisionFailure(
                    "executor boundary self-test accepted " + name
                )
    print(
        "executor_dispatch_isolation=PASS "
        "executor_descriptor_isolation=PASS"
    )


# The earlier combined self-test resolves this symbol dynamically.
previous._self_test_dispatch_and_descriptors = (
    _corrected_dispatch_and_descriptors
)


def _suite_cases(suite, module_name):
    """Return validated runtime-selected TestCase instances without rebuilding them."""
    cases = []

    def visit(item):
        if isinstance(item, base.unittest.TestSuite):
            for child in item:
                visit(child)
            return
        base.require(
            isinstance(item, base.unittest.TestCase),
            "runtime discovery returned a non-TestCase object",
        )
        cls = type(item)
        method = getattr(item, "_testMethodName", None)
        base.require(
            type(method) is str and method.startswith("test"),
            "runtime discovery returned an invalid test method",
        )
        base.require(
            cls.__module__ == module_name,
            "runtime discovery escaped the selected frozen module",
        )
        cases.append(item)

    visit(suite)
    identities = [
        (module_name, type(item).__name__, item._testMethodName)
        for item in cases
    ]
    base.require(
        identities and len(identities) == len(set(identities)),
        "empty or duplicate runtime frozen test floor",
    )
    return cases


def _require_reconstructible_case(item):
    """Fail closed if load_tests mutates per-instance state after construction."""
    cls = type(item)
    method = getattr(item, "_testMethodName", None)
    try:
        fresh = cls(method)
        selected_state = object.__getattribute__(item, "__dict__")
        fresh_state = object.__getattribute__(fresh, "__dict__")
        same_state = selected_state == fresh_state
    except BaseException as exc:
        raise base.SupervisionFailure(
            "runtime discovery returned a non-reconstructible TestCase instance"
        ) from exc
    base.require(
        same_state,
        "runtime discovery returned configured TestCase instance state; "
        "per-instance load_tests mutation is unsupported",
    )


def _flatten_suite(suite, module_name):
    cases = _suite_cases(suite, module_name)
    identities = []
    for item in cases:
        _require_reconstructible_case(item)
        identities.append(
            (module_name, type(item).__name__, item._testMethodName)
        )
    return identities


@contextlib.contextmanager
def _trusted_test_facades(importer):
    """Expose worker facades through sys.modules as well as injected __import__."""
    facades = getattr(importer, "_blue_forge_facades", None)
    base.require(
        type(facades) is dict and type(facades.get("subprocess")) is types.ModuleType,
        "trusted test importer omitted subprocess facade",
    )
    sentinel = object()
    prior = sys.modules.get("subprocess", sentinel)
    sys.modules["subprocess"] = facades["subprocess"]
    try:
        yield
    finally:
        if prior is sentinel:
            sys.modules.pop("subprocess", None)
        else:
            sys.modules["subprocess"] = prior


def _enumerate_module_worker(root, module_name):
    """Execute trusted test-module setup while proposed imports remain actor-proxied."""
    global_base = base
    bridge = global_base._Bridge(root, local_test=False)
    global_base._ACTIVE_BRIDGE = bridge
    finder = global_base._ProxyLoader(bridge)
    sys.meta_path.insert(0, finder)
    test_path = str(root / "tests")
    sys.path.insert(0, test_path)
    try:
        path = root / "tests" / (module_name + ".py")
        global_base.require(
            path.is_file() and not path.is_symlink(),
            "invalid runtime-enumeration test module",
        )
        source_text = path.read_text(encoding="utf-8")
        tree = global_base._TestTransform().visit(
            ast.parse(source_text, filename=str(path))
        )
        ast.fix_missing_locations(tree)
        module = types.ModuleType(module_name)
        module.__file__ = str(path)
        importer = _hardened_test_importer(bridge)
        module.__dict__["__builtins__"] = {
            **vars(builtins),
            "__import__": importer,
        }
        module.__dict__["_remote_object_setattr"] = (
            global_base._remote_object_setattr
        )
        sys.modules[module_name] = module
        with _trusted_test_facades(importer):
            exec(
                compile(tree, str(path), "exec", dont_inherit=True),
                module.__dict__,
            )
            suite = global_base.unittest.defaultTestLoader.loadTestsFromModule(
                module
            )
            return _flatten_suite(suite, module_name)
    finally:
        bridge.close()
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        try:
            sys.path.remove(test_path)
        except ValueError:
            pass
        sys.modules.pop(module_name, None)
        global_base._ACTIVE_BRIDGE = None


def _enumeration_child(root, module_name):
    raw_secret = sys.stdin.buffer.read(64)
    sys.stdin.close()
    try:
        secret = bytes.fromhex(raw_secret.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise base.SupervisionFailure(
            "invalid trusted enumeration key"
        ) from exc
    base.require(
        len(secret) == 32, "missing trusted enumeration key"
    )
    identities = _enumerate_module_worker(root.resolve(), module_name)
    payload = base._wire_dump(
        [list(identity) for identity in identities]
    )
    mac = hmac.new(
        secret, b"ENUM:" + payload, hashlib.sha256
    ).hexdigest()
    print(
        "trusted_enumeration="
        + mac
        + ":"
        + base64.b64encode(payload).decode("ascii")
    )


def _enumerate_module_parent(root, module_name):
    secret = base.secrets.token_bytes(32)
    command = [
        sys.executable,
        "-I",
        str(Path(__file__).resolve()),
        "--enumerate-root",
        str(root),
        "--enumerate-module",
        module_name,
    ]
    rc, diagnostic, timed_out = base._run_process_bounded(
        command,
        cwd=root,
        env=dict(os.environ),
        timeout_seconds=30,
        input_bytes=secret.hex().encode("ascii"),
    )
    base.require(
        not timed_out and rc == 0,
        f"trusted runtime enumeration failed for {module_name}: "
        f"rc={rc}\n{diagnostic}",
    )
    lines = diagnostic.splitlines()
    prefix = "trusted_enumeration="
    base.require(
        lines and lines[-1].startswith(prefix),
        "missing authenticated runtime enumeration",
    )
    record = lines[-1][len(prefix):]
    try:
        mac, encoded = record.split(":", 1)
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise base.SupervisionFailure(
            "malformed authenticated runtime enumeration"
        ) from exc
    expected = hmac.new(
        secret, b"ENUM:" + payload, hashlib.sha256
    ).hexdigest()
    base.require(
        hmac.compare_digest(mac, expected),
        "runtime enumeration authentication failed",
    )
    value = base._wire_load(payload)
    base.require(
        type(value) is list, "runtime enumeration is not a list"
    )
    identities = []
    for item in value:
        base.require(
            type(item) is list
            and len(item) == 3
            and all(type(part) is str for part in item),
            "runtime enumeration contains an invalid identity",
        )
        identity = tuple(item)
        base.require(
            identity[0] == module_name
            and identity[2].startswith("test"),
            "runtime enumeration identity escaped its module",
        )
        identities.append(identity)
    base.require(
        identities and len(identities) == len(set(identities)),
        "empty or duplicate runtime module enumeration",
    )
    return identities


def _runtime_expected_tests(root):
    tests = []
    supervised_current = bool(
        os.environ.get("BLUE_FORGE_SUPERVISED_MARKER")
    )
    paths = sorted((root / "tests").glob("test*.py"))
    base.require(paths, "empty frozen test floor")
    for path in paths:
        base.require(
            path.is_file() and not path.is_symlink(),
            "invalid frozen test file",
        )
        tree = ast.parse(
            path.read_text(encoding="utf-8"), filename=str(path)
        )
        if (
            previous._current_suite_only(tree, path)
            and not supervised_current
        ):
            continue
        tests.extend(_enumerate_module_parent(root, path.stem))
    base.require(
        tests and len(tests) == len(set(tests)),
        "empty or duplicate runtime frozen test floor",
    )
    return tests


def _runtime_membership_self_test():
    with tempfile.TemporaryDirectory(
        prefix="blue-forge-runtime-enumeration-"
    ) as temp:
        root = Path(temp)
        root.chmod(0o755)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge/__init__.py").write_text(
            "def probe(): return 'real'\n", encoding="utf-8"
        )
        (root / "tests/test_dynamic.py").write_text(
            "import unittest\n"
            "from blue_forge import probe\n"
            "class Dynamic(unittest.TestCase): pass\n"
            "def generated(self): self.assertEqual(probe(), 'real')\n"
            "def install(): setattr(Dynamic, 'test_generated', generated)\n"
            "install()\n"
            "setattr(Dynamic, 'test_direct', generated)\n"
            "class Control(unittest.TestCase):\n"
            " def test_control(self): pass\n",
            encoding="utf-8",
        )
        identities = set(_runtime_expected_tests(root))
        expected = {
            ("test_dynamic", "Dynamic", "test_generated"),
            ("test_dynamic", "Dynamic", "test_direct"),
            ("test_dynamic", "Control", "test_control"),
        }
        base.require(
            identities == expected,
            "runtime discovery omitted dynamically installed tests",
        )

    class Configured(base.unittest.TestCase):
        def test_state(self):
            pass

    selected = Configured("test_state")
    selected.expected = "configured"
    try:
        _require_reconstructible_case(selected)
    except base.SupervisionFailure as exc:
        base.require(
            "configured TestCase instance state" in str(exc),
            "configured TestCase state failed closed for an unrelated reason",
        )
    else:
        raise base.SupervisionFailure(
            "runtime discovery accepted configured TestCase instance state"
        )


def _looks_like_proposed_path(value, root):
    if type(value) is not str:
        return False
    try:
        path = Path(value)
        resolved = (
            path.resolve()
            if path.is_absolute()
            else (Path.cwd() / path).resolve()
        )
        return resolved.is_relative_to(
            (Path(root) / "blue_forge").resolve()
        )
    except (OSError, RuntimeError, ValueError):
        return False


def _hardened_test_importer(bridge):
    """Bridge every proposed CLI launch; explicitly mediate all process APIs."""
    real_import = base.builtins.__import__
    json_proxy = types.ModuleType("json")
    json_proxy.__dict__.update(vars(base.json))
    json_proxy.dumps = lambda value, *a, **k: base.json.dumps(
        base._local(value), *a, **k
    )
    dc_proxy = types.ModuleType("dataclasses")
    dc_proxy.__dict__.update(vars(base.dataclasses))
    dc_proxy.replace = base._remote_replace

    process_proxy = types.ModuleType("subprocess")
    for name in (
        "PIPE",
        "STDOUT",
        "DEVNULL",
        "CompletedProcess",
        "CalledProcessError",
        "TimeoutExpired",
        "SubprocessError",
    ):
        setattr(process_proxy, name, getattr(subprocess, name))

    safe_flags = {"-I", "-E", "-s", "-S", "-B", "-P", "-u"}
    safe_xoptions = {"utf8", "utf8=1", "utf8=0"}
    shell_programs = {"sh", "bash", "dash", "zsh", "ksh", "mksh"}
    timeout_programs = {"timeout", "gtimeout"}

    def exact_sequence(command):
        if type(command) not in (list, tuple):
            return None
        items = list(command)
        base.require(
            all(type(item) is str for item in items),
            "subprocess command entries must be exact strings",
        )
        return items

    def unwrap_env(items):
        """Unwrap the supported GNU env COMMAND form without executing env."""
        if not items or Path(items[0]).name != "env":
            return items, {}
        index = 1
        if index < len(items) and items[index] == "--":
            index += 1
        overrides = {}
        while index < len(items):
            token = items[index]
            if token.startswith("-"):
                return None, {}
            if "=" not in token:
                break
            key, value = token.split("=", 1)
            base.require(
                bool(key), "invalid env assignment before proposed CLI"
            )
            overrides[key] = value
            index += 1
        if index >= len(items):
            return None, {}
        return items[index:], overrides

    def cli_details(command):
        items = exact_sequence(command)
        if not items:
            return None
        inner, env_overrides = unwrap_env(items)
        if not inner:
            return None
        try:
            same_python = (
                Path(inner[0]).resolve()
                == Path(sys.executable).resolve()
            )
        except (OSError, RuntimeError):
            same_python = False
        if not same_python:
            return None
        index = 1
        while index < len(inner) and inner[index] != "-m":
            token = inner[index]
            if token in safe_flags:
                index += 1
                continue
            if token == "-X":
                base.require(
                    index + 1 < len(inner)
                    and inner[index + 1] in safe_xoptions,
                    "unsupported Python -X option for proposed CLI",
                )
                index += 2
                continue
            return None
        if index >= len(inner):
            return None
        if index + 1 >= len(inner) or inner[index + 1] != "blue_forge":
            return None
        cli = inner[index + 2 :]
        base.require(
            len(cli) == 2 and cli[0] in {"verify", "regression"},
            "unsupported proposed CLI invocation",
        )
        return cli[0], Path(cli[1]), env_overrides

    def shell_wrapped_arguments(items):
        """Return command-interpreter arguments, including env/busybox wrappers."""
        if not items:
            return ()
        start = 0
        program = Path(items[start]).name
        if program == "env":
            found = None
            for index, token in enumerate(items[1:], 1):
                if Path(token).name in shell_programs or Path(token).name == "busybox":
                    found = index
                    break
            if found is None:
                return ()
            start = found
            program = Path(items[start]).name
        if program == "busybox":
            if start + 1 >= len(items):
                return ()
            candidate = Path(items[start + 1]).name
            if candidate not in shell_programs:
                return ()
            start += 1
            program = candidate
        if program not in shell_programs:
            return ()
        return tuple(items[start + 1 :])

    def reject_direct_proposed(command, *, shell=False):
        base.require(
            shell is not True,
            "shell subprocess execution is unsupported in trusted workers",
        )
        if type(command) is str:
            base.require(
                "blue_forge" not in command,
                "direct proposed application execution is not allowed",
            )
            return
        items = exact_sequence(command)
        if items is None:
            return
        if items and Path(items[0]).name == "env":
            inner, _overrides = unwrap_env(items)
            candidate = items[1:] if inner is None else inner
            base.require(
                not any(
                    "blue_forge" in item
                    or _looks_like_proposed_path(item, bridge.root)
                    for item in candidate
                ),
                "unsupported env-wrapped proposed application execution",
            )
        if items and Path(items[0]).name in timeout_programs:
            base.require(
                not any(
                    "blue_forge" in item
                    or _looks_like_proposed_path(item, bridge.root)
                    for item in items[1:]
                ),
                "timeout-wrapped proposed application execution is not allowed",
            )
        wrapped = shell_wrapped_arguments(items)
        if wrapped:
            base.require(
                not any(
                    "blue_forge" in item
                    or _looks_like_proposed_path(item, bridge.root)
                    for item in wrapped
                ),
                "shell-wrapped proposed application execution is not allowed",
            )
        try:
            same_python = bool(items) and (
                Path(items[0]).resolve()
                == Path(sys.executable).resolve()
            )
        except (OSError, RuntimeError):
            same_python = False
        if same_python and "-c" in items:
            index = items.index("-c")
            if index + 1 < len(items):
                base.require(
                    "blue_forge" not in items[index + 1],
                    "direct proposed Python execution is not allowed",
                )
        base.require(
            not any(
                _looks_like_proposed_path(item, bridge.root)
                for item in items
            ),
            "direct proposed source execution is not allowed",
        )
        if same_python and "-m" in items:
            index = items.index("-m")
            if index + 1 < len(items):
                base.require(
                    items[index + 1] != "blue_forge",
                    "proposed CLI must use the actor bridge",
                )

    def relay_inherited(fd, payload):
        base.require(type(payload) is bytes, "invalid actor CLI output")
        view = memoryview(payload)
        while view:
            try:
                written = os.write(fd, view)
            except OSError as exc:
                raise base.SupervisionFailure(
                    "failed to relay proposed CLI output"
                ) from exc
            base.require(written > 0, "failed to relay proposed CLI output")
            view = view[written:]

    def bridged_run(command, kwargs, details):
        subcommand, path, env_overrides = details
        allowed = {
            "env",
            "check",
            "text",
            "universal_newlines",
            "encoding",
            "errors",
            "stdout",
            "stderr",
            "capture_output",
            "timeout",
            "cwd",
        }
        unknown = set(kwargs) - allowed
        base.require(
            not unknown,
            "unsupported proposed CLI option: "
            + ",".join(sorted(unknown)),
        )
        cwd = kwargs.get("cwd")
        if cwd is not None:
            base.require(
                Path(cwd).resolve() == Path(bridge.root).resolve(),
                "proposed CLI cwd must remain the sterile root",
            )
        timeout = kwargs.get("timeout")
        if timeout is not None:
            base.require(
                type(timeout) in (int, float)
                and not isinstance(timeout, bool)
                and 0 < timeout <= 15,
                "proposed CLI timeout exceeds actor budget",
            )
        actor_timeout = timeout if timeout is not None else 10.0
        capture_output = kwargs.get("capture_output", False)
        base.require(
            type(capture_output) is bool,
            "capture_output must be boolean",
        )
        stdout_mode = kwargs.get("stdout")
        stderr_mode = kwargs.get("stderr")
        if capture_output:
            base.require(
                stdout_mode is None and stderr_mode is None,
                "capture_output conflicts with stdout/stderr",
            )
            stdout_mode = subprocess.PIPE
            stderr_mode = subprocess.PIPE
        base.require(
            stdout_mode
            in (None, subprocess.PIPE, subprocess.DEVNULL),
            "unsupported stdout target for proposed CLI",
        )
        base.require(
            stderr_mode
            in (
                None,
                subprocess.PIPE,
                subprocess.DEVNULL,
                subprocess.STDOUT,
            ),
            "unsupported stderr target for proposed CLI",
        )
        env_value = kwargs.get("env")
        if env_value is None:
            environment = dict(os.environ)
        else:
            base.require(
                type(env_value) is dict
                and all(
                    type(key) is str and type(value) is str
                    for key, value in env_value.items()
                ),
                "proposed CLI environment must be an exact string mapping",
            )
            environment = dict(env_value)
        environment.update(env_overrides)
        environment = {
            key: value
            for key, value in environment.items()
            if not key.startswith("BLUE_FORGE_")
        }
        base.require(
            path.is_file() and not path.is_symlink(),
            "proposed CLI case path is not a regular file",
        )
        with path.open("rb") as handle:
            payload = handle.read(2 * 1024 * 1024 + 1)
        base.require(
            len(payload) <= 2 * 1024 * 1024,
            "proposed CLI case transport budget exceeded",
        )
        merge_stderr = stderr_mode == subprocess.STDOUT
        rc, stdout, stderr, timed_out = bridge.request(
            "cli", [subcommand], payload, environment, merge_stderr, actor_timeout
        )
        base.require(
            type(stdout) is bytes and type(stderr) is bytes,
            "invalid actor CLI output",
        )
        base.require(type(timed_out) is bool, "invalid actor CLI timeout observation")
        if stdout_mode is None and stdout:
            relay_inherited(1, stdout)
        if stderr_mode is None and stderr:
            relay_inherited(2, stderr)
        if timed_out:
            if timeout is None:
                raise base.SupervisionFailure(
                    "proposed CLI exceeded actor execution budget"
                )
            output = stdout if stdout_mode == subprocess.PIPE else None
            error_output = stderr if stderr_mode == subprocess.PIPE else None
            raise subprocess.TimeoutExpired(
                command, timeout, output=output, stderr=error_output
            )
        text_mode = bool(
            kwargs.get("text")
            or kwargs.get("universal_newlines")
            or kwargs.get("encoding") is not None
            or kwargs.get("errors") is not None
        )
        if text_mode:
            encoding = kwargs.get("encoding") or "utf-8"
            errors = kwargs.get("errors") or "strict"
            base.require(
                type(encoding) is str and type(errors) is str,
                "invalid proposed CLI text decoding options",
            )
            stdout = stdout.decode(encoding, errors)
            stderr = stderr.decode(encoding, errors)
        returned_stdout = (
            stdout if stdout_mode == subprocess.PIPE else None
        )
        returned_stderr = (
            stderr if stderr_mode == subprocess.PIPE else None
        )
        completed = subprocess.CompletedProcess(
            command, rc, returned_stdout, returned_stderr
        )
        if kwargs.get("check"):
            completed.check_returncode()
        return completed

    def run(command, *args, **kwargs):
        details = cli_details(command)
        if details is not None:
            base.require(
                not args,
                "positional subprocess.run options are unsupported "
                "for proposed CLI",
            )
            return bridged_run(command, dict(kwargs), details)
        reject_direct_proposed(
            command, shell=kwargs.get("shell", False)
        )
        return subprocess.run(command, *args, **kwargs)

    def check_output(command, *args, **kwargs):
        details = cli_details(command)
        if details is None:
            reject_direct_proposed(
                command, shell=kwargs.get("shell", False)
            )
            return subprocess.check_output(
                command, *args, **kwargs
            )
        base.require(
            "stdout" not in kwargs,
            "stdout argument not allowed for check_output",
        )
        options = dict(kwargs)
        options["stdout"] = subprocess.PIPE
        options["check"] = True
        return run(command, *args, **options).stdout

    def check_call(command, *args, **kwargs):
        details = cli_details(command)
        if details is None:
            reject_direct_proposed(
                command, shell=kwargs.get("shell", False)
            )
            return subprocess.check_call(
                command, *args, **kwargs
            )
        options = dict(kwargs)
        options["check"] = True
        return run(command, *args, **options).returncode

    def call(command, *args, **kwargs):
        details = cli_details(command)
        if details is None:
            reject_direct_proposed(
                command, shell=kwargs.get("shell", False)
            )
            return subprocess.call(command, *args, **kwargs)
        options = dict(kwargs)
        options.pop("check", None)
        return run(command, *args, **options).returncode

    def popen(command, *args, **kwargs):
        details = cli_details(command)
        base.require(
            details is None,
            "streaming proposed CLI subprocesses are unsupported; "
            "use run/check_output/check_call",
        )
        reject_direct_proposed(
            command, shell=kwargs.get("shell", False)
        )
        return subprocess.Popen(command, *args, **kwargs)

    def blocked_shell(*args, **kwargs):
        del args, kwargs
        raise base.SupervisionFailure(
            "shell subprocess helpers are unavailable in trusted workers"
        )

    process_proxy.run = run
    process_proxy.check_output = check_output
    process_proxy.check_call = check_call
    process_proxy.call = call
    process_proxy.Popen = popen
    process_proxy.getoutput = blocked_shell
    process_proxy.getstatusoutput = blocked_shell
    facades = {
        "json": json_proxy,
        "dataclasses": dc_proxy,
        "subprocess": process_proxy,
    }

    def trusted_import(
        name, globals=None, locals=None, fromlist=(), level=0
    ):
        if level == 0 and name in facades:
            return facades[name]
        return real_import(name, globals, locals, fromlist, level)

    trusted_import._blue_forge_facades = facades
    return trusted_import


def _runtime_worker_run(root, identity, *, local_test=False):
    """Run the actual suite-selected instance under facade-complete mediation."""
    global_base = base
    module_name, class_name, method_name = identity
    bridge = global_base._Bridge(root, local_test=local_test)
    global_base._ACTIVE_BRIDGE = bridge
    finder = global_base._ProxyLoader(bridge)
    sys.meta_path.insert(0, finder)
    test_path = str(root / "tests")
    sys.path.insert(0, test_path)
    try:
        path = root / "tests" / (module_name + ".py")
        global_base.require(
            path.is_file() and not path.is_symlink(),
            "invalid runtime worker test module",
        )
        source_text = path.read_text(encoding="utf-8")
        tree = global_base._TestTransform().visit(
            ast.parse(source_text, filename=str(path))
        )
        ast.fix_missing_locations(tree)
        module = types.ModuleType(module_name)
        module.__file__ = str(path)
        importer = _hardened_test_importer(bridge)
        module.__dict__["__builtins__"] = {
            **vars(builtins),
            "__import__": importer,
        }
        module.__dict__["_remote_object_setattr"] = (
            global_base._remote_object_setattr
        )
        sys.modules[module_name] = module
        with _trusted_test_facades(importer):
            exec(
                compile(tree, str(path), "exec", dont_inherit=True),
                module.__dict__,
            )
            suite = global_base.unittest.defaultTestLoader.loadTestsFromModule(
                module
            )
            cases = _suite_cases(suite, module_name)
            matches = [
                item
                for item in cases
                if (
                    type(item).__name__ == class_name
                    and item._testMethodName == method_name
                )
            ]
            global_base.require(
                len(matches) == 1,
                "runtime worker could not select the authenticated frozen test",
            )
            selected = matches[0]
            _require_reconstructible_case(selected)
            result = global_base.unittest.TestResult()
            global_base.unittest.TestSuite([selected]).run(result)
        global_base.require(
            bridge.fatal is None,
            f"RPC failure was caught by a test: {bridge.fatal}",
        )
        global_base.require(
            result.testsRun == 1
            and not (
                result.failures
                or result.errors
                or result.skipped
                or result.expectedFailures
                or result.unexpectedSuccesses
            ),
            "frozen test failed: "
            + ".".join(identity)
            + "\n"
            + "\n".join(
                item[1] for item in result.failures + result.errors
            ),
        )
    finally:
        bridge.close()
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        try:
            sys.path.remove(test_path)
        except ValueError:
            pass
        sys.modules.pop(module_name, None)
        global_base._ACTIVE_BRIDGE = None


def _subprocess_policy_self_test():
    class FakeBridge:
        def __init__(self, root):
            self.root = root

        def request(self, action, *arguments):
            base.require(
                action == "cli",
                "subprocess self-test escaped CLI bridge",
            )
            base.require(
                arguments[0] == ["verify"],
                "subprocess self-test lost CLI action",
            )
            base.require(
                len(arguments) == 5
                and type(arguments[3]) is bool
                and type(arguments[4]) in (int, float),
                "subprocess self-test lost stderr merge or timeout mode",
            )
            if arguments[4] == 0.125:
                return -9, b"partial", b"", True
            if arguments[3]:
                return 0, b"merged", b"", False
            return 0, b"bridged", b"diagnostic", False

    with tempfile.TemporaryDirectory(
        prefix="blue-forge-subprocess-policy-"
    ) as temp:
        root = Path(temp)
        case = root / "case.json"
        case.write_bytes(b"{}")
        importer = _hardened_test_importer(FakeBridge(root))
        proxy = importer("subprocess")
        command = [
            sys.executable,
            "-I",
            "-X",
            "utf8",
            "-m",
            "blue_forge",
            "verify",
            str(case),
        ]
        completed = proxy.run(
            command, capture_output=True, check=True
        )
        base.require(
            completed.stdout == b"bridged"
            and completed.stderr == b"diagnostic",
            "bridged subprocess.run lost captured output",
        )
        env_command = ["env", *command]
        base.require(
            proxy.check_output(env_command) == b"bridged",
            "env-wrapped proposed CLI bypassed actor routing",
        )
        assigned_env_command = ["env", "SELFTEST_FLAG=1", *command]
        base.require(
            proxy.check_output(assigned_env_command) == b"bridged",
            "env assignment wrapper bypassed actor routing",
        )
        merged = proxy.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
        base.require(
            merged.stdout == b"merged" and merged.stderr is None,
            "bridged subprocess.run did not preserve actor-side stderr merge",
        )
        read_fd, write_fd = os.pipe()
        saved_stdout = os.dup(1)
        inherited = None
        try:
            os.dup2(write_fd, 1)
            os.close(write_fd)
            inherited = proxy.run(
                command, stderr=subprocess.DEVNULL, check=True
            )
        finally:
            os.dup2(saved_stdout, 1)
            os.close(saved_stdout)
        inherited_bytes = os.read(read_fd, 8192)
        os.close(read_fd)
        base.require(
            inherited is not None
            and inherited.stdout is None
            and inherited_bytes == b"bridged",
            "bridged subprocess.run discarded inherited stdout",
        )
        try:
            proxy.run(command, capture_output=True, timeout=0.125)
        except subprocess.TimeoutExpired as exc:
            base.require(
                exc.timeout == 0.125 and exc.output == b"partial",
                "bridged subprocess.run lost the requested timeout observation",
            )
        else:
            raise base.SupervisionFailure(
                "bridged subprocess.run ignored the requested timeout"
            )
        base.require(
            proxy.check_output(command) == b"bridged",
            "bridged subprocess.check_output failed",
        )
        base.require(
            proxy.check_call(command) == 0
            and proxy.call(command) == 0,
            "bridged subprocess call helpers failed",
        )

        with _trusted_test_facades(importer):
            imported = importlib.import_module("subprocess")
            indexed = sys.modules["subprocess"]
            base.require(
                imported is proxy and indexed is proxy,
                "alternative subprocess import escaped trusted facade",
            )
            base.require(
                imported.check_output(command) == b"bridged"
                and indexed.call(command) == 0,
                "alternative subprocess import bypassed actor routing",
            )
        base.require(
            sys.modules.get("subprocess") is subprocess,
            "subprocess facade leaked outside trusted test scope",
        )

        shell_wrapped = [
            "/bin/sh",
            "-c",
            f"{sys.executable} -m blue_forge verify {case}",
        ]
        unsupported_env = [
            "env", "-i", sys.executable, "-m", "blue_forge", "verify", str(case)
        ]
        timeout_wrapped = ["timeout", "5", *command]
        for operation in (
            lambda: proxy.Popen(command),
            lambda: proxy.run(
                [sys.executable, "-c", "import blue_forge"]
            ),
            lambda: proxy.run(shell_wrapped),
            lambda: proxy.run(unsupported_env),
            lambda: proxy.run(timeout_wrapped),
        ):
            try:
                operation()
            except base.SupervisionFailure:
                pass
            else:
                raise base.SupervisionFailure(
                    "direct proposed subprocess escaped actor routing"
                )
        completed = proxy.run(
            ["/bin/sh", "-c", "exit 0"], check=True
        )
        base.require(
            completed.returncode == 0,
            "ordinary bounded subprocess support was lost",
        )
        child = proxy.Popen(
            [sys.executable, "-c", "pass"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base.require(
            child.wait(timeout=5) == 0,
            "ordinary bounded Popen support was lost",
        )


# The first-stage P1 chain resolves both helpers dynamically.
previous._self_test_dynamic_membership = _runtime_membership_self_test
previous._self_test_subprocess_facade = _subprocess_policy_self_test

base.expected_tests = _runtime_expected_tests
base._test_importer = _hardened_test_importer
base._worker_run = _runtime_worker_run


if "--actor-root" in sys.argv:
    # Retain the first-stage inert main-module boundary.
    sys.modules["__main__"] = types.ModuleType("__main__")


def _main():
    if "--enumerate-root" in sys.argv:
        try:
            root_index = sys.argv.index("--enumerate-root")
            module_index = sys.argv.index("--enumerate-module")
            root = Path(sys.argv[root_index + 1])
            module_name = sys.argv[module_index + 1]
            base.require(
                type(module_name) is str
                and module_name.startswith("test")
                and "/" not in module_name
                and "\\" not in module_name,
                "invalid runtime enumeration module",
            )
            _enumeration_child(root, module_name)
            return 0
        except BaseException as exc:
            print(
                f"frozen_test_supervisor=FAIL reason={str(exc)!r}",
                file=sys.stderr,
            )
            return 1
    return base.main()


if __name__ == "__main__":
    raise SystemExit(_main())