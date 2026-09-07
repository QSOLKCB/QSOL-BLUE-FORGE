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
import hashlib
import hmac
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
    for name, source in (
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
                source, encoding="utf-8"
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


def _flatten_suite(suite, module_name):
    identities = []

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
        identities.append((module_name, cls.__name__, method))

    visit(suite)
    base.require(
        identities and len(identities) == len(set(identities)),
        "empty or duplicate runtime frozen test floor",
    )
    return identities


def _enumerate_module_worker(root, module_name):
    """Execute trusted test-module setup while proposed imports remain actor-proxied."""
    global_base = base
    bridge = global_base._Bridge(root, local_test=False)
    global_base._ACTIVE_BRIDGE = bridge
    finder = global_base._ProxyLoader(bridge)
    sys.meta_path.insert(0, finder)
    sys.path.insert(0, str(root / "tests"))
    try:
        path = root / "tests" / (module_name + ".py")
        global_base.require(
            path.is_file() and not path.is_symlink(),
            "invalid runtime-enumeration test module",
        )
        source = path.read_text(encoding="utf-8")
        tree = global_base._TestTransform().visit(
            ast.parse(source, filename=str(path))
        )
        ast.fix_missing_locations(tree)
        module = types.ModuleType(module_name)
        module.__file__ = str(path)
        module.__dict__["__builtins__"] = {
            **vars(builtins),
            "__import__": global_base._test_importer(bridge),
        }
        module.__dict__["_remote_object_setattr"] = (
            global_base._remote_object_setattr
        )
        sys.modules[module_name] = module
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

    def exact_sequence(command):
        if type(command) not in (list, tuple):
            return None
        items = list(command)
        base.require(
            all(type(item) is str for item in items),
            "subprocess command entries must be exact strings",
        )
        return items

    def cli_details(command):
        items = exact_sequence(command)
        if not items:
            return None
        try:
            same_python = (
                Path(items[0]).resolve()
                == Path(sys.executable).resolve()
            )
        except (OSError, RuntimeError):
            same_python = False
        if not same_python:
            return None
        index = 1
        while index < len(items) and items[index] != "-m":
            token = items[index]
            if token in safe_flags:
                index += 1
                continue
            if token == "-X":
                base.require(
                    index + 1 < len(items)
                    and items[index + 1] in safe_xoptions,
                    "unsupported Python -X option for proposed CLI",
                )
                index += 2
                continue
            return None
        if index >= len(items):
            return None
        if index + 1 >= len(items) or items[index + 1] != "blue_forge":
            return None
        cli = items[index + 2 :]
        base.require(
            len(cli) == 2 and cli[0] in {"verify", "regression"},
            "unsupported proposed CLI invocation",
        )
        return cli[0], Path(cli[1])

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

    def bridged_run(command, kwargs, details):
        subcommand, path = details
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
        rc, stdout, stderr = bridge.request(
            "cli", [subcommand], payload, environment
        )
        if stderr_mode == subprocess.STDOUT:
            stdout = stdout + stderr
            stderr = b""
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

    return trusted_import


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
            return 0, b"bridged", b"diagnostic"

    with tempfile.TemporaryDirectory(
        prefix="blue-forge-subprocess-policy-"
    ) as temp:
        root = Path(temp)
        case = root / "case.json"
        case.write_bytes(b"{}")
        proxy = _hardened_test_importer(
            FakeBridge(root)
        )("subprocess")
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
        base.require(
            proxy.check_output(command) == b"bridged",
            "bridged subprocess.check_output failed",
        )
        base.require(
            proxy.check_call(command) == 0
            and proxy.call(command) == 0,
            "bridged subprocess call helpers failed",
        )
        for operation in (
            lambda: proxy.Popen(command),
            lambda: proxy.run(
                [sys.executable, "-c", "import blue_forge"]
            ),
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
