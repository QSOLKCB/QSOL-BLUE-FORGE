#!/usr/bin/env python3
"""Final trusted supervisor hardening for cached launches and remote observation.

The reviewed round-3 entrypoint is retained byte-for-byte in a sibling module.
This layer closes cached native-process references, requires proposed source to
be unreadable from the trusted frozen worker, executes runtime discovery and
frozen assertions in one authenticated worker, preserves validated Python CLI
flags across the actor bridge, makes Remote truth/str/repr and iteration observe
bounded actor-side behavior, and fails closed on direct-call output.
"""
from __future__ import annotations

import ast
import base64
import builtins
import contextlib
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path
import sys
import threading
import types


_ROUND3 = Path(__file__).with_name("_run_frozen_tests_supervised_round3.py")
_RETAINED_EXECUTOR = Path(__file__).with_name("run_proposed_executor.py")
_spec = importlib.util.spec_from_file_location(
    "_blue_forge_supervisor_round3_final", _ROUND3
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted third-stage supervisor is unavailable")
round3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(round3)
base = round3.base

# Every descendant must return through this final mediation layer.
base.__file__ = str(Path(__file__).resolve())

_legacy_importer = round3._hardened_test_importer
_legacy_subprocess_self_test = round3._subprocess_policy_self_test
_legacy_final_boundary_self_test = round3._final_boundary_self_test
_legacy_worker_run = base._worker_run
_legacy_run_one = base.run_one
_legacy_bridge_close = base._Bridge.close
_legacy_base_main = base.main

# These CPython audit events sit below Python module aliases. A cached reference
# such as pathlib.os.system therefore cannot escape merely because it points at
# the original os module rather than the facade installed in sys.modules.
_NATIVE_PROCESS_AUDIT_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.exec",
        "os.spawn",
    }
)
_PROCESS_AUDIT_STATE = threading.local()
_CLI_FLAG_STATE = threading.local()
_SAFE_PYTHON_FLAGS = frozenset({"-I", "-E", "-s", "-S", "-B", "-P", "-u"})
_SAFE_PYTHON_XOPTIONS = frozenset({"utf8", "utf8=1", "utf8=0"})


@contextlib.contextmanager
def _trusted_process_launch():
    prior = getattr(_PROCESS_AUDIT_STATE, "armed", False)
    _PROCESS_AUDIT_STATE.armed = True
    try:
        yield
    finally:
        _PROCESS_AUDIT_STATE.armed = prior


def _cached_process_audit_guard(event, args):
    del args
    if base._ACTIVE_BRIDGE is None:
        return
    if event not in _NATIVE_PROCESS_AUDIT_EVENTS:
        return
    if getattr(_PROCESS_AUDIT_STATE, "armed", False):
        return
    raise base.SupervisionFailure(
        "native process creation bypassed trusted process mediation"
    )


# Audit hooks are process-global and non-removable. The guard is deliberately
# inert before/after a live trusted bridge, so supervisor bootstrap and actor
# creation remain governed by the already-retained boundary.
sys.addaudithook(_cached_process_audit_guard)


def _python_cli_flags(command, kwargs, root: Path) -> tuple[str, ...]:
    """Return the validated interpreter flags from a proposed CLI invocation."""
    normalized, _changed = round3._normalize_python_command(command, kwargs, root)
    if type(normalized) not in (list, tuple):
        return ()
    items = list(normalized)
    if not items or not all(type(item) is str for item in items):
        return ()
    executable_index, _overrides = round3._env_command_index(items)
    if executable_index is None:
        return ()
    inner = items[executable_index:]
    if not inner:
        return ()
    try:
        if Path(inner[0]).resolve() != Path(sys.executable).resolve():
            return ()
    except (OSError, RuntimeError, ValueError):
        return ()
    flags: list[str] = []
    index = 1
    while index < len(inner) and inner[index] != "-m":
        token = inner[index]
        if token in _SAFE_PYTHON_FLAGS:
            flags.append(token)
            index += 1
            continue
        if token == "-X":
            if index + 1 >= len(inner) or inner[index + 1] not in _SAFE_PYTHON_XOPTIONS:
                return ()
            flags.extend((token, inner[index + 1]))
            index += 2
            continue
        return ()
    if (
        index + 1 >= len(inner)
        or inner[index] != "-m"
        or inner[index + 1] != "blue_forge"
    ):
        return ()
    return tuple(flags)


class _CliFlagBridge:
    """Add final-layer Python flags to the retained CLI request envelope."""

    __slots__ = ("_bridge", "root")

    def __init__(self, bridge):
        object.__setattr__(self, "_bridge", bridge)
        object.__setattr__(self, "root", bridge.root)

    def request(self, action, *arguments):
        bridge = object.__getattribute__(self, "_bridge")
        flags = getattr(_CLI_FLAG_STATE, "flags", ())
        if action == "cli" and flags:
            base.require(
                len(arguments) >= 1
                and type(arguments[0]) is list
                and len(arguments[0]) == 1
                and arguments[0][0] in {"verify", "regression"},
                "retained CLI bridge produced an invalid action envelope",
            )
            arguments = ([arguments[0][0], *flags], *arguments[1:])
        return bridge.request(action, *arguments)


def _arm_process_method(function, source_bridge, root):
    def mediated(command, *args, **kwargs):
        prior_flags = getattr(_CLI_FLAG_STATE, "flags", ())
        flags = ()
        if isinstance(source_bridge, base._Bridge):
            flags = _python_cli_flags(command, kwargs, root)
        _CLI_FLAG_STATE.flags = flags
        try:
            with _trusted_process_launch():
                return function(command, *args, **kwargs)
        finally:
            _CLI_FLAG_STATE.flags = prior_flags

    return mediated


def _hardened_test_importer(bridge):
    mediated_bridge = _CliFlagBridge(bridge) if isinstance(bridge, base._Bridge) else bridge
    importer = _legacy_importer(mediated_bridge)
    facades = importer._blue_forge_facades
    process_proxy = facades["subprocess"]
    for name in ("run", "check_output", "check_call", "call", "Popen"):
        setattr(
            process_proxy,
            name,
            _arm_process_method(getattr(process_proxy, name), bridge, Path(bridge.root)),
        )
    return importer


def _patched_executor_bootstrap(executor) -> str:
    """Patch only retained CLI command construction before proposed Python exists."""
    bootstrap = executor._SUBINTERPRETER_BOOTSTRAP
    capture = "_bf_modules = sys.modules\n"
    capture_replacement = capture + "_bf_sys_executable = sys.executable\n"
    base.require(
        bootstrap.count(capture) == 1,
        "retained executor bootstrap executable capture changed",
    )
    old = '                command = [sys.executable, "-m", "blue_forge", cli_args[0], _bf_str(path)]'
    new = '''                _bf_require(
                    _bf_type(cli_args) is _bf_list and _bf_len(cli_args) >= 1,
                    "invalid proposed CLI interpreter envelope",
                )
                _bf_cli_subcommand = cli_args[0]
                _bf_cli_flags = cli_args[1:]
                _bf_require(
                    _bf_type(_bf_cli_subcommand) is _bf_str
                    and _bf_cli_subcommand in ("verify", "regression"),
                    "invalid proposed CLI subcommand",
                )
                _bf_cli_index = 0
                while _bf_cli_index < _bf_len(_bf_cli_flags):
                    _bf_cli_token = _bf_cli_flags[_bf_cli_index]
                    _bf_require(_bf_type(_bf_cli_token) is _bf_str,
                                "invalid proposed CLI Python flag")
                    if _bf_cli_token in ("-I", "-E", "-s", "-S", "-B", "-P", "-u"):
                        _bf_cli_index += 1
                        continue
                    _bf_require(
                        _bf_cli_token == "-X"
                        and _bf_cli_index + 1 < _bf_len(_bf_cli_flags)
                        and _bf_cli_flags[_bf_cli_index + 1] in ("utf8", "utf8=1", "utf8=0"),
                        "unsupported proposed CLI Python flag",
                    )
                    _bf_cli_index += 2
                command = [_bf_sys_executable, *_bf_cli_flags, "-m", "blue_forge",
                           _bf_cli_subcommand, _bf_str(path)]'''
    base.require(
        bootstrap.count(old) == 1,
        "retained executor CLI construction changed",
    )
    return bootstrap.replace(capture, capture_replacement, 1).replace(old, new, 1)


def _executor_entry(root: Path) -> int:
    """Run the retained executor with the reviewed CLI-flag patch in memory."""
    spec = importlib.util.spec_from_file_location(
        "_blue_forge_retained_executor", _RETAINED_EXECUTOR
    )
    if spec is None or spec.loader is None:
        raise base.SupervisionFailure("retained proposed executor is unavailable")
    executor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(executor)
    executor._SUBINTERPRETER_BOOTSTRAP = _patched_executor_bootstrap(executor)
    prior_argv = sys.argv
    sys.argv = [str(_RETAINED_EXECUTOR), str(root)]
    try:
        return executor.main()
    except BaseException as exc:
        print(f"proposed_executor=FAIL reason={str(exc)!r}", file=sys.stderr)
        return 1
    finally:
        sys.argv = prior_argv


# The baseline-owned first-stage broker checks this path for root ownership and
# non-writability before spawning it. Re-enter this pinned final supervisor as
# the executor wrapper, so no new unpinned control file is introduced.
round3.round2.previous._EXECUTOR = Path(__file__).resolve()


# ---------------------------------------------------------------------------
# Proposed-source provenance
# ---------------------------------------------------------------------------
def _require_private_proposed_source(root: Path):
    source_root = root / "blue_forge"
    files = sorted(source_root.glob("*.py"))
    base.require(bool(files), "proposed source tree is empty")
    for path in files:
        base.require(
            path.is_file() and not path.is_symlink(),
            "invalid proposed source file",
        )
        base.require(
            not os.access(path, os.R_OK),
            "proposed source is readable from trusted worker",
        )


def _check_private_proposed_root(root: Path, *, local_test: bool) -> None:
    private_root = os.environ.get("BLUE_FORGE_PRIVATE_PROPOSED_SOURCE_ROOT")
    if local_test or type(private_root) is not str or not private_root:
        return
    try:
        is_private_root = root.resolve() == Path(private_root).resolve()
    except (OSError, RuntimeError):
        raise base.SupervisionFailure("invalid private proposed source root")
    if is_private_root:
        _require_private_proposed_source(root)


def _worker_run(root, identity, *, local_test=False):
    _check_private_proposed_root(Path(root), local_test=local_test)
    return _legacy_worker_run(root, identity, local_test=local_test)


# ---------------------------------------------------------------------------
# Direct proposed-call output
# ---------------------------------------------------------------------------
def _require_silent_actor(bridge):
    diagnostic_bytes = object.__getattribute__(bridge, "diagnostic_bytes")
    base.require(
        type(diagnostic_bytes) is int and diagnostic_bytes == 0,
        "proposed direct API emitted output during trusted supervision",
    )


def _trusted_transport_attack_selftest(bridge):
    root = object.__getattribute__(bridge, "root")
    try:
        name = Path(root).name
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    return name.startswith("blue-forge-boundary-selftest-")


def _bridge_close(self):
    result = _legacy_bridge_close(self)
    supervised_current = bool(os.environ.get("BLUE_FORGE_SUPERVISED_MARKER"))
    if not supervised_current and not _trusted_transport_attack_selftest(self):
        _require_silent_actor(self)
    return result


# ---------------------------------------------------------------------------
# Deterministic runtime discovery + execution
# ---------------------------------------------------------------------------
def _runtime_module_names(root: Path) -> list[str]:
    supervised_current = bool(os.environ.get("BLUE_FORGE_SUPERVISED_MARKER"))
    paths = sorted((root / "tests").glob("test*.py"))
    base.require(paths, "empty frozen test floor")
    modules: list[str] = []
    for path in paths:
        base.require(path.is_file() and not path.is_symlink(), "invalid frozen test file")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if round3.round2.previous._current_suite_only(tree, path) and not supervised_current:
            continue
        modules.append(path.stem)
    base.require(
        modules and len(modules) == len(set(modules)),
        "empty or duplicate runtime module floor",
    )
    return modules


def _serial_suite_worker(root: Path, modules: list[str]):
    _check_private_proposed_root(root, local_test=False)
    bridge = base._Bridge(root, local_test=False)
    base._ACTIVE_BRIDGE = bridge
    finder = base._ProxyLoader(bridge)
    sys.meta_path.insert(0, finder)
    test_path = str(root / "tests")
    sys.path.insert(0, test_path)
    loaded: list[str] = []
    try:
        importer = _hardened_test_importer(bridge)
        identities = []
        suites = []
        with round3._trusted_test_facades(importer):
            for module_name in modules:
                path = root / "tests" / (module_name + ".py")
                base.require(
                    path.is_file() and not path.is_symlink(),
                    "invalid serial-suite test module",
                )
                source_text = path.read_text(encoding="utf-8")
                tree = base._TestTransform().visit(ast.parse(source_text, filename=str(path)))
                ast.fix_missing_locations(tree)
                module = types.ModuleType(module_name)
                module.__file__ = str(path)
                module.__dict__["__builtins__"] = {
                    **vars(builtins),
                    "__import__": importer,
                }
                module.__dict__["_remote_object_setattr"] = base._remote_object_setattr
                sys.modules[module_name] = module
                loaded.append(module_name)
                exec(compile(tree, str(path), "exec", dont_inherit=True), module.__dict__)
                suite = base.unittest.defaultTestLoader.loadTestsFromModule(module)
                identities.extend(round3.round2._flatten_suite(suite, module_name))
                suites.append(suite)

            base.require(
                identities and len(identities) == len(set(identities)),
                "empty or duplicate serial runtime test floor",
            )
            result = base.unittest.TestResult()
            for suite in suites:
                suite.run(result)

        base.require(bridge.fatal is None, f"RPC failure was caught by a test: {bridge.fatal}")
        base.require(
            result.testsRun == len(identities)
            and not (
                result.failures
                or result.errors
                or result.skipped
                or result.expectedFailures
                or result.unexpectedSuccesses
            ),
            "frozen suite failed in authenticated discovery state\n"
            + "\n".join(item[1] for item in result.failures + result.errors),
        )
        return identities
    finally:
        try:
            bridge.close()
        finally:
            if finder in sys.meta_path:
                sys.meta_path.remove(finder)
            try:
                sys.path.remove(test_path)
            except ValueError:
                pass
            for module_name in loaded:
                sys.modules.pop(module_name, None)
            base._ACTIVE_BRIDGE = None


def _serial_suite_child(root: Path):
    raw_secret = sys.stdin.buffer.read(64)
    sys.stdin.close()
    try:
        secret = bytes.fromhex(raw_secret.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise base.SupervisionFailure("invalid trusted serial-suite key") from exc
    base.require(len(secret) == 32, "missing trusted serial-suite key")
    modules = _runtime_module_names(root)
    identities = _serial_suite_worker(root.resolve(), modules)
    payload = base._wire_dump([list(identity) for identity in identities])
    mac = hmac.new(secret, b"SERIAL-SUITE:" + payload, hashlib.sha256).hexdigest()
    print(
        "trusted_serial_suite="
        + mac
        + ":"
        + base64.b64encode(payload).decode("ascii")
    )


_AUTHENTICATED_SUITE_REPLAY: list[tuple[str, str, str]] | None = None


def _deterministic_expected_tests(root: Path):
    global _AUTHENTICATED_SUITE_REPLAY
    base.require(
        _AUTHENTICATED_SUITE_REPLAY is None,
        "authenticated frozen-suite replay was already armed",
    )
    modules = _runtime_module_names(root)
    secret = base.secrets.token_bytes(32)
    command = [sys.executable, "-I", str(Path(__file__).resolve()), "--execute-all-root", str(root)]
    rc, diagnostic, timed_out = base._run_process_bounded(
        command,
        cwd=root,
        env=dict(os.environ),
        timeout_seconds=220,
        input_bytes=secret.hex().encode("ascii"),
    )
    base.require(
        not timed_out and rc == 0,
        "trusted serial runtime suite failed: " f"rc={rc}\n{diagnostic}",
    )
    lines = diagnostic.splitlines()
    prefix = "trusted_serial_suite="
    base.require(
        lines and lines[-1].startswith(prefix),
        "missing authenticated serial runtime suite",
    )
    record = lines[-1][len(prefix):]
    try:
        mac, encoded = record.split(":", 1)
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise base.SupervisionFailure("malformed authenticated serial runtime suite") from exc
    expected = hmac.new(secret, b"SERIAL-SUITE:" + payload, hashlib.sha256).hexdigest()
    base.require(
        hmac.compare_digest(mac, expected),
        "serial runtime suite authentication failed",
    )
    value = base._wire_load(payload)
    base.require(type(value) is list, "serial runtime suite is not a list")
    module_set = set(modules)
    identities = []
    for item in value:
        base.require(
            type(item) is list
            and len(item) == 3
            and all(type(part) is str for part in item),
            "serial runtime suite contains an invalid identity",
        )
        identity = tuple(item)
        base.require(
            identity[0] in module_set and identity[2].startswith("test"),
            "serial runtime suite identity escaped its module floor",
        )
        identities.append(identity)
    base.require(
        identities and len(identities) == len(set(identities)),
        "empty or duplicate authenticated serial runtime floor",
    )
    _AUTHENTICATED_SUITE_REPLAY = list(identities)
    return identities


def _authenticated_run_one(root, python_bin, identity, timeout_seconds, *, local_test=False):
    global _AUTHENTICATED_SUITE_REPLAY
    if _AUTHENTICATED_SUITE_REPLAY is None:
        return _legacy_run_one(
            root, python_bin, identity, timeout_seconds, local_test=local_test
        )
    base.require(
        bool(_AUTHENTICATED_SUITE_REPLAY) and _AUTHENTICATED_SUITE_REPLAY[0] == identity,
        "authenticated frozen-suite replay order changed",
    )
    del _AUTHENTICATED_SUITE_REPLAY[0]
    if not _AUTHENTICATED_SUITE_REPLAY:
        _AUTHENTICATED_SUITE_REPLAY = None


def _restore_serial_expected_tests():
    base.expected_tests = _deterministic_expected_tests


def _deterministic_base_main(*args, **kwargs):
    replaced = base.expected_tests is not _deterministic_expected_tests
    _restore_serial_expected_tests()
    if replaced:
        print("deterministic_runtime_execution=PASS")
    return _legacy_base_main(*args, **kwargs)


# ---------------------------------------------------------------------------
# Remote observation
# ---------------------------------------------------------------------------
def _remote_bool(self):
    bridge = object.__getattribute__(self, "_bridge")
    value = bridge.request("truth", self)
    base.require(type(value) is bool, "invalid proposed truth observation")
    return value


class _RemoteIterator:
    __slots__ = ("_bridge", "_iterator")

    def __init__(self, bridge, iterator):
        object.__setattr__(self, "_bridge", bridge)
        object.__setattr__(self, "_iterator", iterator)

    def __iter__(self):
        return self

    def __next__(self):
        bridge = object.__getattribute__(self, "_bridge")
        iterator = object.__getattribute__(self, "_iterator")
        return bridge.request("next", iterator)


def _remote_iter(self):
    bridge = object.__getattribute__(self, "_bridge")
    try:
        iterator_method = bridge.request("getattr", self, "__iter__")
    except AttributeError as exc:
        raise base.SupervisionFailure("remote iterable without explicit __iter__ is unsupported") from exc
    iterator = bridge.request("call", iterator_method, (), {})
    base.require(
        type(iterator) is base._Remote,
        "proposed __iter__ did not return a remote iterator",
    )
    return _RemoteIterator(bridge, iterator)


def _remote_render(self, template: str, label: str) -> str:
    bridge = object.__getattribute__(self, "_bridge")
    formatter = bridge.request("getattr", template, "format")
    rendered = bridge.request("call", formatter, (self,), {})
    base.require(type(rendered) is str, f"invalid proposed {label} observation")
    try:
        byte_length = len(rendered.encode("utf-8"))
    except UnicodeError as exc:
        raise base.SupervisionFailure(f"proposed {label} is not valid UTF-8 text") from exc
    base.require(
        byte_length <= base.MAX_DIAGNOSTIC_BYTES,
        f"proposed {label} exceeds diagnostic budget",
    )
    return rendered


def _remote_repr(self):
    return _remote_render(self, "{!r}", "repr")


def _remote_str(self):
    return _remote_render(self, "{!s}", "str")


base._Remote.__bool__ = _remote_bool
base._Remote.__iter__ = _remote_iter
base._Remote.__repr__ = _remote_repr
base._Remote.__str__ = _remote_str
base._Bridge.close = _bridge_close
base.main = _deterministic_base_main
base.expected_tests = _deterministic_expected_tests
base.run_one = _authenticated_run_one


def _cached_process_self_test():
    import pathlib

    class LiveBridge:
        root = Path.cwd()

    prior = base._ACTIVE_BRIDGE
    base._ACTIVE_BRIDGE = LiveBridge()
    try:
        try:
            pathlib.os.system("true")
        except base.SupervisionFailure as exc:
            base.require(
                "native process creation bypassed" in str(exc),
                "cached native-launch guard failed for unrelated reason",
            )
        else:
            raise base.SupervisionFailure(
                "cached os.system reference bypassed trusted process mediation"
            )
    finally:
        base._ACTIVE_BRIDGE = prior
    print("cached_native_process_mediation=PASS")


def _cli_flag_forwarding_self_test():
    class FlagBridge(base._Bridge):
        def __init__(self, root):
            self.root = root
            self.calls = []

        def request(self, action, *arguments):
            base.require(action == "cli", "CLI-flag self-test escaped actor bridge")
            self.calls.append(arguments)
            return 0, b"flagged", b"", False

    import tempfile

    with tempfile.TemporaryDirectory(prefix="blue-forge-cli-flags-") as temp:
        root = Path(temp)
        case = root / "case.json"
        case.write_bytes(b"{}")
        bridge = FlagBridge(root)
        importer = _hardened_test_importer(bridge)
        proxy = importer("subprocess")
        command = [
            sys.executable,
            "-S",
            "-I",
            "-X",
            "utf8",
            "-m",
            "blue_forge",
            "verify",
            str(case),
        ]
        completed = proxy.run(command, capture_output=True, check=True)
        base.require(
            completed.stdout == b"flagged"
            and len(bridge.calls) == 1
            and bridge.calls[0][0] == ["verify", "-S", "-I", "-X", "utf8"],
            "validated Python flags were not preserved across the actor bridge",
        )
    print("proposed_cli_python_flags=PASS")


def _subprocess_policy_self_test():
    _legacy_subprocess_self_test()
    _cached_process_self_test()
    _cli_flag_forwarding_self_test()


def _remote_observation_self_test():
    class FakeBridge:
        def request(self, action, *arguments):
            if action == "len":
                raise base.SupervisionFailure(
                    "Remote truth used unauthenticated type-name length shortcut"
                )
            if action == "export":
                raise base.SupervisionFailure(
                    "mapping-view truth incorrectly used actor export"
                )
            if action == "truth":
                remote = arguments[0]
                handle = object.__getattribute__(remote, "_handle")
                return handle != 3
            if action == "getattr":
                base.require(
                    len(arguments) == 2
                    and arguments[1] == "format"
                    and arguments[0] in ("{!r}", "{!s}"),
                    "remote representation used unexpected actor operation",
                )
                return ("formatter", arguments[0])
            if action == "call":
                formatter, call_args, kwargs = arguments
                base.require(
                    type(formatter) is tuple
                    and len(formatter) == 2
                    and type(call_args) is tuple
                    and len(call_args) == 1
                    and kwargs == {},
                    "remote representation call envelope changed",
                )
                return "actual-proposed-repr" if formatter[1] == "{!r}" else "actual-proposed-str"
            raise base.SupervisionFailure(
                "unexpected remote observation self-test operation"
            )

    bridge = FakeBridge()
    view = base._Remote(bridge, 1, "dict_keys")
    base.require(bool(view), "nonempty mapping view observed as false")
    spoofed = base._Remote(bridge, 3, "list")
    base.require(not bool(spoofed), "user type name spoofed exact-builtin truth semantics")
    obj = base._Remote(bridge, 2, "object")
    base.require(repr(obj) == "actual-proposed-repr", "Remote repr remained synthetic")
    base.require(str(obj) == "actual-proposed-str", "Remote str remained synthetic")
    print("remote_representation=PASS actor_truth_semantics=PASS")


def _remote_iteration_self_test():
    class IteratorBridge:
        def __init__(self):
            self.actions = []
            self.next_count = 0

        def request(self, action, *arguments):
            self.actions.append(action)
            if action == "getattr":
                base.require(
                    len(arguments) == 2 and arguments[1] == "__iter__",
                    "lazy iteration requested an unexpected attribute",
                )
                return base._Remote(self, 90, "method-wrapper")
            if action == "call":
                base.require(
                    len(arguments) == 3
                    and type(arguments[0]) is base._Remote
                    and object.__getattribute__(arguments[0], "_handle") == 90
                    and arguments[1] == ()
                    and arguments[2] == {},
                    "lazy iteration used an invalid __iter__ call envelope",
                )
                return base._Remote(self, 91, "generator")
            if action == "next":
                base.require(
                    len(arguments) == 1
                    and type(arguments[0]) is base._Remote
                    and object.__getattribute__(arguments[0], "_handle") == 91,
                    "lazy iteration advanced the wrong actor handle",
                )
                self.next_count += 1
                if self.next_count == 1:
                    return "first"
                raise StopIteration
            raise base.SupervisionFailure(
                "lazy iteration used eager or unexpected actor operation"
            )

    bridge = IteratorBridge()
    source = base._Remote(bridge, 1, "generator")
    iterator = iter(source)
    base.require(
        bridge.actions == ["getattr", "call"],
        "Remote iteration consumed values while creating the iterator",
    )
    base.require(next(iterator) == "first", "Remote iterator lost its first item")
    base.require(
        bridge.actions == ["getattr", "call", "next"],
        "Remote iterator eagerly consumed more than one item",
    )
    try:
        next(iterator)
    except StopIteration:
        pass
    else:
        raise base.SupervisionFailure("Remote iterator lost StopIteration")
    base.require(
        "iterate" not in bridge.actions,
        "Remote iterator fell back to eager actor materialization",
    )
    print("remote_lazy_iteration=PASS")


def _direct_output_policy_self_test():
    class NoisyBridge:
        diagnostic_bytes = 1

    try:
        _require_silent_actor(NoisyBridge())
    except base.SupervisionFailure as exc:
        base.require(
            "emitted output" in str(exc),
            "direct-output guard failed for an unrelated reason",
        )
    else:
        raise base.SupervisionFailure("direct proposed-call output was not fail-closed")
    print("direct_call_output_policy=PASS")


def _state_preservation_self_test():
    import tempfile

    marker_name = "blue-forge-enumeration-state-" + base.secrets.token_hex(8)
    marker = Path.home() / marker_name
    try:
        marker.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="blue-forge-enumeration-state-") as temp:
            root = Path(temp)
            root.chmod(0o755)
            (root / "tests").mkdir()
            (root / "blue_forge").mkdir()
            (root / "blue_forge/__init__.py").write_text(
                "def probe(): return 'real'\n", encoding="utf-8"
            )
            (root / "tests/test_state.py").write_text(
                "import unittest\nfrom pathlib import Path\nfrom blue_forge import probe\n"
                f"MARKER=Path.home()/{marker_name!r}\n"
                "SEEN=MARKER.exists()\nMARKER.write_text('seen',encoding='ascii')\n"
                "class State(unittest.TestCase):\n"
                " def test_preserved(self):\n"
                "  self.assertFalse(SEEN)\n"
                "  self.assertTrue(MARKER.exists())\n"
                "  self.assertEqual(probe(),'real')\n",
                encoding="utf-8",
            )
            identities = _serial_suite_worker(root, ["test_state"])
            base.require(
                identities == [("test_state", "State", "test_preserved")],
                "serial suite state self-test selected the wrong oracle",
            )
    finally:
        marker.unlink(missing_ok=True)
    print("serial_runtime_discovery_execution=PASS")


def _deterministic_enumeration_self_test():
    global _AUTHENTICATED_SUITE_REPLAY
    marker = lambda root: []
    base.expected_tests = marker
    base.require(
        base.expected_tests is marker,
        "deterministic execution self-test could not install override",
    )
    _restore_serial_expected_tests()
    base.require(
        base.expected_tests is _deterministic_expected_tests,
        "serial runtime suite execution was not restored",
    )
    identity = ("test_state", "State", "test_preserved")
    _AUTHENTICATED_SUITE_REPLAY = [identity]
    _authenticated_run_one(Path.cwd(), sys.executable, identity, 1)
    base.require(
        _AUTHENTICATED_SUITE_REPLAY is None,
        "authenticated suite replay did not consume exact execution order",
    )
    _state_preservation_self_test()


def _final_boundary_self_test(python_bin, timeout_seconds, *, local_test=False):
    _legacy_final_boundary_self_test(
        python_bin, timeout_seconds, local_test=local_test
    )
    _remote_observation_self_test()
    _remote_iteration_self_test()
    _direct_output_policy_self_test()
    _deterministic_enumeration_self_test()


# Round-3 and retained functions resolve these globals dynamically. Patch every
# effective importer/worker hook while preserving all prior checks.
round3._hardened_test_importer = _hardened_test_importer
round3.round2._hardened_test_importer = _hardened_test_importer
round3.round2.previous._test_importer = _hardened_test_importer
base._test_importer = _hardened_test_importer
base._worker_run = _worker_run
base.run_one = _authenticated_run_one
round3._subprocess_policy_self_test = _subprocess_policy_self_test
round3.round2.previous._self_test_subprocess_facade = _subprocess_policy_self_test
round3._final_boundary_self_test = _final_boundary_self_test
round3.round2.previous._self_test_dispatch_and_descriptors = _final_boundary_self_test

# Compatibility names used by the governed launcher/current-suite scheduler.
previous = round3.previous
_enumerate_module_parent = round3._enumerate_module_parent


def _main():
    if len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
        return _executor_entry(Path(sys.argv[1]).resolve())
    if len(sys.argv) == 3 and sys.argv[1] == "--execute-all-root":
        _serial_suite_child(Path(sys.argv[2]))
        return 0
    return round3._main()


if __name__ == "__main__":
    raise SystemExit(_main())
