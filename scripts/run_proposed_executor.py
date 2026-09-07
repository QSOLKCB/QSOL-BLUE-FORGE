#!/usr/bin/env python3
"""Transport-side executor for the BLUE-FORGE supervised RPC bridge.

The process main interpreter never imports proposed application code. It owns the
broker-facing request/response framing and marshal codec. Proposed modules,
objects, and object handles live in a persistent CPython subinterpreter.

Python 3.12 supplies immutable values to ``run_string(..., shared=...)``. Each
request therefore enters the proposed subinterpreter as bounded marshal bytes.
In-process proposed calls run on a detached native thread whose nearest Python
ancestor uses transport-free globals. Before the first proposed frame executes,
that thread installs a Linux seccomp filter that irreversibly denies thread and
process creation. During the call, ``import __main__`` is bound to an inert
module. The real run-string module is restored only after the proposed frame has
unwound, so proposed code cannot park a background thread and wait for trusted
response state to reappear.

The private runner then emits a bounded observation through a reserved
``SystemExit`` envelope. The main interpreter validates that envelope,
constructs the final response, and performs the only broker-facing framing.
"""
from __future__ import annotations

import marshal
from pathlib import Path
import sys


MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_OPERATIONS = 4096
_RESPONSE_PREFIX = "__BLUE_FORGE_EXECUTOR_RESPONSE_V1__:"
_RUNFAILED_PREFIX = "<class 'SystemExit'>: " + _RESPONSE_PREFIX


_SUBINTERPRETER_BOOTSTRAP = r"""
from __future__ import annotations

import builtins
import collections
import ctypes
import functools
import importlib.util
import marshal
import operator
import os
from pathlib import Path
import sys
import tempfile
import types
import _thread
import time

_BF_ROOT = Path(__ROOT__).resolve()
_BF_SUPPORT_PATH = Path(__SUPPORT__).resolve()
_BF_MAX_FRAME_BYTES = __MAX_FRAME_BYTES__
_BF_MAX_OPERATIONS = __MAX_OPERATIONS__
_BF_RESPONSE_PREFIX = __RESPONSE_PREFIX__

# Capture trusted primitives before any proposed import. The detached operation
# function resolves only these captured objects from its own transport-free
# globals mapping.
_bf_BaseException = BaseException
_bf_RuntimeError = RuntimeError
_bf_SystemExit = SystemExit
_bf_type = type
_bf_object = object
_bf_len = len
_bf_bool = bool
_bf_tuple = tuple
_bf_iter = iter
_bf_next = next
_bf_getattr = getattr
_bf_setattr = setattr
_bf_delattr = delattr
_bf_str = str
_bf_bytes = bytes
_bf_dict = dict
_bf_list = list
_bf_any = any
_bf_id = id
_bf_hasattr = hasattr
_bf_map = map
_bf_deque = collections.deque
_bf_partial = functools.partial
_bf_methodcaller = operator.methodcaller
_bf_start_new_thread = _thread.start_new_thread
_bf_sleep = time.sleep
_bf_monotonic = time.monotonic
_bf_marshal_loads = marshal.loads
_bf_marshal_dumps = marshal.dumps
_bf_modules = sys.modules
_bf_actual_main = _bf_modules["__main__"]
_bf_inert_main = types.ModuleType("__main__")
_bf_hard_exit = os._exit
_bf_strerror = os.strerror
_bf_machine = os.uname().machine

_spec = importlib.util.spec_from_file_location(
    "_blue_forge_executor_support", _BF_SUPPORT_PATH
)
if _spec is None or _spec.loader is None:
    raise _bf_RuntimeError("trusted executor implementation support is unavailable")
_support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_support)

_bf_graph_decoder = _support._GraphDecoder
_bf_encode_data = _support._encode_data
_bf_run_cli_bounded = _support._run_cli_bounded
_bf_require = _support.require
_bf_max_nodes = _support.MAX_GRAPH_NODES
_bf_islice = _support.itertools.islice
_bf_deepcopy = _support.copy.deepcopy
_bf_replace = _support.dataclasses.replace
_bf_import_module = _support.importlib.import_module
_bf_temporary_directory = _support.tempfile.TemporaryDirectory

# Python 3.12 isolated subinterpreters reject daemon threads. The trusted CLI
# output-drain helper only needs joinable reader threads and already joins them
# before returning, so adapt that helper without exposing thread creation to
# proposed imports.
_bf_thread_type = _support.threading.Thread

def _bf_joinable_thread(*args, **kwargs):
    kwargs["daemon"] = False
    return _bf_thread_type(*args, **kwargs)

_support.threading.Thread = _bf_joinable_thread

# An audit hook makes the sensitive bootstrap modules non-reimportable after
# they are removed/sentinelized below. Audit hooks have no Python API for
# removal. The immutable blocked-name set and exception type are closure-owned,
# not kept in the importable proposed __main__ namespace.
def _bf_make_import_guard(blocked, error_type):
    def guard(event, args):
        if event == "import" and args and type(args[0]) is str and args[0] in blocked:
            raise error_type("executor bootstrap module import is blocked")
    return guard

_bf_import_guard = _bf_make_import_guard(
    frozenset({
        "_thread", "threading", "ctypes", "_ctypes", "gc",
        "_xxsubinterpreters", "_testcapi", "_testinternalcapi",
    }),
    _bf_RuntimeError,
)
sys.addaudithook(_bf_import_guard)
del _bf_import_guard, _bf_make_import_guard

# Per-thread seccomp is the irreversible boundary behind the import guard. It is
# installed only on each detached proposed-call thread, so the trusted run-string
# thread can still launch the separately isolated CLI subprocess. A proposed
# import may not create threads/processes even if it somehow recovers a low-level
# start primitive: clone/clone3/fork/vfork fail with EPERM in the kernel.
_bf_c_ushort = ctypes.c_ushort
_bf_c_ubyte = ctypes.c_ubyte
_bf_c_uint32 = ctypes.c_uint32
_bf_c_ushort_len = ctypes.c_ushort
_bf_c_int = ctypes.c_int
_bf_c_ulong = ctypes.c_ulong
_bf_POINTER = ctypes.POINTER
_bf_Structure = ctypes.Structure
_bf_cast = ctypes.cast
_bf_addressof = ctypes.addressof
_bf_get_errno = ctypes.get_errno
_bf_libc = ctypes.CDLL(None, use_errno=True)
_bf_prctl = _bf_libc.prctl
_bf_prctl.argtypes = [_bf_c_int, _bf_c_ulong, _bf_c_ulong, _bf_c_ulong, _bf_c_ulong]
_bf_prctl.restype = _bf_c_int

class _BfSockFilter(_bf_Structure):
    _fields_ = [
        ("code", _bf_c_ushort),
        ("jt", _bf_c_ubyte),
        ("jf", _bf_c_ubyte),
        ("k", _bf_c_uint32),
    ]

class _BfSockFprog(_bf_Structure):
    _fields_ = [
        ("len", _bf_c_ushort_len),
        ("filter", _bf_POINTER(_BfSockFilter)),
    ]

if _bf_machine in {"x86_64", "amd64"}:
    _BF_AUDIT_ARCH = 0xC000003E
    _BF_BLOCKED_SYSCALLS = (
        56, 57, 58, 435,
        0x40000000 | 56, 0x40000000 | 57,
        0x40000000 | 58, 0x40000000 | 435,
    )
elif _bf_machine in {"aarch64", "arm64"}:
    _BF_AUDIT_ARCH = 0xC00000B7
    _BF_BLOCKED_SYSCALLS = (220, 435)
else:
    raise _bf_RuntimeError("unsupported architecture for proposed-call seccomp")


def _bf_install_proposed_seccomp():
    try:
        # BPF: verify audit architecture, load syscall number, then return EPERM
        # for every process/thread creation syscall and ALLOW otherwise.
        instructions = [
            _BfSockFilter(0x20, 0, 0, 4),                    # LD W ABS arch
            _BfSockFilter(0x15, 1, 0, _BF_AUDIT_ARCH),       # JEQ arch
            _BfSockFilter(0x06, 0, 0, 0x80000000),           # KILL_PROCESS
            _BfSockFilter(0x20, 0, 0, 0),                    # LD W ABS nr
        ]
        for syscall_number in _BF_BLOCKED_SYSCALLS:
            instructions.append(_BfSockFilter(0x15, 0, 1, syscall_number))
            instructions.append(_BfSockFilter(0x06, 0, 0, 0x00050000 | 1))  # ERRNO EPERM
        instructions.append(_BfSockFilter(0x06, 0, 0, 0x7FFF0000))  # ALLOW
        array_type = _BfSockFilter * _bf_len(instructions)
        program_array = array_type(*instructions)
        program = _BfSockFprog(
            _bf_len(instructions),
            _bf_cast(program_array, _bf_POINTER(_BfSockFilter)),
        )
        # PR_SET_NO_NEW_PRIVS=38; PR_SET_SECCOMP=22; SECCOMP_MODE_FILTER=2.
        if _bf_prctl(38, 1, 0, 0, 0) != 0:
            raise _bf_RuntimeError(
                "cannot set no_new_privs for proposed-call seccomp: "
                + _bf_strerror(_bf_get_errno())
            )
        if _bf_prctl(22, 2, _bf_addressof(program), 0, 0) != 0:
            raise _bf_RuntimeError(
                "cannot install proposed-call seccomp: "
                + _bf_strerror(_bf_get_errno())
            )
        return None
    except _bf_BaseException:
        # Never execute proposed Python if the irreversible boundary cannot be
        # established. Killing this isolated executor makes the supervisor fail.
        _bf_hard_exit(120)


# Mandatory bootstrap proof: on this runner/architecture, a thread with the
# proposed-call filter must be unable to create a second native Python thread.
def _bf_seccomp_self_test(destination):
    _bf_install_proposed_seccomp()
    try:
        _bf_start_new_thread(_bf_sleep, (0.01,))
    except _bf_BaseException:
        destination.append(True)
    else:
        destination.append(False)

_bf_seccomp_probe = _bf_deque()
_bf_start_new_thread(_bf_seccomp_self_test, (_bf_seccomp_probe,))
_bf_seccomp_deadline = _bf_monotonic() + 2.0
while not _bf_seccomp_probe and _bf_monotonic() < _bf_seccomp_deadline:
    _bf_sleep(0.001)
if not _bf_seccomp_probe or _bf_seccomp_probe.popleft() is not True:
    raise _bf_RuntimeError("proposed-call seccomp self-test failed")
del _bf_seccomp_self_test, _bf_seccomp_probe, _bf_seccomp_deadline

# The support module retains any stdlib objects it needs. These sentinels are
# defense in depth only; the audit hook prevents pop-and-reimport, and seccomp
# is the load-bearing irreversible thread/process boundary for proposed calls.
_bf_modules.pop("_blue_forge_executor_support", None)
_bf_modules["_xxsubinterpreters"] = None
_bf_modules["gc"] = None
_bf_modules["_thread"] = None
_bf_modules.pop("threading", None)
_bf_modules["ctypes"] = None
_bf_modules["_ctypes"] = None
_bf_modules["_testcapi"] = None
_bf_modules["_testinternalcapi"] = None
if _bf_hasattr(sys, "_current_frames"):
    sys._current_frames = None

del ctypes

_BF_OPERATION_SOURCE = r'''
def execute_action(action, arguments):
    try:
        if action == "module":
            value = import_module(arguments[0])
        elif action == "getattr":
            value = getattr_fn(*arguments)
        elif action == "setattr":
            value = setattr_fn(*arguments)
        elif action == "delattr":
            value = delattr_fn(*arguments)
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
            value = bool_fn(arguments[0])
        elif action == "len":
            value = len_fn(arguments[0])
        elif action == "iterate":
            items = tuple_fn(islice(iter_fn(arguments[0]), max_nodes + 1))
            if len_fn(items) > max_nodes:
                raise RuntimeErrorType("executor iteration budget exceeded")
            value = items
        elif action == "next":
            value = next_fn(arguments[0])
        elif action == "deepcopy":
            value = deepcopy(arguments[0])
        elif action == "replace":
            value = replace(arguments[0], **arguments[1])
        elif action == "object_setattr":
            value = object_type.__setattr__(*arguments)
        elif action == "export":
            value = arguments[0]
        elif action == "cli":
            cli_args, case_bytes, environment = arguments
            with TemporaryDirectory() as temp:
                path = PathType(temp) / "case.json"
                path.write_bytes(case_bytes)
                command = [python_executable, "-m", "blue_forge", cli_args[0], str_fn(path)]
                value = run_cli_bounded(command, root, environment)
        else:
            raise RuntimeErrorType("unknown executor operation")
        return (True, value, "")
    except BaseExceptionType as exc:
        try:
            message = str_fn(exc)
        except BaseExceptionType:
            message = "exception message unavailable"
        return (False, exc, message)
'''

_operation_globals = {
    "__builtins__": {},
    "BaseExceptionType": _bf_BaseException,
    "RuntimeErrorType": _bf_RuntimeError,
    "import_module": _bf_import_module,
    "getattr_fn": _bf_getattr,
    "setattr_fn": _bf_setattr,
    "delattr_fn": _bf_delattr,
    "bool_fn": _bf_bool,
    "len_fn": _bf_len,
    "tuple_fn": _bf_tuple,
    "iter_fn": _bf_iter,
    "next_fn": _bf_next,
    "object_type": _bf_object,
    "str_fn": _bf_str,
    "islice": _bf_islice,
    "max_nodes": _bf_max_nodes,
    "deepcopy": _bf_deepcopy,
    "replace": _bf_replace,
    "root": _BF_ROOT,
    "python_executable": sys.executable,
    "run_cli_bounded": _bf_run_cli_bounded,
    "TemporaryDirectory": _bf_temporary_directory,
    "PathType": Path,
}
exec(compile(_BF_OPERATION_SOURCE, "<blue-forge-proposed-operation>", "exec"), _operation_globals)
_bf_execute_action = _operation_globals["execute_action"]

sys.path.insert(0, _bf_str(_BF_ROOT))
os.chdir(_BF_ROOT)
sys.stdout = sys.stderr
sys.__stdout__ = sys.stderr

_bf_handles = {}
_bf_identities = {}
_bf_exported_validation = None
_bf_exported_blue = None
_bf_operations = 0


def _bf_detached_execute(action, arguments):
    outcomes = _bf_deque()
    invocation = _bf_partial(_bf_execute_action, action, arguments)
    # Both calls are driven by C-level map/methodcaller/deque machinery. The
    # seccomp installer frame has fully unwound before the proposed invocation
    # begins, so it is not present in the proposed Python back-frame chain.
    calls = _bf_map(
        _bf_methodcaller("__call__"),
        (_bf_install_proposed_seccomp, invocation),
    )
    target = _bf_methodcaller("extend", calls)

    # The importable __main__ is inert for the entire lifetime of proposed
    # Python execution. The real run-string module returns only after the
    # detached frame has fully unwound. Seccomp prevents a background thread
    # from surviving this boundary and observing the restored trusted module.
    _bf_modules["__main__"] = _bf_inert_main
    try:
        _bf_start_new_thread(target, (outcomes,))
        while _bf_len(outcomes) < 2:
            _bf_sleep(0.001)
    finally:
        _bf_modules["__main__"] = _bf_actual_main

    installer_result = outcomes.popleft()
    if installer_result is not None or _bf_len(outcomes) != 1:
        raise _bf_RuntimeError("detached executor seccomp setup produced invalid state")
    outcome = outcomes.popleft()
    if (
        _bf_type(outcome) is not _bf_tuple
        or _bf_len(outcome) != 3
        or _bf_type(outcome[0]) is not _bf_bool
    ):
        raise _bf_RuntimeError("detached executor produced a malformed outcome")
    return outcome


def _bf_result(value):
    if value is None or _bf_type(value) in (_bf_str, _bf_bytes, int, float, _bf_bool):
        return ["data", _bf_encode_data(value)]
    if _bf_type(value) is _bf_tuple:
        return ["tuple", [_bf_result(item) for item in value]]
    oid = _bf_id(value)
    if oid not in _bf_identities:
        _bf_require(_bf_len(_bf_handles) < _bf_max_nodes, "executor handle budget exceeded")
        handle = _bf_len(_bf_handles)
        _bf_identities[oid] = handle
        _bf_handles[handle] = value
    name = _bf_type.__getattribute__(_bf_type(value), "__name__")
    return ["handle", [_bf_identities[oid], name]]


def _bf_capture_exports():
    global _bf_exported_validation, _bf_exported_blue
    package = _bf_modules.get("blue_forge")
    if package is None:
        return
    namespace = _bf_object.__getattribute__(package, "__dict__")
    validation = namespace.get("ValidationError")
    blue = namespace.get("BlueForgeError")
    if _bf_type(validation) is _bf_type:
        _bf_exported_validation = validation
    if _bf_type(blue) is _bf_type:
        _bf_exported_blue = blue


def _bf_exception_key(exc):
    cls = _bf_type(exc)
    mro = _bf_type.__getattribute__(cls, "__mro__")
    if _bf_exported_validation is not None and _bf_any(
        item is _bf_exported_validation for item in mro
    ):
        return "blue_forge.ValidationError"
    if _bf_exported_blue is not None and _bf_any(item is _bf_exported_blue for item in mro):
        return "blue_forge.BlueForgeError"
    exact = {
        AssertionError: "builtins.AssertionError",
        AttributeError: "builtins.AttributeError",
        TypeError: "builtins.TypeError",
        ValueError: "builtins.ValueError",
        KeyError: "builtins.KeyError",
        StopIteration: "builtins.StopIteration",
        RuntimeError: "builtins.RuntimeError",
    }
    return exact.get(cls)


def _bf_process_one(raw):
    global _bf_operations
    _bf_operations += 1
    _bf_require(_bf_operations <= _BF_MAX_OPERATIONS, "executor operation budget exceeded")
    _bf_require(_bf_type(raw) is _bf_bytes and _bf_len(raw) <= _BF_MAX_FRAME_BYTES,
                "invalid executor subinterpreter request")
    try:
        request = _bf_marshal_loads(raw)
    except (EOFError, TypeError, ValueError) as exc:
        raise _bf_RuntimeError("malformed executor subinterpreter request") from exc

    _bf_require(_bf_type(request) is _bf_dict, "invalid executor request")
    _bf_require(_bf_type(request.get("action")) is _bf_str, "invalid executor action")
    _bf_require(_bf_type(request.get("nodes")) is _bf_list, "invalid executor graph")
    _bf_require(_bf_type(request.get("arguments")) is _bf_list, "invalid executor arguments")
    _bf_require(_bf_type(request.get("sync")) is _bf_list, "invalid executor sync set")

    decoder = _bf_graph_decoder(request["nodes"], _bf_handles)
    arguments = [decoder.decode(value) for value in request["arguments"]]
    action = request["action"]

    # CLI orchestration is trusted code in this interpreter; the proposed CLI
    # itself runs in a separate child process. Running the helper here avoids
    # Python 3.12 DummyThread semantics without exposing response transport to
    # proposed in-process Python frames.
    if action == "cli":
        ok, observed, message = _bf_execute_action(action, arguments)
    else:
        ok, observed, message = _bf_detached_execute(action, arguments)

    if ok:
        if action == "module":
            _bf_capture_exports()
        observation = {
            "ok": True,
            "value": (
                ["data", _bf_encode_data(_bf_encode_data(observed))]
                if action == "export"
                else _bf_result(observed)
            ),
        }
    else:
        observation = {
            "ok": False,
            "error": _bf_exception_key(observed),
            "message": message,
        }

    states = {}
    for key in request.get("sync", []):
        if key in decoder.cache:
            states[_bf_str(key)] = _bf_encode_data(
                _bf_object.__getattribute__(decoder.cache[key], "__dict__")
            )
    observation["states"] = states
    payload = _bf_marshal_dumps(observation, 4)
    _bf_require(_bf_len(payload) <= _BF_MAX_FRAME_BYTES,
                "executor subinterpreter response exceeds byte budget")

    # Raised only after any proposed in-process frame has unwound and __main__
    # has been restored. Proposed exceptions were already converted to data.
    raise _bf_SystemExit(_BF_RESPONSE_PREFIX + payload.hex())


if _bf_modules.get("__main__") is not _bf_actual_main:
    raise _bf_RuntimeError("executor subinterpreter main module was not preserved")
if _bf_hasattr(_bf_inert_main, "_write_frame"):
    raise _bf_RuntimeError("proposed subinterpreter exposes executor transport module")
"""


def _read_exact(stream, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = stream.read(count - len(chunks))
        if not chunk:
            raise EOFError("executor channel closed")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_frame(stream, loads) -> object:
    header = _read_exact(stream, 8)
    size = int.from_bytes(header, "big")
    if size > MAX_FRAME_BYTES:
        raise RuntimeError("executor request exceeds byte budget")
    return loads(_read_exact(stream, size))


def _write_frame(stream, value: object, dumps) -> None:
    payload = dumps(value, 4)
    if len(payload) > MAX_FRAME_BYTES:
        raise RuntimeError("executor response exceeds byte budget")
    stream.write(len(payload).to_bytes(8, "big"))
    stream.write(payload)
    stream.flush()


def _validate_request(request: object) -> dict:
    if type(request) is not dict:
        raise RuntimeError("invalid executor request")
    if type(request.get("sequence")) is not int:
        raise RuntimeError("invalid executor sequence")
    if type(request.get("action")) is not str:
        raise RuntimeError("invalid executor action")
    if type(request.get("nodes")) is not list:
        raise RuntimeError("invalid executor graph")
    if type(request.get("arguments")) is not list:
        raise RuntimeError("invalid executor arguments")
    if type(request.get("sync")) is not list:
        raise RuntimeError("invalid executor sync set")
    return request


def _decode_runfailed(exc: BaseException, loads) -> object:
    text = str(exc)
    if not text.startswith(_RUNFAILED_PREFIX):
        raise RuntimeError(f"proposed subinterpreter operation failed: {text}") from exc
    encoded = text[len(_RUNFAILED_PREFIX):]
    if not encoded or len(encoded) > MAX_FRAME_BYTES * 2:
        raise RuntimeError("invalid executor subinterpreter response envelope")
    try:
        payload = bytes.fromhex(encoded)
    except ValueError as decode_exc:
        raise RuntimeError("malformed executor subinterpreter response envelope") from decode_exc
    if len(payload) > MAX_FRAME_BYTES:
        raise RuntimeError("executor subinterpreter response exceeds byte budget")
    try:
        return loads(payload)
    except (EOFError, TypeError, ValueError) as decode_exc:
        raise RuntimeError("malformed executor subinterpreter observation") from decode_exc


def _response_from_observation(sequence: int, observation: object) -> dict:
    if type(observation) is not dict:
        raise RuntimeError("invalid executor observation")
    ok = observation.get("ok")
    states = observation.get("states")
    if type(ok) is not bool or type(states) is not dict:
        raise RuntimeError("malformed executor observation")
    response = {"sequence": sequence, "ok": ok, "states": states}
    if ok:
        if "value" not in observation:
            raise RuntimeError("executor success omitted value")
        response["value"] = observation["value"]
    else:
        if "error" not in observation or type(observation.get("message")) is not str:
            raise RuntimeError("executor failure omitted identity")
        response["error"] = observation.get("error")
        response["message"] = observation["message"]
    return response


def main() -> int:
    if len(sys.argv) != 2:
        raise RuntimeError("executor requires one proposed source root")
    root = Path(sys.argv[1]).resolve()
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("invalid proposed executor root")

    support_path = Path(__file__).with_name("_run_frozen_tests_supervised_impl.py").resolve()
    support_info = support_path.stat()
    if not support_path.is_file() or support_info.st_mode & 0o022:
        raise RuntimeError("trusted executor support is unavailable or writable")

    try:
        import _xxsubinterpreters as interpreters
    except ImportError as exc:
        raise RuntimeError("CPython subinterpreter support is unavailable") from exc

    loads = marshal.loads
    dumps = marshal.dumps
    wire_in = sys.stdin.buffer
    transport_stdout = sys.stdout
    wire_out = transport_stdout.buffer
    sys.stdout = sys.stderr
    sys.__stdout__ = sys.stderr

    interpreter = interpreters.create()
    bootstrap = (
        _SUBINTERPRETER_BOOTSTRAP
        .replace("__ROOT__", repr(str(root)))
        .replace("__SUPPORT__", repr(str(support_path)))
        .replace("__MAX_FRAME_BYTES__", str(MAX_FRAME_BYTES))
        .replace("__MAX_OPERATIONS__", str(MAX_OPERATIONS))
        .replace("__RESPONSE_PREFIX__", repr(_RESPONSE_PREFIX))
    )

    try:
        interpreters.run_string(interpreter, bootstrap)
        for _number in range(MAX_OPERATIONS):
            try:
                request = _validate_request(_read_frame(wire_in, loads))
            except EOFError:
                return 0

            request_payload = dumps(
                {
                    "action": request["action"],
                    "nodes": request["nodes"],
                    "arguments": request["arguments"],
                    "sync": request["sync"],
                },
                4,
            )
            if len(request_payload) > MAX_FRAME_BYTES:
                raise RuntimeError("executor request exceeds byte budget")

            try:
                interpreters.run_string(
                    interpreter,
                    "_bf_process_one(_bf_request)",
                    {"_bf_request": request_payload},
                )
            except interpreters.RunFailedError as exc:
                observation = _decode_runfailed(exc, loads)
            else:
                raise RuntimeError("proposed subinterpreter omitted response envelope")

            # Final response construction and broker-facing framing occur only
            # in this interpreter, which never imported proposed application code.
            response = _response_from_observation(request["sequence"], observation)
            _write_frame(wire_out, response, dumps)
        raise RuntimeError("executor operation budget exceeded")
    finally:
        try:
            interpreters.destroy(interpreter)
        except RuntimeError:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaseException as exc:
        print(f"proposed_executor=FAIL reason={str(exc)!r}", file=sys.stderr)
        raise SystemExit(1)
