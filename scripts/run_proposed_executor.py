#!/usr/bin/env python3
"""Transport-side executor for the BLUE-FORGE supervised RPC bridge.

The process main interpreter never imports proposed application code. It owns the
broker-facing request/response framing and marshal codec. Proposed modules,
objects, and object handles live in a persistent CPython subinterpreter.

The Python 3.12 internal subinterpreter API supports immutable values passed into
``run_string(..., shared=...)`` but does not expose the newer channel helpers on
the hosted runner. Requests therefore enter the proposed interpreter as shared
bytes. After a proposed operation has fully unwound, the private runner encodes a
bounded observation and raises a reserved built-in ``SystemExit`` envelope. The
main interpreter receives that envelope as ``RunFailedError``, validates its
exact prefix/hex payload, reconstructs the final response, and performs the only
broker-facing framing.

Proposed imports cannot reach this module's ``__main__``, ``_write_frame``,
request objects, captured ``marshal.dumps``, or broker-facing stdout framing.
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

# Capture immutable/built-in authorities before any proposed import.  The
# operation function resolves these names from its own transport-free globals
# rather than consulting a subsequently modified builtins module.
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

# Do not leave runner-support or interpreter-control modules importable by the
# code under test.  The actual run-string namespace is also hidden behind an
# inert importable __main__ below.
sys.modules.pop("_blue_forge_executor_support", None)
sys.modules["_xxsubinterpreters"] = None
sys.modules["gc"] = None

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

# The proposed call's nearest Python ancestor is defined with this deliberately
# transport-free globals mapping.  It contains no request/response serializer,
# run-string envelope, broker stream, or interpreter-control object.
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
    "TemporaryDirectory": tempfile.TemporaryDirectory,
    "PathType": Path,
}
exec(compile(_BF_OPERATION_SOURCE, "<blue-forge-proposed-operation>", "exec"), _operation_globals)
_bf_execute_action = _operation_globals["execute_action"]

# Proposed ``import __main__`` receives only this inert module, never the actual
# run-string namespace where observation encoding is retained.
sys.modules["__main__"] = types.ModuleType("__main__")
if hasattr(sys, "_current_frames"):
    sys._current_frames = None

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
    outcomes = collections.deque()
    invocation = functools.partial(_bf_execute_action, action, arguments)
    calls = map(operator.methodcaller("__call__"), (invocation,))
    target = operator.methodcaller("extend", calls)
    _thread.start_new_thread(target, (outcomes,))
    while not outcomes:
        time.sleep(0.001)
    if _bf_len(outcomes) != 1:
        raise _bf_RuntimeError("detached executor produced an invalid outcome count")
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
    oid = id(value)
    if oid not in _bf_identities:
        _bf_require(_bf_len(_bf_handles) < _bf_max_nodes, "executor handle budget exceeded")
        handle = _bf_len(_bf_handles)
        _bf_identities[oid] = handle
        _bf_handles[handle] = value
    name = _bf_type.__getattribute__(_bf_type(value), "__name__")
    return ["handle", [_bf_identities[oid], name]]


def _bf_capture_exports():
    global _bf_exported_validation, _bf_exported_blue
    package = sys.modules.get("blue_forge")
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
        request = marshal.loads(raw)
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
    payload = marshal.dumps(observation, 4)
    _bf_require(_bf_len(payload) <= _BF_MAX_FRAME_BYTES,
                "executor subinterpreter response exceeds byte budget")

    # This reserved exception is raised only after the proposed frame has fully
    # unwound.  Proposed exceptions are data in `observation` and cannot escape
    # this function to impersonate the return envelope.
    raise _bf_SystemExit(_BF_RESPONSE_PREFIX + payload.hex())


if hasattr(sys.modules["__main__"], "_write_frame"):
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

            # The final response and the only broker-facing binary frame are
            # constructed in the interpreter that never imported proposed code.
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
