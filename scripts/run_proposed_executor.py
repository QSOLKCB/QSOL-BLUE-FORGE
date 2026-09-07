#!/usr/bin/env python3
"""Transport-side executor for the BLUE-FORGE supervised RPC bridge.

The process main interpreter never imports proposed application code. It owns the
broker-facing request/response framing and marshal codec. Proposed modules,
objects, and object handles live in a persistent CPython subinterpreter.

Within that subinterpreter, proposed Python operations execute on a detached
native thread whose Python ancestor frames use a transport-free globals mapping.
The subinterpreter runner receives the raw returned object only after the
proposed frame unwinds, converts it to a bounded observation, and transfers that
observation over a private CPython interpreter channel. The main interpreter
then independently constructs and serializes the executor response.

Proposed imports therefore cannot reach this module's __main__, _write_frame,
request objects, marshal.dumps reference, or broker-facing stdout framing.
"""
from __future__ import annotations

import marshal
from pathlib import Path
import sys


MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_OPERATIONS = 4096


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
import types
import _thread
import time
import _xxsubinterpreters as _bf_interpreters

_BF_ROOT = Path(__ROOT__).resolve()
_BF_SUPPORT_PATH = Path(__SUPPORT__).resolve()
_BF_REQUEST_CHANNEL = __REQUEST_CHANNEL__
_BF_RESPONSE_CHANNEL = __RESPONSE_CHANNEL__
_BF_MAX_FRAME_BYTES = __MAX_FRAME_BYTES__
_BF_MAX_OPERATIONS = __MAX_OPERATIONS__

_bf_channel_recv = _bf_interpreters.channel_recv
_bf_channel_send = _bf_interpreters.channel_send

_spec = importlib.util.spec_from_file_location(
    "_blue_forge_executor_support", _BF_SUPPORT_PATH
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted executor implementation support is unavailable")
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

sys.modules.pop("_blue_forge_executor_support", None)
sys.modules["_xxsubinterpreters"] = None
sys.modules["gc"] = None

_BF_OPERATION_SOURCE = r'''
def execute_action(action, arguments):
    try:
        if action == "module":
            value = import_module(arguments[0])
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
            items = tuple(islice(iter(arguments[0]), max_nodes + 1))
            if len(items) > max_nodes:
                raise RuntimeError("executor iteration budget exceeded")
            value = items
        elif action == "next":
            value = next(arguments[0])
        elif action == "deepcopy":
            value = deepcopy(arguments[0])
        elif action == "replace":
            value = replace(arguments[0], **arguments[1])
        elif action == "object_setattr":
            value = object.__setattr__(*arguments)
        elif action == "export":
            value = arguments[0]
        elif action == "cli":
            cli_args, case_bytes, environment = arguments
            with TemporaryDirectory() as temp:
                path = PathType(temp) / "case.json"
                path.write_bytes(case_bytes)
                command = [python_executable, "-m", "blue_forge", cli_args[0], str(path)]
                value = run_cli_bounded(command, root, environment)
        else:
            raise RuntimeError("unknown executor operation")
        return (True, value, "")
    except BaseException as exc:
        try:
            message = str(exc)
        except BaseException:
            message = "exception message unavailable"
        return (False, exc, message)
'''

_operation_globals = {
    "__builtins__": builtins.__dict__,
    "import_module": _bf_import_module,
    "islice": _bf_islice,
    "max_nodes": _bf_max_nodes,
    "deepcopy": _bf_deepcopy,
    "replace": _bf_replace,
    "root": _BF_ROOT,
    "python_executable": sys.executable,
    "run_cli_bounded": _bf_run_cli_bounded,
    "TemporaryDirectory": _support.tempfile.TemporaryDirectory,
    "PathType": Path,
}
exec(compile(_BF_OPERATION_SOURCE, "<blue-forge-proposed-operation>", "exec"), _operation_globals)
_bf_execute_action = _operation_globals["execute_action"]

sys.modules["__main__"] = types.ModuleType("__main__")
if hasattr(sys, "_current_frames"):
    sys._current_frames = None

sys.path.insert(0, str(_BF_ROOT))
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
    if len(outcomes) != 1:
        raise RuntimeError("detached executor produced an invalid outcome count")
    outcome = outcomes.popleft()
    if type(outcome) is not tuple or len(outcome) != 3 or type(outcome[0]) is not bool:
        raise RuntimeError("detached executor produced a malformed outcome")
    return outcome


def _bf_result(value):
    if value is None or type(value) in (str, bytes, int, float, bool):
        return ["data", _bf_encode_data(value)]
    if type(value) is tuple:
        return ["tuple", [_bf_result(item) for item in value]]
    oid = id(value)
    if oid not in _bf_identities:
        _bf_require(len(_bf_handles) < _bf_max_nodes, "executor handle budget exceeded")
        handle = len(_bf_handles)
        _bf_identities[oid] = handle
        _bf_handles[handle] = value
    name = type.__getattribute__(type(value), "__name__")
    return ["handle", [_bf_identities[oid], name]]


def _bf_capture_exports():
    global _bf_exported_validation, _bf_exported_blue
    package = sys.modules.get("blue_forge")
    if package is None:
        return
    namespace = object.__getattribute__(package, "__dict__")
    validation = namespace.get("ValidationError")
    blue = namespace.get("BlueForgeError")
    if type(validation) is type:
        _bf_exported_validation = validation
    if type(blue) is type:
        _bf_exported_blue = blue


def _bf_exception_key(exc):
    cls = type(exc)
    mro = type.__getattribute__(cls, "__mro__")
    if _bf_exported_validation is not None and any(
        item is _bf_exported_validation for item in mro
    ):
        return "blue_forge.ValidationError"
    if _bf_exported_blue is not None and any(item is _bf_exported_blue for item in mro):
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


def _bf_process_one():
    global _bf_operations
    _bf_operations += 1
    _bf_require(_bf_operations <= _BF_MAX_OPERATIONS, "executor operation budget exceeded")
    raw = _bf_channel_recv(_BF_REQUEST_CHANNEL)
    _bf_require(type(raw) is bytes and len(raw) <= _BF_MAX_FRAME_BYTES,
                "invalid executor subinterpreter request")
    try:
        request = marshal.loads(raw)
    except (EOFError, TypeError, ValueError) as exc:
        raise RuntimeError("malformed executor subinterpreter request") from exc

    _bf_require(type(request) is dict, "invalid executor request")
    _bf_require(type(request.get("action")) is str, "invalid executor action")
    _bf_require(type(request.get("nodes")) is list, "invalid executor graph")
    _bf_require(type(request.get("arguments")) is list, "invalid executor arguments")
    _bf_require(type(request.get("sync")) is list, "invalid executor sync set")

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
            states[str(key)] = _bf_encode_data(
                object.__getattribute__(decoder.cache[key], "__dict__")
            )
    observation["states"] = states
    payload = marshal.dumps(observation, 4)
    _bf_require(len(payload) <= _BF_MAX_FRAME_BYTES,
                "executor subinterpreter response exceeds byte budget")
    _bf_channel_send(_BF_RESPONSE_CHANNEL, payload)


if hasattr(sys.modules["__main__"], "_write_frame"):
    raise RuntimeError("proposed subinterpreter exposes executor transport module")
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

    request_channel = interpreters.channel_create()
    response_channel = interpreters.channel_create()
    interpreter = interpreters.create()
    bootstrap = (
        _SUBINTERPRETER_BOOTSTRAP
        .replace("__ROOT__", repr(str(root)))
        .replace("__SUPPORT__", repr(str(support_path)))
        .replace("__REQUEST_CHANNEL__", str(int(request_channel)))
        .replace("__RESPONSE_CHANNEL__", str(int(response_channel)))
        .replace("__MAX_FRAME_BYTES__", str(MAX_FRAME_BYTES))
        .replace("__MAX_OPERATIONS__", str(MAX_OPERATIONS))
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
            interpreters.channel_send(request_channel, request_payload)
            try:
                interpreters.run_string(interpreter, "_bf_process_one()")
            except interpreters.RunFailedError as exc:
                raise RuntimeError(
                    f"proposed subinterpreter operation failed: {exc}"
                ) from exc

            raw_observation = interpreters.channel_recv(response_channel)
            if type(raw_observation) is not bytes or len(raw_observation) > MAX_FRAME_BYTES:
                raise RuntimeError("invalid executor subinterpreter observation")
            try:
                observation = loads(raw_observation)
            except (EOFError, TypeError, ValueError) as exc:
                raise RuntimeError("malformed executor subinterpreter observation") from exc

            response = _response_from_observation(request["sequence"], observation)
            _write_frame(wire_out, response, dumps)
        raise RuntimeError("executor operation budget exceeded")
    finally:
        try:
            interpreters.destroy(interpreter)
        except RuntimeError:
            pass
        for channel in (request_channel, response_channel):
            try:
                interpreters.channel_destroy(channel)
            except (RuntimeError, KeyError):
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaseException as exc:
        print(f"proposed_executor=FAIL reason={str(exc)!r}", file=sys.stderr)
        raise SystemExit(1)
