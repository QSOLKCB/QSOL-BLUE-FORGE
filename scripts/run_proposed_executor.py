#!/usr/bin/env python3
"""Untrusted-side executor for the BLUE-FORGE supervised RPC bridge.

This process imports proposed application code and retains proposed Python object
handles. It never speaks the trusted worker protocol directly. A separate
baseline-owned broker process validates requests, receives these bounded
observations over a private binary channel, and constructs the worker-facing
response with serializer state that proposed imports cannot reach.

Proposed operations execute on a detached native thread. Their Python frame
chain terminates inside a transport-free dispatch frame; request framing,
worker-facing output, and marshal serialization remain on the executor's main
thread. The executor therefore has no signing key and no authority to declare a
test successful. Its observations remain untrusted application data.
"""
from __future__ import annotations

import collections
import copy
import dataclasses
import functools
import importlib
import importlib.util
import inspect
import itertools
import marshal
import operator
import os
from pathlib import Path
import sys
import tempfile
import _thread
import time


MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_OPERATIONS = 4096


def _load_impl():
    path = Path(__file__).with_name("_run_frozen_tests_supervised_impl.py")
    spec = importlib.util.spec_from_file_location("_blue_forge_executor_impl", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("trusted executor implementation support is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def _execute_action(action: str, arguments: list[object], context: tuple[object, ...]):
    """Execute proposed behavior without any response-transport ancestor frame.

    This function is entered from CPython's native _thread bootstrap through
    C-implemented operator/functools/deque combinators. Proposed Python called
    below can inspect its own Python ancestors, but those ancestors contain no
    request framing, response stream, marshal codec, signing material, or result
    sink. The C trampoline records this function's returned outcome only after
    the proposed frame has unwound.
    """
    (
        import_module,
        islice,
        max_nodes,
        deepcopy,
        replace,
        root,
        python_executable,
        run_cli_bounded,
    ) = context
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
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "case.json"
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


def _detached_execute(action: str, arguments: list[object], context: tuple[object, ...]):
    """Run one dispatch on a native thread and return exactly one C-deposited outcome."""
    outcomes = collections.deque()
    invocation = functools.partial(_execute_action, action, arguments, context)
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


def _self_test_frame_boundary(context: tuple[object, ...]) -> None:
    """Prove detached proposed frames cannot climb into transport-frame locals."""
    def probe():
        frame = inspect.currentframe().f_back
        while frame is not None:
            namespace = frame.f_locals
            if any(name in namespace for name in ("wire_out", "request", "dumps")):
                return False
            frame = frame.f_back
        return True

    # These names intentionally mirror the transport locals attacked in review.
    wire_out = object()
    request = {"sequence": 1}
    dumps = marshal.dumps
    if not wire_out or not request or not dumps:
        raise RuntimeError("executor frame-boundary self-test setup failed")
    ok, observed, message = _detached_execute("call", [probe, (), {}], context)
    if not ok or observed is not True or message != "":
        raise RuntimeError("executor detached frame boundary self-test failed")


def main() -> int:
    if len(sys.argv) != 2:
        raise RuntimeError("executor requires one proposed source root")
    root = Path(sys.argv[1]).resolve()
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("invalid proposed executor root")

    support = _load_impl()
    graph_decoder = support._GraphDecoder
    encode_data = support._encode_data
    run_cli_bounded = support._run_cli_bounded
    require = support.require
    max_nodes = support.MAX_GRAPH_NODES
    islice = support.itertools.islice
    deepcopy = support.copy.deepcopy
    replace = support.dataclasses.replace
    import_module = support.importlib.import_module
    loads = marshal.loads
    dumps = marshal.dumps

    dispatch_context = (
        import_module,
        islice,
        max_nodes,
        deepcopy,
        replace,
        root,
        sys.executable,
        run_cli_bounded,
    )
    _self_test_frame_boundary(dispatch_context)

    sys.path.insert(0, str(root))
    os.chdir(root)
    wire_in = sys.stdin.buffer
    wire_out = sys.stdout.buffer
    sys.stdout = sys.stderr
    sys.__stdout__ = sys.stderr
    sys._current_frames = None

    handles: dict[int, object] = {}
    identities: dict[int, int] = {}
    exported_validation = None
    exported_blue = None

    def result(value: object):
        if value is None or type(value) in (str, bytes, int, float, bool):
            return ["data", encode_data(value)]
        if type(value) is tuple:
            return ["tuple", [result(item) for item in value]]
        oid = id(value)
        if oid not in identities:
            require(len(handles) < max_nodes, "executor handle budget exceeded")
            handle = len(handles)
            identities[oid] = handle
            handles[handle] = value
        name = type.__getattribute__(type(value), "__name__")
        return ["handle", [identities[oid], name]]

    def capture_exports() -> None:
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

    def exception_key(exc: BaseException):
        cls = type(exc)
        mro = type.__getattribute__(cls, "__mro__")
        if exported_validation is not None and any(item is exported_validation for item in mro):
            return "blue_forge.ValidationError"
        if exported_blue is not None and any(item is exported_blue for item in mro):
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

    for _number in range(MAX_OPERATIONS):
        try:
            request = _read_frame(wire_in, loads)
        except EOFError:
            return 0
        require(type(request) is dict, "invalid executor request")
        require(type(request.get("sequence")) is int, "invalid executor sequence")
        require(type(request.get("action")) is str, "invalid executor action")
        require(type(request.get("nodes")) is list, "invalid executor graph")
        require(type(request.get("arguments")) is list, "invalid executor arguments")
        require(type(request.get("sync")) is list, "invalid executor sync set")

        decoder = graph_decoder(request["nodes"], handles)
        arguments = [decoder.decode(value) for value in request["arguments"]]
        action = request["action"]
        ok, observed, message = _detached_execute(action, arguments, dispatch_context)
        if ok:
            if action == "module":
                capture_exports()
            response = {
                "sequence": request["sequence"],
                "ok": True,
                "value": ["data", encode_data(observed)] if action == "export" else result(observed),
            }
        else:
            response = {
                "sequence": request["sequence"],
                "ok": False,
                "error": exception_key(observed),
                "message": message,
            }

        states = {}
        for key in request.get("sync", []):
            if key in decoder.cache:
                states[str(key)] = encode_data(
                    object.__getattribute__(decoder.cache[key], "__dict__")
                )
        response["states"] = states
        _write_frame(wire_out, response, dumps)

    raise RuntimeError("executor operation budget exceeded")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaseException as exc:
        print(f"proposed_executor=FAIL reason={str(exc)!r}", file=sys.stderr)
        raise SystemExit(1)
