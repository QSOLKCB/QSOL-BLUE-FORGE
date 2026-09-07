#!/usr/bin/env python3
"""Run frozen assertions outside proposed Python, using a bounded data bridge.

Only the trusted worker executes unittest and signs test completion. The actor
never receives a signing key. Actor responses are untrusted data, not evidence
that a test passed. CI launches each actor under a distinct UID in a fresh PID
namespace; the namespace lifetime contains even detached descendants.

The bridge retains real actor-side objects between calls. It does not substitute
its own implementation of result immutability, factories, or parser validation.
Trusted test container subclasses are reconstructed in the actor before the
operation under test, without invoking their iterators during transport.
"""
from __future__ import annotations

import argparse
import ast
import base64
import builtins
import copy
import dataclasses
import hashlib
import hmac
import importlib
import importlib.abc
import importlib.util
import inspect
import io
import itertools
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import types
import unittest
from unittest import mock
from typing import Any

MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_GRAPH_NODES = 32768
MAX_DIAGNOSTIC_BYTES = 64 * 1024
MAX_OPERATIONS = 4096
ACTOR_TIMEOUT = 15


class SupervisionFailure(RuntimeError):
    """Transport, isolation, or trusted accounting failed."""


class BlueForgeError(Exception):
    pass


class ValidationError(BlueForgeError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SupervisionFailure(reason)


# Capture primitive encoding, not json.dumps: a captured Python function still
# resolves mutable module globals. No actor-controlled JSONEncoder is consulted.
def _make_wire_codec():
    quote = json.encoder.encode_basestring_ascii
    decoder = json.JSONDecoder()
    decode = decoder.decode
    kind = type
    items = dict.items
    string = str
    encode = str.encode
    join = str.join
    maximum = MAX_FRAME_BYTES
    error = SupervisionFailure

    def dump(value):
        chunks = []
        size = 0

        def emit(text):
            nonlocal size
            size += len(text)
            if size > maximum:
                raise error("wire frame exceeds byte budget")
            chunks.append(text)

        def visit(obj, depth=0):
            if depth > 100:
                raise error("wire nesting exceeds budget")
            t = kind(obj)
            if obj is None:
                emit("null")
            elif t is bool:
                emit("true" if obj else "false")
            elif t is int:
                emit(string(obj))
            elif t is str:
                emit(quote(obj))
            elif t is list or t is tuple:
                emit("[")
                for i, child in enumerate(obj):
                    if i:
                        emit(",")
                    visit(child, depth + 1)
                emit("]")
            elif t is dict:
                emit("{")
                for i, (key, child) in enumerate(items(obj)):
                    if kind(key) is not str:
                        raise error("wire object key is not an exact string")
                    if i:
                        emit(",")
                    emit(quote(key))
                    emit(":")
                    visit(child, depth + 1)
                emit("}")
            else:
                raise error("unsupported wire scalar")

        visit(value)
        return encode(join("", chunks), "ascii")

    def load(raw):
        if kind(raw) is not bytes or len(raw) > maximum:
            raise error("invalid or oversized wire frame")
        try:
            return decode(raw.decode("ascii"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise error("malformed wire JSON") from exc

    return dump, load


_wire_dump, _wire_load = _make_wire_codec()


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def _run_process_bounded(command, *, cwd, env, timeout_seconds, input_bytes=None):
    """Bound diagnostics and reap the complete worker group on every exit path."""
    process = subprocess.Popen(
        command, cwd=cwd, env=env, start_new_session=True,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    tail = bytearray()
    errors = []

    def drain():
        try:
            while chunk := process.stdout.read(8192):
                tail.extend(chunk)
                del tail[:-MAX_DIAGNOSTIC_BYTES]
        except (OSError, ValueError) as exc:
            errors.append(exc)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        if input_bytes is not None:
            process.stdin.write(input_bytes)
            process.stdin.close()
        try:
            rc = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            rc = -signal.SIGKILL
    finally:
        # Completion is not permission for a worker to leave descendants behind.
        _kill_group(process)
        reader.join(timeout=5)
        process.stdout.close()
    require(not reader.is_alive() and not errors, "worker diagnostic drain failed")
    return rc, bytes(tail).decode("utf-8", errors="replace"), timed_out


class _Remote:
    """Opaque actor object. Every API access goes back to the real object."""
    __slots__ = ("_bridge", "_handle", "_kind")

    def __init__(self, bridge, handle, kind):
        object.__setattr__(self, "_bridge", bridge)
        object.__setattr__(self, "_handle", handle)
        object.__setattr__(self, "_kind", kind)

    def __getattr__(self, name):
        return self._bridge.request("getattr", self, name)

    def __setattr__(self, name, value):
        self._bridge.request("setattr", self, name, value)

    def __delattr__(self, name):
        self._bridge.request("delattr", self, name)

    def __call__(self, *args, **kwargs):
        return self._bridge.request("call", self, args, kwargs)

    def __getitem__(self, key):
        return self._bridge.request("getitem", self, key)

    def __setitem__(self, key, value):
        self._bridge.request("setitem", self, key, value)

    def __delitem__(self, key):
        self._bridge.request("delitem", self, key)

    def __len__(self):
        return self._bridge.request("len", self)

    def __bool__(self):
        if self._kind in {"dict", "list", "tuple", "set", "frozenset", "dict_keys", "dict_values", "dict_items"}:
            return bool(self._bridge.export(self))
        return self._bridge.request("truth", self)

    def __iter__(self):
        return iter(self._bridge.request("iterate", self))

    def __next__(self):
        return self._bridge.request("next", self)

    def __contains__(self, value):
        return _local(value) in self._bridge.export(self)

    def __eq__(self, other):
        # Assertions compare reconstructed builtin data in the trusted worker,
        # never an actor-provided "assertion passed" flag.
        return self._bridge.export(self) == _local(other)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return f"<proposed {self._kind} #{self._handle}>"

    def __deepcopy__(self, memo):
        result = self._bridge.request("deepcopy", self)
        memo[id(self)] = result
        return result


_ACTIVE_BRIDGE = None


def _local(value):
    if isinstance(value, _Remote):
        return value._bridge.export(value)
    if type(value) is dict:
        return {_local(k): _local(v) for k, v in value.items()}
    if type(value) is list:
        return [_local(v) for v in value]
    if type(value) is tuple:
        return tuple(_local(v) for v in value)
    return value


def _remote_object_setattr(obj, name, value):
    if isinstance(obj, _Remote):
        return obj._bridge.request("object_setattr", obj, name, value)
    return object.__setattr__(obj, name, value)


def _remote_replace(obj, **changes):
    if isinstance(obj, _Remote):
        return obj._bridge.request("replace", obj, changes)
    return dataclasses.replace(obj, **changes)


class _TestTransform(ast.NodeTransformer):
    """Route low-level mutation to the actor instead of testing proxy storage."""
    def visit_Attribute(self, node):
        self.generic_visit(node)
        if isinstance(node.value, ast.Name) and node.value.id == "object" and node.attr == "__setattr__":
            return ast.copy_location(ast.Name(id="_remote_object_setattr", ctx=node.ctx), node)
        return node


def _class_recipe(cls):
    path = inspect.getsourcefile(cls)
    require(path is not None, "boundary class has no trusted source")
    path = Path(path).resolve()
    require(_ACTIVE_BRIDGE is not None and path.is_relative_to(_ACTIVE_BRIDGE.root / "tests"),
            "boundary class source is outside frozen tests")
    source = textwrap.dedent(inspect.getsource(cls))
    tree = ast.parse(source)
    require(len(tree.body) == 1 and isinstance(tree.body[0], ast.ClassDef),
            "boundary class recipe is not a class definition")
    require(len(source.encode("utf-8")) <= 65536, "boundary class recipe is too large")
    return {"name": cls.__name__, "source": source}


class _GraphEncoder:
    """Preserve aliases, scalar types, and builtin-subclass boundary fixtures."""
    def __init__(self):
        self.nodes = []
        self.memo = {}
        self.sync = {}

    def encode(self, value):
        t = type(value)
        if value is None or t is bool or t is str:
            return ["scalar", value]
        if t is int:
            return ["int", str(value)]
        if t is float:
            return ["float", value.hex()]
        if t is bytes:
            return ["bytes", base64.b64encode(value).decode("ascii")]
        if isinstance(value, _Remote):
            return ["remote", value._handle]
        oid = id(value)
        if oid in self.memo:
            return ["node", self.memo[oid]]
        require(len(self.nodes) < MAX_GRAPH_NODES, "transport graph node budget exceeded")
        index = len(self.nodes)
        self.memo[oid] = index
        self.nodes.append(None)
        if isinstance(value, mock.Mock):
            require(isinstance(value.side_effect, BaseException), "unsupported mock boundary recipe")
            node = {"kind": "mock", "error": type(value.side_effect).__name__,
                    "message": str(value.side_effect)}
        elif isinstance(value, BaseException):
            node = {"kind": "exception", "error": t.__name__, "message": str(value)}
        elif isinstance(value, (dict, list, tuple, frozenset, set)):
            base = next(c for c in (dict, list, tuple, frozenset, set) if isinstance(value, c))
            node = {"kind": base.__name__, "class": None}
            if t is not base:
                node["class"] = _class_recipe(t)
            # Explicit base descriptors never invoke a hostile __iter__/items/len.
            if base is dict:
                node["items"] = [[self.encode(k), self.encode(v)] for k, v in dict.items(value)]
            else:
                node["items"] = [self.encode(v) for v in base.__iter__(value)]
            if t is not base:
                try:
                    state = object.__getattribute__(value, "__dict__")
                except AttributeError:
                    state = None
                if state is not None:
                    node["state"] = self.encode(state)
                    self.sync[index] = value
        else:
            node = {"kind": "object", "class": _class_recipe(t),
                    "state": self.encode(object.__getattribute__(value, "__dict__"))}
            self.sync[index] = value
        self.nodes[index] = node
        return ["node", index]


class _GraphDecoder:
    """Actor-only reconstruction. Recipes originate in trusted frozen source."""
    def __init__(self, nodes, handles):
        self.nodes, self.handles, self.cache = nodes, handles, {}
        self.classes = {}

    def cls(self, recipe, base):
        if recipe is None:
            return base
        key = recipe["source"]
        if key not in self.classes:
            namespace = {"io": io, "Any": Any, "Path": Path, "json": json,
                         "unittest": unittest, "copy": copy}
            code = compile("from __future__ import annotations\n" + key, "<frozen-boundary-class>", "exec")
            exec(code, namespace)
            self.classes[key] = namespace[recipe["name"]]
        return self.classes[key]

    def decode(self, value):
        tag, data = value
        if tag == "scalar":
            return data
        if tag == "int":
            return int(data)
        if tag == "float":
            return float.fromhex(data)
        if tag == "bytes":
            return base64.b64decode(data, validate=True)
        if tag == "remote":
            return self.handles[data]
        require(tag == "node" and type(data) is int and 0 <= data < len(self.nodes), "invalid transport reference")
        if data in self.cache:
            return self.cache[data]
        node = self.nodes[data]
        kind = node["kind"]
        if kind in {"mock", "exception"}:
            cls = getattr(builtins, node["error"], None)
            require(isinstance(cls, type) and issubclass(cls, Exception), "unsupported fixture exception")
            obj = cls(node["message"])
            if kind == "mock":
                obj = mock.MagicMock(side_effect=obj)
            self.cache[data] = obj
            return obj
        base = {"dict": dict, "list": list, "tuple": tuple, "frozenset": frozenset,
                "set": set, "object": object}[kind]
        cls = self.cls(node.get("class"), base)
        if kind in {"tuple", "frozenset"}:
            obj = base.__new__(cls, [self.decode(v) for v in node["items"]])
            self.cache[data] = obj
        else:
            obj = base.__new__(cls)
            self.cache[data] = obj
            if kind == "dict":
                for k, v in node["items"]:
                    dict.__setitem__(obj, self.decode(k), self.decode(v))
            elif kind == "list":
                list.extend(obj, [self.decode(v) for v in node["items"]])
            elif kind == "set":
                set.update(obj, [self.decode(v) for v in node["items"]])
        if "state" in node:
            object.__getattribute__(obj, "__dict__").update(self.decode(node["state"]))
        return obj


def _encode_data(value, *, budget=None, depth=0):
    """Export only bounded builtin data, without executing object constructors."""
    if budget is None:
        budget = [MAX_GRAPH_NODES]
    budget[0] -= 1
    require(budget[0] >= 0 and depth <= 64, "actor data export exceeds budget")
    t = type(value)
    if value is None or t is bool or t is str:
        return ["scalar", value]
    if t is int:
        return ["int", str(value)]
    if t is bytes:
        return ["bytes", base64.b64encode(value).decode("ascii")]
    if t is float:
        return ["float", value.hex()]
    if t is dict:
        return ["dict", [[_encode_data(k, budget=budget, depth=depth+1),
                          _encode_data(v, budget=budget, depth=depth+1)] for k, v in value.items()]]
    if t in (list, tuple, set, frozenset):
        return [t.__name__, [_encode_data(v, budget=budget, depth=depth+1) for v in value]]
    raise SupervisionFailure("actor export is not builtin data")


def _decode_data(value, *, budget=None, depth=0):
    if budget is None:
        budget = [MAX_GRAPH_NODES]
    budget[0] -= 1
    require(budget[0] >= 0 and depth <= 64 and type(value) is list and len(value) == 2,
            "invalid actor data envelope")
    tag, data = value
    if tag == "scalar":
        require(data is None or type(data) in (bool, str), "invalid scalar response")
        return data
    if tag == "int":
        require(type(data) is str and len(data) <= 5000, "invalid integer response")
        return int(data)
    if tag == "float":
        return float.fromhex(data)
    if tag == "bytes":
        return base64.b64decode(data, validate=True)
    require(type(data) is list, "invalid container response")
    if tag == "dict":
        out = {}
        for pair in data:
            require(type(pair) is list and len(pair) == 2, "invalid mapping entry")
            key = _decode_data(pair[0], budget=budget, depth=depth+1)
            require(type(key) in (str, int, bool, bytes, float, tuple), "invalid mapping key")
            require(key not in out, "duplicate actor mapping key")
            out[key] = _decode_data(pair[1], budget=budget, depth=depth+1)
        return out
    require(tag in {"list", "tuple", "set", "frozenset"}, "unknown actor data tag")
    items = [_decode_data(v, budget=budget, depth=depth+1) for v in data]
    return {"list": list, "tuple": tuple, "set": set, "frozenset": frozenset}[tag](items)



def _run_cli_bounded(command, root, environment):
    process = subprocess.Popen(command, cwd=root, env=environment, start_new_session=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outputs = [bytearray(), bytearray()]
    overflow = threading.Event()

    def drain(stream, destination):
        try:
            while chunk := stream.read(8192):
                if len(destination) + len(chunk) > MAX_FRAME_BYTES:
                    overflow.set()
                if not overflow.is_set():
                    destination.extend(chunk)
        finally:
            stream.close()

    readers = [threading.Thread(target=drain, args=pair, daemon=True)
               for pair in zip((process.stdout, process.stderr), outputs)]
    for reader in readers:
        reader.start()
    try:
        rc = process.wait(timeout=10)
    finally:
        _kill_group(process)
        for reader in readers:
            reader.join(timeout=2)
    require(not overflow.is_set() and not any(t.is_alive() for t in readers),
            "CLI output budget exceeded or descendants retained output")
    return rc, bytes(outputs[0]), bytes(outputs[1])


def _actor(root):
    """Untrusted actor: no signing keys, test oracle, or completion authority."""
    root = root.resolve()
    sys.path.insert(0, str(root))
    os.chdir(root)
    wire_in, wire_out = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr
    handles = {}
    identities = {}

    def result(value):
        if value is None or type(value) in (str, bytes, int, float, bool):
            return ["data", _encode_data(value)]
        if type(value) is tuple:
            return ["tuple", [result(v) for v in value]]
        oid = id(value)
        if oid not in identities:
            require(len(handles) < MAX_GRAPH_NODES, "actor handle budget exceeded")
            handle = len(handles)
            identities[oid] = handle
            handles[handle] = value
        return ["handle", [identities[oid], type(value).__name__]]

    for number in range(MAX_OPERATIONS):
        raw = wire_in.readline(MAX_FRAME_BYTES + 2)
        if not raw:
            return
        require(len(raw) <= MAX_FRAME_BYTES + 1 and raw.endswith(b"\n"), "oversized actor request")
        request = _wire_load(raw[:-1])
        decoder = _GraphDecoder(request["nodes"], handles)
        arguments = [decoder.decode(v) for v in request["arguments"]]
        action = request["action"]
        try:
            if action == "module":
                value = importlib.import_module(arguments[0])
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
                items = tuple(itertools.islice(iter(arguments[0]), MAX_GRAPH_NODES + 1))
                require(len(items) <= MAX_GRAPH_NODES, "actor iteration budget exceeded")
                value = items
            elif action == "next":
                value = next(arguments[0])
            elif action == "deepcopy":
                value = copy.deepcopy(arguments[0])
            elif action == "replace":
                value = dataclasses.replace(arguments[0], **arguments[1])
            elif action == "object_setattr":
                value = object.__setattr__(*arguments)
            elif action == "export":
                value = _encode_data(arguments[0])
            elif action == "cli":
                cli_args, case_bytes, environment = arguments
                with tempfile.TemporaryDirectory() as temp:
                    path = Path(temp) / "case.json"
                    path.write_bytes(case_bytes)
                    command = [sys.executable, "-m", "blue_forge", cli_args[0], str(path)]
                    value = _run_cli_bounded(command, root, environment)
            else:
                raise SupervisionFailure("unknown actor operation")
            response = {"sequence": request["sequence"], "ok": True,
                        "value": ["data", _encode_data(value)] if action == "export" else result(value)}
        except BaseException as exc:
            response = {"sequence": request["sequence"], "ok": False,
                        "error": type(exc).__name__, "message": str(exc)}
        states = {}
        for key in request.get("sync", []):
            if key in decoder.cache:
                states[str(key)] = _encode_data(object.__getattribute__(decoder.cache[key], "__dict__"))
        response["states"] = states
        wire_out.write(_wire_dump(response) + b"\n")
        wire_out.flush()
    raise SupervisionFailure("actor operation budget exceeded")


class _Bridge:
    def __init__(self, root, *, local_test=False):
        self.root = root.resolve()
        helper = os.environ.get("BLUE_FORGE_RPC_HELPER")
        require(helper is not None or local_test, "isolated RPC launcher is required")
        if helper:
            launcher = Path(helper)
            info = launcher.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    "isolated RPC launcher must be a root-owned, non-writable regular file")
        self.control_dir = tempfile.TemporaryDirectory(prefix="blue-forge-worker-lifeline-")
        self.control_fd = None
        control_path = Path(self.control_dir.name) / "control"
        if helper:
            os.mkfifo(control_path, 0o600)
            self.control_fd = os.open(control_path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        command = (["sudo", "-n", helper, sys.executable, str(Path(__file__).resolve()), str(self.root), str(control_path)] if helper else
                   [sys.executable, "-I", str(Path(__file__).resolve()), "--actor-root", str(self.root)])
        self.process = subprocess.Popen(command, cwd=root, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True, bufsize=0)
        self.tail = bytearray()
        self.sequence = 0
        self.fatal = None
        self.refs = {}
        self.signing_key = secrets.token_bytes(32)  # This key never leaves the trusted process.
        self.last_receipt = None
        self.reader = threading.Thread(target=self._drain, daemon=True)
        self.reader.start()

    def _drain(self):
        while chunk := self.process.stderr.read(8192):
            self.tail.extend(chunk)
            del self.tail[:-MAX_DIAGNOSTIC_BYTES]

    def _result(self, item):
        require(type(item) is list and len(item) == 2, "invalid actor result")
        tag, value = item
        if tag == "data":
            return _decode_data(value)
        if tag == "tuple":
            require(type(value) is list and len(value) <= MAX_GRAPH_NODES, "invalid actor tuple")
            return tuple(self._result(v) for v in value)
        require(tag == "handle" and type(value) is list and len(value) == 2,
                "unknown actor result type")
        handle, kind = value
        require(type(handle) is int and 0 <= handle < MAX_GRAPH_NODES and type(kind) is str,
                "invalid actor handle")
        if handle not in self.refs:
            self.refs[handle] = _Remote(self, handle, kind)
        return self.refs[handle]

    def _exchange(self, data):
        deadline = time.monotonic() + ACTOR_TIMEOUT
        selector = selectors.DefaultSelector()
        output = bytearray()
        pending = memoryview(data + b"\n")
        selector.register(self.process.stdin, selectors.EVENT_WRITE)
        selector.register(self.process.stdout, selectors.EVENT_READ)
        try:
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "proposed RPC timeout")
                events = selector.select(remaining)
                require(bool(events), "proposed RPC timeout")
                for key, mask in events:
                    if mask & selectors.EVENT_WRITE:
                        count = os.write(key.fd, pending[:65536])
                        pending = pending[count:]
                        if not pending:
                            selector.unregister(self.process.stdin)
                    if mask & selectors.EVENT_READ:
                        chunk = os.read(key.fd, 65536)
                        require(bool(chunk), "proposed RPC exited without a response")
                        output.extend(chunk)
                        require(len(output) <= MAX_FRAME_BYTES + 1, "proposed RPC response byte budget exceeded")
                        if b"\n" in output:
                            line, remainder = bytes(output).split(b"\n", 1)
                            require(not remainder and not pending, "unexpected actor protocol output")
                            return _wire_load(line)
        finally:
            selector.close()

    def request(self, action, *arguments):
        require(self.fatal is None, "RPC bridge previously failed")
        self.sequence += 1
        encoder = _GraphEncoder()
        try:
            encoded = [encoder.encode(v) for v in arguments]
            request = {"sequence": self.sequence, "action": action,
                       "arguments": encoded, "nodes": encoder.nodes, "sync": list(encoder.sync)}
            response = self._exchange(_wire_dump(request))
            require(type(response) is dict and response.get("sequence") == self.sequence,
                    "actor response sequence mismatch")
            require(type(response.get("ok")) is bool and type(response.get("states")) is dict,
                    "malformed actor response")
            # Authentication records transport observations only. It is generated
            # here, never accepted from the actor, and is not a test-pass predicate.
            observation = _wire_dump({"request": request, "response": response})
            self.last_receipt = hmac.new(self.signing_key, observation, hashlib.sha256).hexdigest()
            for key, state in response["states"].items():
                require(key.isdecimal() and int(key) in encoder.sync, "unexpected fixture-state response")
                target = object.__getattribute__(encoder.sync[int(key)], "__dict__")
                decoded = _decode_data(state)
                require(type(decoded) is dict, "invalid fixture-state response")
                target.clear()
                target.update(decoded)
            if response["ok"]:
                return self._result(response["value"])
        except (SupervisionFailure, OSError, ValueError, KeyError, TypeError) as exc:
            self.fatal = str(exc)
            diagnostic = bytes(self.tail).decode("utf-8", errors="replace")
            raise SupervisionFailure(f"RPC failed closed: {exc}\n{diagnostic}") from exc
        name = response.get("error")
        message = response.get("message")
        require(type(message) is str, "invalid actor exception message")
        known = {"ValidationError": ValidationError, "BlueForgeError": BlueForgeError,
                 "AssertionError": AssertionError, "AttributeError": AttributeError,
                 "TypeError": TypeError, "ValueError": ValueError, "KeyError": KeyError,
                 "StopIteration": StopIteration, "RuntimeError": RuntimeError}
        if name not in known:
            self.fatal = f"unexpected actor failure: {name}"
            raise SupervisionFailure(self.fatal)
        raise known[name](message)

    def export(self, value):
        return _decode_data(self.request("export", value))

    def close(self):
        self.process.stdin.close()
        if self.control_fd is not None:
            os.close(self.control_fd)
            self.control_fd = None
        try:
            self.process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            raise SupervisionFailure("isolated actor launcher did not confirm namespace teardown")
        finally:
            if self.process.poll() is not None:
                _kill_group(self.process)
            self.control_dir.cleanup()
            self.reader.join(timeout=3)
            self.process.stdout.close()
            self.process.stderr.close()
        require(self.process.returncode == 0, "isolated actor launcher failed during cleanup")
        require(not self.reader.is_alive(), "actor stderr descendants survived namespace teardown")


class _ProxyLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, bridge):
        self.bridge = bridge

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "blue_forge" or fullname.startswith("blue_forge."):
            return importlib.util.spec_from_loader(fullname, self, is_package=fullname == "blue_forge")
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        remote = self.bridge.request("module", module.__name__)
        module.BlueForgeError = BlueForgeError
        module.ValidationError = ValidationError

        def get(name):
            if name.startswith("__"):
                raise AttributeError(name)
            return getattr(remote, name)

        module.__getattr__ = get


def _test_importer(bridge):
    real_import = builtins.__import__
    json_proxy = types.ModuleType("json")
    json_proxy.__dict__.update(vars(json))
    json_proxy.dumps = lambda value, *a, **k: json.dumps(_local(value), *a, **k)
    dc_proxy = types.ModuleType("dataclasses")
    dc_proxy.__dict__.update(vars(dataclasses))
    dc_proxy.replace = _remote_replace
    process_proxy = types.ModuleType("subprocess")
    process_proxy.__dict__.update(vars(subprocess))

    def run(command, *args, **kwargs):
        if isinstance(command, (list, tuple)) and len(command) >= 5 and list(command[1:3]) == ["-m", "blue_forge"]:
            path = Path(command[4])
            with path.open("rb") as handle:
                payload = handle.read(2 * 1024 * 1024)
            env = dict(kwargs.get("env") or os.environ)
            # Do not propagate worker/supervisor configuration into proposed CLI.
            env = {k: v for k, v in env.items() if not k.startswith("BLUE_FORGE_")}
            rc, stdout, stderr = bridge.request("cli", list(command[3:]), payload, env)
            if kwargs.get("text") or kwargs.get("universal_newlines"):
                encoding = kwargs.get("encoding") or "utf-8"
                stdout, stderr = stdout.decode(encoding), stderr.decode(encoding)
            completed = subprocess.CompletedProcess(command, rc, stdout, stderr)
            if kwargs.get("check"):
                completed.check_returncode()
            return completed
        return subprocess.run(command, *args, **kwargs)

    process_proxy.run = run
    facades = {"json": json_proxy, "dataclasses": dc_proxy, "subprocess": process_proxy}

    def trusted_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in facades:
            return facades[name]
        return real_import(name, globals, locals, fromlist, level)

    return trusted_import


def expected_tests(root):
    tests = []
    for path in sorted((root / "tests").glob("test*.py")):
        require(path.is_file() and not path.is_symlink(), "invalid frozen test file")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and any(
                (isinstance(b, ast.Name) and b.id == "TestCase") or
                (isinstance(b, ast.Attribute) and b.attr == "TestCase") for b in node.bases
            ):
                for method in node.body:
                    if isinstance(method, ast.AsyncFunctionDef) and method.name.startswith("test"):
                        raise SupervisionFailure("async frozen tests require an explicit trusted runner")
                    if isinstance(method, ast.FunctionDef) and method.name.startswith("test"):
                        tests.append((path.stem, node.name, method.name))
    require(tests and len(tests) == len(set(tests)), "empty or duplicate frozen test floor")
    return tests


def _worker_run(root, identity, *, local_test=False):
    global _ACTIVE_BRIDGE
    module_name, class_name, method_name = identity
    bridge = _Bridge(root, local_test=local_test)
    _ACTIVE_BRIDGE = bridge
    finder = _ProxyLoader(bridge)
    sys.meta_path.insert(0, finder)
    sys.path.insert(0, str(root / "tests"))
    try:
        path = root / "tests" / (module_name + ".py")
        source = path.read_text(encoding="utf-8")
        tree = _TestTransform().visit(ast.parse(source, filename=str(path)))
        ast.fix_missing_locations(tree)
        module = types.ModuleType(module_name)
        module.__file__ = str(path)
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": _test_importer(bridge)}
        module.__dict__["_remote_object_setattr"] = _remote_object_setattr
        sys.modules[module_name] = module
        exec(compile(tree, str(path), "exec", dont_inherit=True), module.__dict__)
        case_class = getattr(module, class_name)
        require(isinstance(case_class, type) and issubclass(case_class, unittest.TestCase), "invalid frozen TestCase")
        result = unittest.TestResult()
        unittest.TestSuite([case_class(method_name)]).run(result)
        require(bridge.fatal is None, f"RPC failure was caught by a test: {bridge.fatal}")
        require(result.testsRun == 1 and not (result.failures or result.errors or result.skipped or result.expectedFailures or result.unexpectedSuccesses),
                "frozen test failed: " + ".".join(identity) + "\n" + "\n".join(x[1] for x in result.failures + result.errors))
    finally:
        bridge.close()
        sys.meta_path.remove(finder)
        _ACTIVE_BRIDGE = None


def run_one(root, python_bin, identity, timeout_seconds, *, local_test=False):
    secret = secrets.token_bytes(32)
    command = [python_bin, "-I", str(Path(__file__).resolve()), "--worker-root", str(root),
               "--worker-module", identity[0], "--worker-class", identity[1], "--worker-method", identity[2]]
    if local_test:
        command.append("--local-test")
    rc, diagnostic, timeout = _run_process_bounded(command, cwd=root, env=dict(os.environ),
                                                   timeout_seconds=timeout_seconds, input_bytes=secret.hex().encode())
    require(not timeout and rc == 0, f"trusted worker failed for {'.'.join(identity)}: rc={rc}\n{diagnostic}")
    expected = hmac.new(secret, ("PASS:" + ".".join(identity)).encode(), hashlib.sha256).hexdigest()
    lines = diagnostic.splitlines()
    require(lines and lines[-1] == "trusted_completion=" + expected, "missing authenticated trusted test completion")


def _self_test(python_bin, timeout_seconds, *, local_test=False):
    attacks = {
        "subclasses": "import unittest\nfor c in object.__subclasses__():\n if c.__name__ == 'TestCase': c.fail=lambda *a,**k: None\n",
        "builtins": "import builtins\n_real=builtins.getattr\ndef forged(o,n,*d):\n if isinstance(n,str) and n.startswith('test'): return lambda: None\n return _real(o,n,*d)\nbuiltins.getattr=forged\n",
        "encoder": "import json\nclass BadEncoder:\n def __init__(self,*a,**k): pass\n def encode(self,*a,**k): return 'FORGED'\njson.JSONEncoder=BadEncoder\n",
    }
    for name, attack in attacks.items():
        with tempfile.TemporaryDirectory(prefix="blue-forge-oracle-selftest-") as temp:
            root = Path(temp)
            root.chmod(0o755)
            (root / "tests").mkdir()
            (root / "blue_forge").mkdir()
            (root / "blue_forge/__init__.py").write_text(attack + "\ndef probe(): return 'real'\n", encoding="utf-8")
            (root / "tests/test_fake.py").write_text(
                "import unittest\nfrom blue_forge import probe\nclass Fake(unittest.TestCase):\n"
                " def test_pass(self): self.assertEqual(probe(), 'real')\n"
                " def test_fail(self):\n  probe()\n  self.fail('oracle is external')\n", encoding="utf-8")
            # A failure-only self-test could pass simply because the bridge broke.
            run_one(root, python_bin, ("test_fake", "Fake", "test_pass"), timeout_seconds, local_test=local_test)
            try:
                run_one(root, python_bin, ("test_fake", "Fake", "test_fail"), timeout_seconds, local_test=local_test)
            except SupervisionFailure:
                pass
            else:
                raise SupervisionFailure("oracle accepted attack " + name)



def _self_test_boundary_transport(python_bin, timeout_seconds, *, local_test=False):
    with tempfile.TemporaryDirectory(prefix="blue-forge-boundary-selftest-") as temp:
        root = Path(temp)
        root.chmod(0o755)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge/__init__.py").write_text(
            "class ValidationError(Exception): pass\n"
            "def boundary(value):\n"
            " if type(value) is not list: raise ValidationError('exact list required')\n"
            " return value\n"
            "def shared(value): return value[0] is value[1]\n", encoding="utf-8")
        (root / "tests/test_boundary.py").write_text(
            "import unittest\nfrom blue_forge import boundary, shared, ValidationError\n"
            "class Boundary(unittest.TestCase):\n"
            " def test_preserved(self):\n"
            "  class ExplodingList(list):\n"
            "   def __iter__(self): raise AssertionError('transport ran a hostile iterator')\n"
            "  self.assertEqual(boundary(['retained']), ['retained'])\n"
            "  with self.assertRaisesRegex(ValidationError, 'exact list'):\n"
            "   boundary(ExplodingList(['retained']))\n"
            "  child=['leaf']; self.assertTrue(shared([child,child]))\n", encoding="utf-8")
        run_one(root, python_bin, ("test_boundary", "Boundary", "test_preserved"),
                timeout_seconds, local_test=local_test)


def _self_test_encoder_failure(python_bin, timeout_seconds, *, local_test=False):
    with tempfile.TemporaryDirectory(prefix="blue-forge-encoder-selftest-") as temp:
        root = Path(temp)
        root.chmod(0o755)
        (root / "tests").mkdir()
        (root / "blue_forge").mkdir()
        (root / "blue_forge/__init__.py").write_text(
            "import json\n"
            "class Stealer:\n"
            " def __radd__(self, secret_prefix):\n"
            "  raise AssertionError('signing material entered proposed interpreter')\n"
            "class Encoder:\n"
            " def __init__(self,*a,**k): pass\n"
            " def encode(self,*a,**k): return Stealer()\n"
            "json.JSONEncoder=Encoder\n"
            "raise RuntimeError('genuine import failure')\n", encoding="utf-8")
        (root / "tests/test_encoder.py").write_text(
            "import unittest\nclass EncoderTests(unittest.TestCase):\n"
            " def test_error_survives(self):\n"
            "  with self.assertRaisesRegex(RuntimeError, 'genuine import failure'):\n"
            "   import blue_forge\n"
            " def test_cannot_pass(self):\n"
            "  with self.assertRaisesRegex(RuntimeError, 'genuine import failure'):\n"
            "   import blue_forge\n"
            "  self.fail('no proposed encoder can sign this test as passed')\n", encoding="utf-8")
        run_one(root, python_bin, ("test_encoder", "EncoderTests", "test_error_survives"),
                timeout_seconds, local_test=local_test)
        try:
            run_one(root, python_bin, ("test_encoder", "EncoderTests", "test_cannot_pass"),
                    timeout_seconds, local_test=local_test)
        except SupervisionFailure:
            return
        raise SupervisionFailure("proposed encoder forged trusted completion")


def _live_marker(marker):
    encoded = marker.encode("ascii")
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if encoded in path.read_bytes().split(b"\x00"):
                return True
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return False


def _self_test_descendants(python_bin, timeout_seconds):
    """A detached native-spawn child must die on success and worker SIGKILL."""
    require(os.environ.get("BLUE_FORGE_RPC_HELPER"), "kernel lifetime self-test requires isolated launcher")
    for timeout in (False, True):
        marker = "blue-forge-child-" + secrets.token_hex(16)
        with tempfile.TemporaryDirectory(prefix="blue-forge-lifetime-selftest-") as temp:
            root = Path(temp)
            root.chmod(0o755)
            (root / "tests").mkdir()
            (root / "blue_forge").mkdir()
            (root / "blue_forge/__init__.py").write_text(
                "import subprocess,sys,time\n"
                "def spawn():\n"
                f" subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)',{marker!r}],"
                "start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                + (" time.sleep(60)\n" if timeout else " return 'spawned'\n"), encoding="utf-8")
            (root / "tests/test_lifetime.py").write_text(
                "import unittest\nfrom blue_forge import spawn\n"
                "class Lifetime(unittest.TestCase):\n"
                " def test_spawn(self): self.assertEqual(spawn(), 'spawned')\n", encoding="utf-8")
            rejected = False
            try:
                run_one(root, python_bin, ("test_lifetime", "Lifetime", "test_spawn"),
                        3 if timeout else timeout_seconds)
            except SupervisionFailure:
                rejected = True
            require(rejected == timeout, "namespace lifetime self-test returned the wrong test outcome")
            deadline = time.monotonic() + 5
            while _live_marker(marker) and time.monotonic() < deadline:
                time.sleep(0.05)
            require(not _live_marker(marker), "detached proposed descendant survived namespace teardown")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--actor-root", type=Path)
    parser.add_argument("--worker-root", type=Path)
    parser.add_argument("--worker-module")
    parser.add_argument("--worker-class")
    parser.add_argument("--worker-method")
    parser.add_argument("--local-test", action="store_true", help="development-only transport checks; never CI proof")
    args = parser.parse_args(argv)
    try:
        if args.actor_root:
            _actor(args.actor_root)
        elif args.worker_root:
            require(all((args.worker_module, args.worker_class, args.worker_method)), "incomplete worker identity")
            secret = bytes.fromhex(sys.stdin.buffer.read(64).decode("ascii"))
            sys.stdin.close()
            require(len(secret) == 32, "missing trusted completion key")
            identity = (args.worker_module, args.worker_class, args.worker_method)
            _worker_run(args.worker_root.resolve(), identity, local_test=args.local_test)
            mac = hmac.new(secret, ("PASS:" + ".".join(identity)).encode(), hashlib.sha256).hexdigest()
            print("trusted_completion=" + mac)
        else:
            require(args.root is not None, "missing frozen root")
            require(not args.local_test or os.environ.get("GITHUB_ACTIONS") != "true", "local-test mode cannot authorize CI")
            _self_test(args.python, args.timeout_seconds, local_test=args.local_test)
            _self_test_boundary_transport(args.python, args.timeout_seconds, local_test=args.local_test)
            _self_test_encoder_failure(args.python, args.timeout_seconds, local_test=args.local_test)
            if not args.local_test:
                _self_test_descendants(args.python, args.timeout_seconds)
            tests = expected_tests(args.root.resolve())
            for identity in tests:
                run_one(args.root.resolve(), args.python, identity, args.timeout_seconds, local_test=args.local_test)
            label = "LOCAL_TEST_ONLY" if args.local_test else "PASS"
            print(f"frozen_test_supervisor={label} tests={len(tests)}")
    except BaseException as exc:
        print(f"frozen_test_supervisor=FAIL reason={str(exc)!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
