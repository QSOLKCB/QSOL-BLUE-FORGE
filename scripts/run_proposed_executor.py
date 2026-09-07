#!/usr/bin/env python3
"""Process-separated executor for the BLUE-FORGE supervised RPC bridge.

Only the transport parent owns broker-facing descriptors. Before creating the
proposed subinterpreter, its application child replaces stdin/stdout and closes
all other inherited descriptors except diagnostic stderr. Fixed-capacity
anonymous shared-memory mailboxes, synchronized by process-shared POSIX
semaphores, carry bounded observations; they are not file-descriptor channels.
The parent is non-dumpable, preventing same-UID /proc descriptor reopening.

Operation selection remains on the subinterpreter control thread. Proposed
calls enter a fresh transport-free wrapper whose arguments are locals, not a
shared dispatch dictionary. Namespace mutation fails closed before an observation
is accepted. Kernel isolation and the existing tracing/thread guards remain
required. This is tested observation isolation, not universal Python attestation.
"""
from __future__ import annotations

import ctypes
import errno
import marshal
import mmap
import os
from pathlib import Path
import resource
import signal
import sys
import time

MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_OPERATIONS = 4096
OPERATION_SECONDS = 15.0
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

_bf_BaseException = BaseException
_bf_Exception = Exception
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
_bf_getitem = operator.getitem
_bf_setitem = operator.setitem
_bf_delitem = operator.delitem
_bf_FunctionType = types.FunctionType
_bf_start_new_thread = _thread.start_new_thread
_bf_sleep = time.sleep
_bf_monotonic = time.monotonic
_bf_marshal_loads = marshal.loads
_bf_marshal_dumps = marshal.dumps
_bf_modules = sys.modules
_bf_actual_main = _bf_modules["__main__"]
_bf_inert_main = types.ModuleType("__main__")
_bf_os_read = os.read
_bf_set_blocking = os.set_blocking
_bf_gettrace = sys.gettrace
_bf_getprofile = sys.getprofile

_spec = importlib.util.spec_from_file_location(
    "_blue_forge_executor_support", _BF_SUPPORT_PATH
)
if _spec is None or _spec.loader is None:
    raise _bf_RuntimeError("trusted executor implementation support is unavailable")
_support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_support)
_bf_graph_decoder = _support._GraphDecoder
_bf_encode_data = _support._encode_data
_bf_require = _support.require
_bf_max_nodes = _support.MAX_GRAPH_NODES
_bf_islice = _support.itertools.islice
_bf_deepcopy = _support.copy.deepcopy
_bf_replace = _support.dataclasses.replace
_bf_import_module = _support.importlib.import_module
_bf_temporary_directory = _support.tempfile.TemporaryDirectory
_bf_Popen = _support.subprocess.Popen
_bf_PIPE = _support.subprocess.PIPE
_bf_DefaultSelector = _support.selectors.DefaultSelector
_bf_EVENT_READ = _support.selectors.EVENT_READ
_bf_kill_group = _support._kill_group
_bf_settrace_all_threads = _support.threading.settrace_all_threads
_bf_setprofile_all_threads = _support.threading.setprofile_all_threads


def _bf_run_cli_bounded(command, root, environment):
    process = _bf_Popen(command, cwd=root, env=environment,
                        start_new_session=True, stdout=_bf_PIPE, stderr=_bf_PIPE)
    outputs = [bytearray(), bytearray()]
    streams = (process.stdout, process.stderr)
    selector = _bf_DefaultSelector()
    deadline = _bf_monotonic() + 10.0
    try:
        for index, stream in enumerate(streams):
            _bf_set_blocking(stream.fileno(), False)
            selector.register(stream, _bf_EVENT_READ, index)
        while selector.get_map():
            remaining = deadline - _bf_monotonic()
            if remaining <= 0:
                raise _bf_RuntimeError("CLI lifetime budget exceeded")
            for key, _mask in selector.select(min(0.05, remaining)):
                try:
                    chunk = _bf_os_read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                destination = outputs[key.data]
                if _bf_len(destination) + _bf_len(chunk) > _BF_MAX_FRAME_BYTES:
                    raise _bf_RuntimeError("CLI output budget exceeded")
                destination.extend(chunk)
        remaining = deadline - _bf_monotonic()
        if remaining <= 0:
            raise _bf_RuntimeError("CLI lifetime budget exceeded")
        rc = process.wait(timeout=remaining)
        return rc, _bf_bytes(outputs[0]), _bf_bytes(outputs[1])
    finally:
        _bf_kill_group(process)
        selector.close()
        for stream in streams:
            if stream is not None and not stream.closed:
                stream.close()


# Retain the existing thread/import/tracing restrictions and bootstrap controls.
def _bf_make_execution_guard(blocked, error_type):
    allowed = [None]
    def arm(target):
        if allowed[0] is not None:
            raise error_type("executor thread permission is already armed")
        allowed[0] = target
    def guard(event, args):
        if event == "import" and args and type(args[0]) is str and args[0] in blocked:
            raise error_type("executor bootstrap module import is blocked")
        if event in {"sys.settrace", "sys.setprofile"}:
            raise error_type("proposed tracing or profiling is blocked")
        if event == "_thread.start_new_thread":
            target = args[0] if args else None
            if target is not allowed[0]:
                raise error_type("proposed thread creation is blocked")
            allowed[0] = None
    return arm, guard

_bf_arm_thread_start, _bf_execution_guard = _bf_make_execution_guard(
    frozenset({"_thread", "threading", "ctypes", "_ctypes", "gc",
               "_xxsubinterpreters", "_testcapi", "_testinternalcapi"}),
    _bf_RuntimeError,
)
sys.addaudithook(_bf_execution_guard)
del _bf_execution_guard, _bf_make_execution_guard


def _bf_thread_guard_self_test(destination):
    try:
        _bf_start_new_thread(_bf_sleep, (0.01,))
    except _bf_BaseException:
        destination.append(True)
    else:
        destination.append(False)

_bf_thread_guard_probe = _bf_deque()
_bf_arm_thread_start(_bf_thread_guard_self_test)
_bf_start_new_thread(_bf_thread_guard_self_test, (_bf_thread_guard_probe,))
_bf_thread_guard_deadline = _bf_monotonic() + 2.0
while not _bf_thread_guard_probe and _bf_monotonic() < _bf_thread_guard_deadline:
    _bf_sleep(0.001)
if not _bf_thread_guard_probe or _bf_thread_guard_probe.popleft() is not True:
    raise _bf_RuntimeError("proposed thread audit self-test failed")
del _bf_thread_guard_self_test, _bf_thread_guard_probe, _bf_thread_guard_deadline


def _bf_trace_probe(*args):
    return _bf_trace_probe

def _bf_ignore_expected_unraisable(unraisable):
    del unraisable

_bf_saved_unraisablehook = sys.unraisablehook
sys.unraisablehook = _bf_ignore_expected_unraisable
try:
    for _bf_trace_setter, _bf_trace_getter, _bf_hook_attr, _bf_label in (
        (_bf_settrace_all_threads, _bf_gettrace, "_trace_hook", "trace"),
        (_bf_setprofile_all_threads, _bf_getprofile, "_profile_hook", "profile"),
    ):
        if _bf_trace_getter() is not None:
            raise _bf_RuntimeError("executor control thread already has a " + _bf_label + " callback")
        try:
            _bf_trace_setter(_bf_trace_probe)
        except _bf_BaseException:
            pass
        if _bf_trace_getter() is not None:
            raise _bf_RuntimeError("proposed cross-thread " + _bf_label + " audit self-test failed")
        _bf_object.__setattr__(_support.threading, _bf_hook_attr, None)
finally:
    sys.unraisablehook = _bf_saved_unraisablehook

del (_bf_trace_probe, _bf_ignore_expected_unraisable, _bf_saved_unraisablehook,
     _bf_trace_setter, _bf_trace_getter, _bf_hook_attr, _bf_label)
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

# Neither code object uses globals. A new namespace and function are created
# per invocation; the control thread independently checks the namespace later.
# In particular, there is no persistent getattr_fn/import_module dispatch map.
_bf_compile_namespace = {"__builtins__": {}}
exec(compile(r'''
def execute_action(function, arguments, keywords, exception_type, str_type):
    try:
        return (True, function(*arguments, **keywords), "")
    except exception_type as exc:
        try:
            message = str_type(exc)
        except exception_type:
            message = "exception message unavailable"
        return (False, exc, message)

def bounded_iterate(value, iter_fn, tuple_fn, islice_fn, len_fn, limit, error_type):
    items = tuple_fn(islice_fn(iter_fn(value), limit + 1))
    if len_fn(items) > limit:
        raise error_type("executor iteration budget exceeded")
    return items
''', "<blue-forge-proposed-operation>", "exec"), _bf_compile_namespace)
_bf_call_code = _bf_compile_namespace["execute_action"].__code__
_bf_iterate_code = _bf_compile_namespace["bounded_iterate"].__code__
del _bf_compile_namespace

sys.path.insert(0, _bf_str(_BF_ROOT))
os.chdir(_BF_ROOT)
sys.stdout = sys.stderr
sys.__stdout__ = sys.stderr
_bf_handles = {}
_bf_identities = {}
_bf_exported_validation = None
_bf_exported_blue = None
_bf_operations = 0


def _bf_fresh_function(code):
    empty_builtins = {}
    namespace = {"__builtins__": empty_builtins}
    return _bf_FunctionType(code, namespace), (namespace, empty_builtins)


def _bf_check_namespace(record):
    namespace, empty_builtins = record
    if _bf_len(namespace) != 1:
        raise _bf_RuntimeError("proposed operation mutated its invocation namespace")
    key = _bf_next(_bf_iter(namespace))
    if (_bf_type(key) is not _bf_str or key != "__builtins__"
            or namespace[key] is not empty_builtins or _bf_len(empty_builtins) != 0):
        raise _bf_RuntimeError("proposed operation mutated its invocation namespace")


def _bf_select_operation(action, arguments):
    # This function runs ONLY on the private control thread, never as an
    # ancestor of proposed Python. Return native operations or existing API
    # functions; no reference to this dispatch function enters their globals.
    plain = {
        "module": _bf_import_module, "getattr": _bf_getattr,
        "setattr": _bf_setattr, "delattr": _bf_delattr,
        "getitem": _bf_getitem, "setitem": _bf_setitem,
        "delitem": _bf_delitem, "truth": _bf_bool,
        "len": _bf_len, "next": _bf_next, "deepcopy": _bf_deepcopy,
        "object_setattr": _bf_object.__setattr__,
    }
    if action in plain:
        return plain[action], arguments, {}, None
    if action == "call":
        function, args, kwargs = arguments
        return function, args, kwargs, None
    if action == "replace":
        return _bf_replace, (arguments[0],), arguments[1], None
    if action == "iterate":
        function, record = _bf_fresh_function(_bf_iterate_code)
        args = (arguments[0], _bf_iter, _bf_tuple, _bf_islice, _bf_len,
                _bf_max_nodes, _bf_RuntimeError)
        return function, args, {}, record
    if action == "export":
        return _bf_getitem, (arguments, 0), {}, None
    raise _bf_RuntimeError("unknown executor operation")


def _bf_detached_execute(action, arguments):
    function, args, kwargs, extra_record = _bf_select_operation(action, arguments)
    wrapper, record = _bf_fresh_function(_bf_call_code)
    outcomes = _bf_deque()
    invocation = _bf_partial(wrapper, function, args, kwargs, _bf_BaseException, _bf_str)
    calls = _bf_map(_bf_methodcaller("__call__"), (invocation,))
    target = _bf_methodcaller("extend", calls)
    _bf_modules["__main__"] = _bf_inert_main
    try:
        _bf_arm_thread_start(target)
        _bf_start_new_thread(target, (outcomes,))
        while not outcomes:
            _bf_sleep(0.001)
    finally:
        _bf_modules["__main__"] = _bf_actual_main
    # Validate before consuming either a value or an exception from the call.
    _bf_check_namespace(record)
    if extra_record is not None:
        _bf_check_namespace(extra_record)
    if _bf_len(outcomes) != 1:
        raise _bf_RuntimeError("detached executor produced an invalid outcome count")
    outcome = outcomes.popleft()
    if (_bf_type(outcome) is not _bf_tuple or _bf_len(outcome) != 3
            or _bf_type(outcome[0]) is not _bf_bool):
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


def _bf_named_exception(candidate, expected_name, required_base=None):
    if _bf_type(candidate) is not _bf_type:
        return False
    mro = _bf_type.__getattribute__(candidate, "__mro__")
    module_name = _bf_type.__getattribute__(candidate, "__module__")
    type_name = _bf_type.__getattribute__(candidate, "__name__")
    if module_name not in {"blue_forge", "blue_forge.core"} or type_name != expected_name:
        return False
    if _bf_Exception not in mro or candidate is _bf_Exception:
        return False
    if required_base is not None and (candidate is required_base or required_base not in mro):
        return False
    return True

if _bf_named_exception(_bf_object, "ValidationError"):
    raise _bf_RuntimeError("executor exception export hierarchy self-test failed")


def _bf_capture_exports():
    global _bf_exported_validation, _bf_exported_blue
    package = _bf_modules.get("blue_forge")
    if package is None:
        return
    namespace = _bf_object.__getattribute__(package, "__dict__")
    validation = namespace.get("ValidationError")
    blue = namespace.get("BlueForgeError")
    if blue is not None:
        _bf_require(_bf_named_exception(blue, "BlueForgeError"),
                    "proposed BlueForgeError export has an invalid exception hierarchy")
    if validation is not None:
        _bf_require(_bf_named_exception(validation, "ValidationError", blue),
                    "proposed ValidationError export has an invalid exception hierarchy")
    _bf_exported_blue = blue
    _bf_exported_validation = validation


def _bf_exception_key(exc):
    cls = _bf_type(exc)
    mro = _bf_type.__getattribute__(cls, "__mro__")
    if _bf_exported_validation is not None and _bf_any(item is _bf_exported_validation for item in mro):
        return "blue_forge.ValidationError"
    if _bf_exported_blue is not None and _bf_any(item is _bf_exported_blue for item in mro):
        return "blue_forge.BlueForgeError"
    exact = {
        AssertionError: "builtins.AssertionError", AttributeError: "builtins.AttributeError",
        TypeError: "builtins.TypeError", ValueError: "builtins.ValueError",
        KeyError: "builtins.KeyError", StopIteration: "builtins.StopIteration",
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
    if action == "cli":
        # CLI orchestration never enters an in-process proposed call frame.
        try:
            cli_args, case_bytes, environment = arguments
            with _bf_temporary_directory() as temp:
                path = Path(temp) / "case.json"
                path.write_bytes(case_bytes)
                command = [sys.executable, "-m", "blue_forge", cli_args[0], _bf_str(path)]
                observed = _bf_run_cli_bounded(command, _BF_ROOT, environment)
            ok, message = True, ""
        except _bf_BaseException as exc:
            ok, observed, message = False, exc, _bf_str(exc)
    else:
        ok, observed, message = _bf_detached_execute(action, arguments)
    if ok:
        if action == "module":
            _bf_capture_exports()
        observation = {"ok": True, "value": (
            ["data", _bf_encode_data(_bf_encode_data(observed))]
            if action == "export" else _bf_result(observed))}
    else:
        observation = {"ok": False, "error": _bf_exception_key(observed), "message": message}
    states = {}
    for key in request.get("sync", []):
        if key in decoder.cache:
            states[_bf_str(key)] = _bf_encode_data(
                _bf_object.__getattribute__(decoder.cache[key], "__dict__"))
    observation["states"] = states
    payload = _bf_marshal_dumps(observation, 4)
    _bf_require(_bf_len(payload) <= _BF_MAX_FRAME_BYTES,
                "executor subinterpreter response exceeds byte budget")
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
    size = int.from_bytes(_read_exact(stream, 8), "big")
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
    for field, expected in (("sequence", int), ("action", str), ("nodes", list),
                            ("arguments", list), ("sync", list)):
        if type(request.get(field)) is not expected:
            raise RuntimeError("invalid executor request field: " + field)
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
    ok, states = observation.get("ok"), observation.get("states")
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
        response["error"], response["message"] = observation["error"], observation["message"]
    return response


def _native_api():
    if sys.platform != "linux" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError("executor requires 64-bit Linux process isolation")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    libc.prctl.restype = ctypes.c_int
    libc.sem_init.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint]
    libc.sem_init.restype = ctypes.c_int
    for name in ("sem_trywait", "sem_post", "sem_destroy"):
        function = getattr(libc, name)
        function.argtypes = [ctypes.c_void_p]
        function.restype = ctypes.c_int
    return libc


def _prctl(libc, operation: int, argument: int = 0) -> int:
    result = libc.prctl(operation, argument, 0, 0, 0)
    if result < 0:
        raise OSError(ctypes.get_errno(), "executor process protection failed")
    return result


class _Mailbox:
    """One bounded slot; native process-shared semaphores, no backing fd.

    Linux's 64-bit sem_t fits in an aligned 64-byte reservation. Neither the
    mappings nor their native pointers are shared into the proposed interpreter.
    Semaphore publication supplies the inter-process memory-ordering boundary.
    """
    HEADER = 128
    DATA = 144

    def __init__(self, libc):
        self.libc = libc
        self.storage = mmap.mmap(-1, self.DATA + MAX_FRAME_BYTES)
        self.address = ctypes.addressof(ctypes.c_char.from_buffer(self.storage))
        self.initialized = []
        try:
            for offset, value in ((0, 1), (64, 0)):
                if libc.sem_init(self.address + offset, 1, value) != 0:
                    raise OSError(ctypes.get_errno(), "executor semaphore setup failed")
                self.initialized.append(offset)
        except BaseException:
            self.close()
            raise

    def _wait(self, offset, deadline, alive):
        while True:
            if alive is not None:
                alive()
            if self.libc.sem_trywait(self.address + offset) == 0:
                return
            error = ctypes.get_errno()
            if error not in (errno.EAGAIN, errno.EINTR):
                raise OSError(error, "executor mailbox wait failed")
            if time.monotonic() >= deadline:
                raise RuntimeError("executor mailbox lifetime budget exceeded")
            time.sleep(0.0005)

    def _post(self, offset):
        if self.libc.sem_post(self.address + offset) != 0:
            raise OSError(ctypes.get_errno(), "executor mailbox publication failed")

    def send(self, generation, payload, *, seconds=OPERATION_SECONDS, alive=None):
        if type(payload) is not bytes or len(payload) > MAX_FRAME_BYTES:
            raise RuntimeError("executor mailbox byte budget exceeded")
        if type(generation) is not int or not 0 <= generation <= MAX_OPERATIONS:
            raise RuntimeError("invalid executor mailbox generation")
        self._wait(0, time.monotonic() + seconds, alive)
        self.storage[self.DATA:self.DATA + len(payload)] = payload
        self.storage[self.HEADER:self.DATA] = (
            generation.to_bytes(8, "big") + len(payload).to_bytes(8, "big"))
        self._post(64)

    def receive(self, *, seconds=OPERATION_SECONDS, alive=None):
        self._wait(64, time.monotonic() + seconds, alive)
        header = self.storage[self.HEADER:self.DATA]
        generation, size = int.from_bytes(header[:8], "big"), int.from_bytes(header[8:], "big")
        if generation > MAX_OPERATIONS or size > MAX_FRAME_BYTES:
            raise RuntimeError("invalid executor mailbox header")
        payload = self.storage[self.DATA:self.DATA + size]
        self._post(0)
        return generation, payload

    def close(self):
        if self.storage.closed:
            return
        for offset in self.initialized:
            self.libc.sem_destroy(self.address + offset)
        self.initialized.clear()
        self.storage.close()


def _remove_inherited_transport(libc, parent_pid):
    _prctl(libc, 1, signal.SIGKILL)  # PR_SET_PDEATHSIG
    if os.getppid() != parent_pid:
        raise RuntimeError("executor transport parent disappeared during fork")
    # There is no fallback that leaves the upstream pipe reachable by proposed
    # Python. Anonymous mailboxes have no fd to preserve here.
    null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.dup2(null, 0)
        os.dup2(2, 1)
    finally:
        if null > 2:
            os.close(null)
    limit = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if limit == resource.RLIM_INFINITY:
        raise RuntimeError("executor descriptor ceiling is unavailable")
    os.closerange(3, limit)
    sys.stdout = sys.stderr
    sys.__stdout__ = sys.stderr
    # Actual descriptor identity, not just replacement Python stream objects.
    if os.fstat(1) != os.fstat(2):
        raise RuntimeError("executor diagnostic descriptor separation failed")


def _application_loop(root, support_path, requests, responses):
    import _xxsubinterpreters as interpreters
    loads, dumps = marshal.loads, marshal.dumps
    interpreter = interpreters.create()
    bootstrap = (_SUBINTERPRETER_BOOTSTRAP
                 .replace("__ROOT__", repr(str(root)))
                 .replace("__SUPPORT__", repr(str(support_path)))
                 .replace("__MAX_FRAME_BYTES__", str(MAX_FRAME_BYTES))
                 .replace("__MAX_OPERATIONS__", str(MAX_OPERATIONS))
                 .replace("__RESPONSE_PREFIX__", repr(_RESPONSE_PREFIX)))
    try:
        interpreters.run_string(interpreter, bootstrap)
        responses.send(0, b"executor-process-ready")
        for expected in range(1, MAX_OPERATIONS + 1):
            generation, payload = requests.receive(seconds=35.0)
            if generation != expected:
                raise RuntimeError("executor application generation mismatch")
            try:
                interpreters.run_string(interpreter, "_bf_process_one(_bf_request)",
                                        {"_bf_request": payload})
            except interpreters.RunFailedError as exc:
                observation = _decode_runfailed(exc, loads)
            else:
                raise RuntimeError("proposed subinterpreter omitted response envelope")
            responses.send(generation, dumps(observation, 4))
        raise RuntimeError("executor operation budget exceeded")
    finally:
        try:
            interpreters.destroy(interpreter)
        except RuntimeError:
            pass


class _Application:
    def __init__(self, root, support_path):
        libc = _native_api()
        _prctl(libc, 4, 0)  # PR_SET_DUMPABLE: deny reopening parent fds via /proc.
        if _prctl(libc, 3) != 0:  # PR_GET_DUMPABLE
            raise RuntimeError("executor transport is still dumpable")
        self.pid = None
        self.requests = _Mailbox(libc)
        try:
            self.responses = _Mailbox(libc)
        except BaseException:
            self.requests.close()
            raise
        parent_pid = os.getpid()
        try:
            pid = os.fork()  # Before any subinterpreter or helper thread exists.
            if pid == 0:
                try:
                    _remove_inherited_transport(libc, parent_pid)
                    _application_loop(root, support_path, self.requests, self.responses)
                except BaseException as exc:
                    print(f"executor_application=FAIL reason={str(exc)!r}", file=sys.stderr)
                finally:
                    os._exit(1)
            self.pid = pid
            if self.responses.receive(alive=self._alive) != (0, b"executor-process-ready"):
                raise RuntimeError("executor application omitted bootstrap completion")
        except BaseException:
            self.close()
            raise

    def _alive(self):
        if self.pid is None:
            raise RuntimeError("executor application is not running")
        waited, status = os.waitpid(self.pid, os.WNOHANG)
        if waited:
            self.pid = None
            raise RuntimeError(f"executor application exited without completion: status={status}")

    def observe(self, generation, request):
        self.requests.send(generation, request, alive=self._alive)
        observed_generation, payload = self.responses.receive(alive=self._alive)
        if observed_generation != generation:
            raise RuntimeError("executor observation generation mismatch")
        return marshal.loads(payload)

    def close(self):
        if self.pid is not None:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(self.pid, 0)
            self.pid = None
        self.requests.close()
        self.responses.close()


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
    loads, dumps = marshal.loads, marshal.dumps
    # TextIOWrapper owns and closes its binary buffer on finalization. Keep the
    # owning streams alive for the whole transport loop, not just their buffers,
    # while both public stdout names are redirected to diagnostics. The child
    # still replaces the actual descriptors before importing proposed code.
    transport_stdin, transport_stdout = sys.stdin, sys.stdout
    wire_in, wire_out = transport_stdin.buffer, transport_stdout.buffer
    sys.stdout = sys.stderr
    sys.__stdout__ = sys.stderr
    application = _Application(root, support_path)
    try:
        for generation in range(1, MAX_OPERATIONS + 1):
            try:
                request = _validate_request(_read_frame(wire_in, loads))
            except EOFError:
                return 0
            payload = dumps({key: request[key] for key in ("action", "nodes", "arguments", "sync")}, 4)
            observation = application.observe(generation, payload)
            # Neither this process nor the broker imports proposed code.
            response = _response_from_observation(request["sequence"], observation)
            _write_frame(wire_out, response, dumps)
        raise RuntimeError("executor operation budget exceeded")
    finally:
        application.close()


if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException as exc:
        print(f"proposed_executor=FAIL reason={str(exc)!r}", file=sys.stderr)
        exit_code = 1
    raise SystemExit(exit_code)
