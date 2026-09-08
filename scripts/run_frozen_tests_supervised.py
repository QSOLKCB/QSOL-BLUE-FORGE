#!/usr/bin/env python3
"""Final trusted supervisor hardening for cached launches and remote observation.

The reviewed round-3 entrypoint is retained byte-for-byte in a sibling module.
This layer closes cached native-process references, requires proposed source to
be unreadable from the trusted frozen worker, and makes Remote truth/str/repr
observe bounded actor-side behavior instead of trusted synthetic values.
"""
from __future__ import annotations

import contextlib
import importlib.util
import os
from pathlib import Path
import sys
import threading


_ROUND3 = Path(__file__).with_name("_run_frozen_tests_supervised_round3.py")
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


def _arm_process_method(function):
    def mediated(*args, **kwargs):
        with _trusted_process_launch():
            return function(*args, **kwargs)

    return mediated


def _hardened_test_importer(bridge):
    importer = _legacy_importer(bridge)
    facades = importer._blue_forge_facades
    process_proxy = facades["subprocess"]
    for name in ("run", "check_output", "check_call", "call", "Popen"):
        setattr(process_proxy, name, _arm_process_method(getattr(process_proxy, name)))
    return importer


# ---------------------------------------------------------------------------
# Proposed-source provenance
# ---------------------------------------------------------------------------
# The frozen/proposed workflow marks only the trust-critical oracle run with
# BLUE_FORGE_PRIVATE_PROPOSED_SOURCE=1. In that run the proposed blue_forge
# files are root:blueforge-rpc 0440: readable by the isolated actor account but
# not by the trusted blueforge-test worker. That makes read+compile("<string>")
# impossible regardless of caller-controlled co_filename metadata.
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


def _worker_run(root, identity, *, local_test=False):
    if (
        not local_test
        and os.environ.get("BLUE_FORGE_PRIVATE_PROPOSED_SOURCE") == "1"
    ):
        _require_private_proposed_source(Path(root))
    return _legacy_worker_run(root, identity, local_test=local_test)


# ---------------------------------------------------------------------------
# Remote observation
# ---------------------------------------------------------------------------
_SIZED_REMOTE_KINDS = frozenset(
    {
        "dict",
        "list",
        "tuple",
        "set",
        "frozenset",
        "dict_keys",
        "dict_values",
        "dict_items",
    }
)


def _remote_bool(self):
    kind = object.__getattribute__(self, "_kind")
    bridge = object.__getattribute__(self, "_bridge")
    if kind in _SIZED_REMOTE_KINDS:
        length = bridge.request("len", self)
        base.require(
            type(length) is int and 0 <= length <= base.MAX_GRAPH_NODES,
            "invalid proposed remote length",
        )
        return length != 0
    value = bridge.request("truth", self)
    base.require(type(value) is bool, "invalid proposed truth observation")
    return value


def _remote_render(self, template: str, label: str) -> str:
    bridge = object.__getattribute__(self, "_bridge")
    # str.format's !r/!s conversions invoke the actor object's actual repr/str
    # protocol without trusting a worker-side placeholder or the actor's mutable
    # builtins.repr/builtins.str names.
    formatter = bridge.request("getattr", template, "format")
    rendered = bridge.request("call", formatter, (self,), {})
    base.require(type(rendered) is str, f"invalid proposed {label} observation")
    try:
        byte_length = len(rendered.encode("utf-8"))
    except UnicodeError as exc:
        raise base.SupervisionFailure(
            f"proposed {label} is not valid UTF-8 text"
        ) from exc
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
base._Remote.__repr__ = _remote_repr
base._Remote.__str__ = _remote_str


def _cached_process_self_test():
    # pathlib imported os before the facade scope exists. This exact cached
    # reference must still hit the lower audit boundary and fail before launch.
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


def _subprocess_policy_self_test():
    _legacy_subprocess_self_test()
    _cached_process_self_test()


def _remote_observation_self_test():
    class FakeBridge:
        def request(self, action, *arguments):
            if action == "len":
                return 1
            if action == "export":
                raise base.SupervisionFailure(
                    "mapping-view truth incorrectly used actor export"
                )
            if action == "truth":
                return True
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
                return (
                    "actual-proposed-repr"
                    if formatter[1] == "{!r}"
                    else "actual-proposed-str"
                )
            raise base.SupervisionFailure(
                "unexpected remote observation self-test operation"
            )

    bridge = FakeBridge()
    view = base._Remote(bridge, 1, "dict_keys")
    base.require(bool(view), "nonempty mapping view observed as false")
    obj = base._Remote(bridge, 2, "object")
    base.require(
        repr(obj) == "actual-proposed-repr",
        "Remote repr remained a trusted synthetic placeholder",
    )
    base.require(
        str(obj) == "actual-proposed-str",
        "Remote str remained a trusted synthetic placeholder",
    )
    print("remote_representation=PASS mapping_view_truth=PASS")


def _final_boundary_self_test(
    python_bin, timeout_seconds, *, local_test=False
):
    _legacy_final_boundary_self_test(
        python_bin, timeout_seconds, local_test=local_test
    )
    # These are pure trusted-worker controls and add no actor startup, preserving
    # the existing fixed aggregate current-suite lifetime.
    _remote_observation_self_test()


# Round-3 and retained functions resolve these globals dynamically. Patch every
# effective importer/worker hook while preserving all prior checks.
round3._hardened_test_importer = _hardened_test_importer
round3.round2._hardened_test_importer = _hardened_test_importer
round3.round2.previous._test_importer = _hardened_test_importer
base._test_importer = _hardened_test_importer
base._worker_run = _worker_run
round3._subprocess_policy_self_test = _subprocess_policy_self_test
round3.round2.previous._self_test_subprocess_facade = _subprocess_policy_self_test
round3._final_boundary_self_test = _final_boundary_self_test
round3.round2.previous._self_test_dispatch_and_descriptors = _final_boundary_self_test

# Compatibility names used by the governed launcher/current-suite scheduler.
previous = round3.previous
_enumerate_module_parent = round3._enumerate_module_parent


def _main():
    return round3._main()


if __name__ == "__main__":
    raise SystemExit(_main())
