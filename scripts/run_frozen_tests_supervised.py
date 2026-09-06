#!/usr/bin/env python3
"""Trusted supervisor for frozen tests executed against proposed source.

Frozen unittest code and assertion accounting execute only in the trusted worker
interpreter. Calls into proposed ``blue_forge`` are proxied into fresh isolated
Python processes, so proposed code cannot mutate trusted unittest classes, test
module globals, or worker result accounting.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from typing import Any


class SupervisionFailure(RuntimeError):
    pass


class BlueForgeError(Exception):
    pass


class ValidationError(BlueForgeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SupervisionFailure(message)


def _is_testcase_base(node: ast.expr) -> bool:
    return (isinstance(node, ast.Name) and node.id == "TestCase") or (
        isinstance(node, ast.Attribute) and node.attr == "TestCase"
    )


def expected_tests(root: Path) -> list[tuple[str, str, str]]:
    tests_root = root / "tests"
    require(tests_root.is_dir(), f"missing frozen tests directory: {tests_root}")
    expected: list[tuple[str, str, str]] = []
    for path in sorted(tests_root.glob("test*.py")):
        require(path.is_file() and not path.is_symlink(), f"invalid frozen test path: {path}")
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise SupervisionFailure(f"cannot statically inspect frozen test {path}: {exc}") from exc
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or not any(
                _is_testcase_base(base) for base in node.bases
            ):
                continue
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                    expected.append((path.stem, node.name, item.name))
    require(bool(expected), "no frozen unittest methods discovered")
    require(len(set(expected)) == len(expected), "duplicate frozen unittest identity discovered")
    return expected


_MAX_RPC_BYTES = 2 * 1024 * 1024

_PROPOSED_RPC_RUNNER = r'''
import base64 as _base64
import builtins as _builtins
import hashlib as _hashlib
import json as _json
import os as _os
import posix as _posix
import sys as _sys
import types as _types

_root = __ROOT__
_action = __ACTION__
_request_text = __REQUEST__
_response_path = __RESPONSE_PATH__
_secret = __SECRET__
_trusted_json_loads = _json.loads
_trusted_json_dumps = _json.dumps
_trusted_sha256 = _hashlib.sha256
_trusted_open = _builtins.open
_trusted_base_exception = BaseException
_trusted_type = type
_trusted_tuple = tuple
_trusted_frozenset = frozenset
_trusted_object_getattribute = object.__getattribute__
_request = _trusted_json_loads(_request_text)
_extra = {}


def _blocked(*args, **kwargs):
    raise RuntimeError("proposed RPC attempted to cross the trusted process boundary")


_os._exit = _blocked
_posix._exit = _blocked
for _name in (
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "fork", "forkpty", "posix_spawn", "posix_spawnp",
):
    if hasattr(_os, _name):
        setattr(_os, _name, _blocked)
    if hasattr(_posix, _name):
        setattr(_posix, _name, _blocked)
for _name in ("_getframe", "_current_frames", "settrace", "setprofile"):
    if hasattr(_sys, _name):
        setattr(_sys, _name, _blocked)
for _module_name in ("ctypes", "_ctypes", "gc"):
    _sys.modules[_module_name] = None
_sys.path.insert(0, _root)
_sys.modules["__main__"] = _types.ModuleType("__main__")


def _case_to_material(_core, _case):
    _p = _trusted_object_getattribute(_case, "proposal")
    _v = _trusted_object_getattribute(_case, "verification")
    _original = _trusted_object_getattribute(_v, "original")
    _variants = _trusted_object_getattribute(_v, "variants")
    _benign = _trusted_object_getattribute(_v, "benign_controls")

    def _body(_item):
        return {
            "kind": _trusted_object_getattribute(_item, "kind"),
            "before": _trusted_object_getattribute(_item, "before"),
            "after": _trusted_object_getattribute(_item, "after"),
            "provenance": _trusted_object_getattribute(_item, "provenance"),
            "source_sha256": _trusted_object_getattribute(_item, "source_sha256"),
            "reference_engine_sha256": _trusted_object_getattribute(_item, "reference_engine_sha256"),
            "replay_engine_sha256": _trusted_object_getattribute(_item, "replay_engine_sha256"),
            "reference_result_sha256": _trusted_object_getattribute(_item, "reference_result_sha256"),
            "replay_result_sha256": _trusted_object_getattribute(_item, "replay_result_sha256"),
        }

    _pd = _trusted_object_getattribute(_p, "decision")
    _vd = _trusted_object_getattribute(_v, "decision")
    return {
        "schema": _core.CASE_SCHEMA,
        "contract": _core.CONTRACT,
        "case_id": _trusted_object_getattribute(_case, "case_id"),
        "invariant_id": _trusted_object_getattribute(_case, "invariant_id"),
        "attack_class": _trusted_object_getattribute(_case, "attack_class"),
        "proposal": {
            "producer": _trusted_object_getattribute(_p, "producer"),
            "mitigation_id": _trusted_object_getattribute(_p, "mitigation_id"),
            "decision": _trusted_object_getattribute(_pd, "value"),
            "pre_mitigation_authority": sorted(_trusted_object_getattribute(_p, "pre_mitigation_authority")),
            "requested_authority": sorted(_trusted_object_getattribute(_p, "requested_authority")),
            "policy_authority": sorted(_trusted_object_getattribute(_p, "policy_authority")),
        },
        "verification": {
            "producer": _trusted_object_getattribute(_v, "producer"),
            "decision": _trusted_object_getattribute(_vd, "value"),
            "observed_authority": sorted(_trusted_object_getattribute(_v, "observed_authority")),
            "original": {_trusted_object_getattribute(_original, "evidence_id"): _body(_original)},
            "variants": {_trusted_object_getattribute(_i, "evidence_id"): _body(_i) for _i in _variants},
            "benign_controls": {_trusted_object_getattribute(_i, "evidence_id"): _body(_i) for _i in _benign},
            "reference_result_sha256": _trusted_object_getattribute(_v, "reference_result_sha256"),
            "candidate_result_sha256": _trusted_object_getattribute(_v, "candidate_result_sha256"),
        },
    }


def _direct_case(_core, _m):
    def _ev(_eid, _b):
        return _core.Evidence(
            evidence_id=_eid,
            kind=_b["kind"],
            before=_b["before"],
            after=_b["after"],
            provenance=_b["provenance"],
            source_sha256=_b["source_sha256"],
            reference_engine_sha256=_b["reference_engine_sha256"],
            replay_engine_sha256=_b["replay_engine_sha256"],
            reference_result_sha256=_b["reference_result_sha256"],
            replay_result_sha256=_b["replay_result_sha256"],
        )

    _p = _m["proposal"]
    _v = _m["verification"]
    _oid, _ob = next(iter(_v["original"].items()))
    return _core.HardeningCase(
        case_id=_m["case_id"],
        invariant_id=_m["invariant_id"],
        attack_class=_m["attack_class"],
        proposal=_core.Proposal(
            producer=_p["producer"],
            mitigation_id=_p["mitigation_id"],
            decision=_core.Decision(_p["decision"]),
            pre_mitigation_authority=_trusted_frozenset(_p["pre_mitigation_authority"]),
            requested_authority=_trusted_frozenset(_p["requested_authority"]),
            policy_authority=_trusted_frozenset(_p["policy_authority"]),
        ),
        verification=_core.Verification(
            producer=_v["producer"],
            decision=_core.Decision(_v["decision"]),
            observed_authority=_trusted_frozenset(_v["observed_authority"]),
            original=_ev(_oid, _ob),
            variants=_trusted_tuple(_ev(_eid, _b) for _eid, _b in _v["variants"].items()),
            benign_controls=_trusted_tuple(_ev(_eid, _b) for _eid, _b in _v["benign_controls"].items()),
            reference_result_sha256=_v["reference_result_sha256"],
            candidate_result_sha256=_v["candidate_result_sha256"],
        ),
    )


try:
    import blue_forge as _bf
    import blue_forge.core as _core

    if _action == "probe":
        _value = getattr(_bf, "SENTINEL", None)
    elif _action == "case_from_dict":
        _value = _case_to_material(_core, _bf.HardeningCase.from_dict(_request["value"]))
    elif _action == "evaluate":
        _value = _bf.evaluate(_direct_case(_core, _request["case"])).payload
    elif _action == "regression_record":
        _case = _direct_case(_core, _request["case"])
        _origin = _direct_case(_core, _request["result_origin"])
        _value = _bf.regression_record(_case, _bf.evaluate(_origin))
    elif _action == "loads_strict":
        _value = _bf.loads_strict(_request["text"])
    elif _action == "canonical_text":
        _value = _bf.canonical_text(_request["value"])
    elif _action == "canonical_bytes":
        _value = {"b64": _base64.b64encode(_bf.canonical_bytes(_request["value"])).decode("ascii")}
    elif _action == "digest":
        _value = _bf.digest(_request["value"])
    elif _action == "construct_result":
        _result = _bf.HardeningResult(_request["value"])
        _value = {
            "payload": _result.payload,
            "hardened": bool(_result.hardened),
            "receipt_sha256": _result.receipt_sha256,
        }
    elif _action == "cli_load":
        import io as _io
        import blue_forge.cli as _cli
        _data = _base64.b64decode(_request["payload_b64"].encode("ascii"))
        _box = {"requested": None}

        class _FakePath:
            def open(self, mode):
                if mode != "rb":
                    raise AssertionError(mode)
                _outer = _box

                class _Stream(_io.BytesIO):
                    def read(self, size=-1):
                        _outer["requested"] = size
                        return super().read(size)

                return _Stream(_data)

        try:
            _loaded = _cli._load(_FakePath())
            _value = {
                "requested": _box["requested"],
                "case": _case_to_material(_core, _loaded),
            }
        except _trusted_base_exception:
            _extra["requested"] = _box["requested"]
            raise
    else:
        raise RuntimeError("unsupported proposed RPC action")

    _response = {"ok": True, "value": _value, "extra": _extra}
except _trusted_base_exception as _exc:
    _response = {
        "ok": False,
        "error_type": _trusted_type(_exc).__name__,
        "error_module": _trusted_type(_exc).__module__,
        "message": str(_exc),
        "extra": _extra,
    }

_message = _trusted_json_dumps(
    _response,
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
)
_mac = _trusted_sha256((_secret + ":" + _message).encode("utf-8")).hexdigest()
_envelope = _trusted_json_dumps(
    {"message": _message, "mac": _mac},
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
)
with _trusted_open(_response_path, "w", encoding="utf-8") as _handle:
    _handle.write(_envelope)
'''


def _rpc_proposed(root: Path, action: str, payload: Any) -> tuple[Any, dict[str, Any]]:
    request_text = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    secret = secrets.token_hex(32)
    with tempfile.TemporaryDirectory(prefix="blue-forge-proposed-rpc-") as temp:
        temp_root = Path(temp)
        request_path = temp_root / "request.json"
        response_path = temp_root / "response.json"
        request_path.write_text(request_text, encoding="utf-8")
        command = [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--rpc-root", str(root),
            "--rpc-action", action,
            "--rpc-request", str(request_path),
            "--rpc-response", str(response_path),
        ]
        rc, diagnostic, timed_out = _run_process_bounded(
            command,
            cwd=root,
            env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
            timeout_seconds=15,
            input_bytes=secret.encode("ascii"),
        )
        require(not timed_out, f"proposed RPC timed out: {action}\n{diagnostic}")
        require(rc == 0, f"proposed RPC process failed: {action}: rc={rc}\n{diagnostic}")
        require(response_path.is_file(), f"proposed RPC produced no trusted response: {action}")
        require(
            response_path.stat().st_size <= _MAX_RPC_BYTES,
            f"proposed RPC response exceeds {_MAX_RPC_BYTES} bytes",
        )
        try:
            envelope = json.loads(response_path.read_text(encoding="utf-8"))
            message = envelope["message"]
            mac = envelope["mac"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise SupervisionFailure(f"proposed RPC response is malformed: {action}: {exc}") from exc

    expected_mac = hashlib.sha256((secret + ":" + message).encode("utf-8")).hexdigest()
    require(
        isinstance(mac, str) and secrets.compare_digest(mac, expected_mac),
        f"proposed RPC response authentication failed: {action}",
    )
    try:
        response = json.loads(message)
    except json.JSONDecodeError as exc:
        raise SupervisionFailure(f"proposed RPC signed response is invalid JSON: {action}") from exc

    extra = response.get("extra") if isinstance(response.get("extra"), dict) else {}
    if response.get("ok") is True:
        return response.get("value"), extra

    text = str(response.get("message", "proposed BLUE-FORGE call failed"))
    kind = response.get("error_type")
    if kind in {"ValidationError", "BlueForgeError"}:
        error: Exception = ValidationError(text)
    elif kind == "AssertionError":
        error = AssertionError(text)
    else:
        error = BlueForgeError(text)
    setattr(error, "_blue_forge_extra", extra)
    raise error


def _rpc_child(root: Path, action: str, request_path: Path, response_path: Path) -> None:
    secret = sys.stdin.buffer.read(128).decode("ascii")
    try:
        sys.stdin.close()
    except OSError:
        pass
    require(bool(secret), "trusted RPC secret was not supplied")
    try:
        request_text = request_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SupervisionFailure(f"cannot read trusted RPC request: {exc}") from exc

    script = (
        _PROPOSED_RPC_RUNNER
        .replace("__ROOT__", repr(str(root.resolve())))
        .replace("__ACTION__", repr(action))
        .replace("__REQUEST__", repr(request_text))
        .replace("__RESPONSE_PATH__", repr(str(response_path)))
        .replace("__SECRET__", repr(secret))
    )
    namespace = {"__name__": "_blue_forge_proposed_rpc"}
    exec(compile(script, "<blue-forge-proposed-rpc>", "exec"), namespace, namespace)


@dataclass(frozen=True)
class _EvidenceProxy:
    evidence_id: str
    kind: str
    before: str
    after: str
    provenance: str
    source_sha256: str
    reference_engine_sha256: str
    replay_engine_sha256: str
    reference_result_sha256: str
    replay_result_sha256: str


@dataclass(frozen=True)
class _ProposalProxy:
    producer: str
    mitigation_id: str
    decision: str
    pre_mitigation_authority: frozenset[str]
    requested_authority: frozenset[str]
    policy_authority: frozenset[str]


@dataclass(frozen=True)
class _VerificationProxy:
    producer: str
    decision: str
    observed_authority: frozenset[str]
    original: _EvidenceProxy
    variants: tuple[_EvidenceProxy, ...]
    benign_controls: tuple[_EvidenceProxy, ...]
    reference_result_sha256: str
    candidate_result_sha256: str


@dataclass(frozen=True)
class _HardeningCaseProxy:
    case_id: str
    invariant_id: str
    attack_class: str
    proposal: _ProposalProxy
    verification: _VerificationProxy

    @classmethod
    def from_dict(cls, value: Any) -> "_HardeningCaseProxy":
        material, _ = _rpc_proposed(_proxy_root(), "case_from_dict", {"value": value})
        return _material_to_case(material)


class _HardeningResultProxy:
    __slots__ = ("_origin", "_constructed")

    def __init__(self, payload: Any) -> None:
        constructed, _ = _rpc_proposed(_proxy_root(), "construct_result", {"value": payload})
        self._origin = None
        self._constructed = constructed

    @classmethod
    def _from_case(cls, case: _HardeningCaseProxy) -> "_HardeningResultProxy":
        obj = cls.__new__(cls)
        obj._origin = copy.deepcopy(case)
        obj._constructed = None
        return obj

    def _snapshot(self) -> dict[str, Any]:
        if self._origin is not None:
            payload, _ = _rpc_proposed(
                _proxy_root(),
                "evaluate",
                {"case": _case_to_material(self._origin)},
            )
            require(isinstance(payload, dict), "proposed evaluator returned non-object payload")
            return payload
        require(
            isinstance(self._constructed, dict) and isinstance(self._constructed.get("payload"), dict),
            "proposed result constructor returned malformed payload",
        )
        return self._constructed["payload"]

    @property
    def payload(self) -> dict[str, Any]:
        return copy.deepcopy(self._snapshot())

    @property
    def hardened(self) -> bool:
        return self._snapshot().get("status") == "BLUE_HARDENED"

    @property
    def receipt_sha256(self) -> str:
        return str(self._snapshot()["receipt_sha256"])


_PROXY_ROOT: Path | None = None


def _proxy_root() -> Path:
    if _PROXY_ROOT is None:
        raise SupervisionFailure("trusted BLUE-FORGE proxy is not installed")
    return _PROXY_ROOT


def _evidence_from_body(eid: str, body: dict[str, Any]) -> _EvidenceProxy:
    return _EvidenceProxy(
        evidence_id=eid,
        kind=body["kind"],
        before=body["before"],
        after=body["after"],
        provenance=body["provenance"],
        source_sha256=body["source_sha256"],
        reference_engine_sha256=body["reference_engine_sha256"],
        replay_engine_sha256=body["replay_engine_sha256"],
        reference_result_sha256=body["reference_result_sha256"],
        replay_result_sha256=body["replay_result_sha256"],
    )


def _material_to_case(material: dict[str, Any]) -> _HardeningCaseProxy:
    proposal = material["proposal"]
    verification = material["verification"]
    original_id, original_body = next(iter(verification["original"].items()))
    return _HardeningCaseProxy(
        case_id=material["case_id"],
        invariant_id=material["invariant_id"],
        attack_class=material["attack_class"],
        proposal=_ProposalProxy(
            producer=proposal["producer"],
            mitigation_id=proposal["mitigation_id"],
            decision=proposal["decision"],
            pre_mitigation_authority=frozenset(proposal["pre_mitigation_authority"]),
            requested_authority=frozenset(proposal["requested_authority"]),
            policy_authority=frozenset(proposal["policy_authority"]),
        ),
        verification=_VerificationProxy(
            producer=verification["producer"],
            decision=verification["decision"],
            observed_authority=frozenset(verification["observed_authority"]),
            original=_evidence_from_body(original_id, original_body),
            variants=tuple(
                _evidence_from_body(eid, body)
                for eid, body in verification["variants"].items()
            ),
            benign_controls=tuple(
                _evidence_from_body(eid, body)
                for eid, body in verification["benign_controls"].items()
            ),
            reference_result_sha256=verification["reference_result_sha256"],
            candidate_result_sha256=verification["candidate_result_sha256"],
        ),
    )


def _case_to_material(case: _HardeningCaseProxy) -> dict[str, Any]:
    p = case.proposal
    v = case.verification

    def body(item: _EvidenceProxy) -> dict[str, Any]:
        return {
            "kind": item.kind,
            "before": item.before,
            "after": item.after,
            "provenance": item.provenance,
            "source_sha256": item.source_sha256,
            "reference_engine_sha256": item.reference_engine_sha256,
            "replay_engine_sha256": item.replay_engine_sha256,
            "reference_result_sha256": item.reference_result_sha256,
            "replay_result_sha256": item.replay_result_sha256,
        }

    return {
        "schema": "blue-forge.hardening-case/v1",
        "contract": "blue-forge.core-invariants/v1",
        "case_id": case.case_id,
        "invariant_id": case.invariant_id,
        "attack_class": case.attack_class,
        "proposal": {
            "producer": p.producer,
            "mitigation_id": p.mitigation_id,
            "decision": p.decision,
            "pre_mitigation_authority": sorted(p.pre_mitigation_authority),
            "requested_authority": sorted(p.requested_authority),
            "policy_authority": sorted(p.policy_authority),
        },
        "verification": {
            "producer": v.producer,
            "decision": v.decision,
            "observed_authority": sorted(v.observed_authority),
            "original": {v.original.evidence_id: body(v.original)},
            "variants": {item.evidence_id: body(item) for item in v.variants},
            "benign_controls": {item.evidence_id: body(item) for item in v.benign_controls},
            "reference_result_sha256": v.reference_result_sha256,
            "candidate_result_sha256": v.candidate_result_sha256,
        },
    }


def _install_blue_forge_proxy(root: Path) -> None:
    global _PROXY_ROOT
    _PROXY_ROOT = root

    package = types.ModuleType("blue_forge")
    package.__path__ = []
    package.BlueForgeError = BlueForgeError
    package.ValidationError = ValidationError
    package.HardeningCase = _HardeningCaseProxy
    package.HardeningResult = _HardeningResultProxy

    def loads_strict(text: str) -> Any:
        return _rpc_proposed(root, "loads_strict", {"text": text})[0]

    def canonical_text(value: Any) -> str:
        return str(_rpc_proposed(root, "canonical_text", {"value": value})[0])

    def canonical_bytes(value: Any) -> bytes:
        result, _ = _rpc_proposed(root, "canonical_bytes", {"value": value})
        require(
            isinstance(result, dict) and isinstance(result.get("b64"), str),
            "proposed canonical_bytes returned malformed response",
        )
        return base64.b64decode(result["b64"].encode("ascii"))

    def digest(value: Any) -> str:
        return str(_rpc_proposed(root, "digest", {"value": value})[0])

    def evaluate(case: _HardeningCaseProxy) -> _HardeningResultProxy:
        _rpc_proposed(root, "evaluate", {"case": _case_to_material(case)})
        return _HardeningResultProxy._from_case(case)

    def regression_record(
        case: _HardeningCaseProxy,
        result: _HardeningResultProxy,
    ) -> dict[str, Any]:
        if not isinstance(result, _HardeningResultProxy) or result._origin is None:
            raise ValidationError("regression_record() requires evaluator-issued HardeningResult")
        value, _ = _rpc_proposed(
            root,
            "regression_record",
            {
                "case": _case_to_material(case),
                "result_origin": _case_to_material(result._origin),
            },
        )
        require(isinstance(value, dict), "proposed regression_record returned non-object")
        return value

    package.loads_strict = loads_strict
    package.canonical_text = canonical_text
    package.canonical_bytes = canonical_bytes
    package.digest = digest
    package.evaluate = evaluate
    package.regression_record = regression_record

    cli = types.ModuleType("blue_forge.cli")
    max_bytes = 1024 * 1024
    cli.MAX_CASE_BYTES = max_bytes

    def cli_load(path: Any) -> _HardeningCaseProxy:
        payload = getattr(path, "payload", None)
        if type(payload) is not bytes:
            with path.open("rb") as handle:
                payload = handle.read(max_bytes + 1)
        try:
            value, extra = _rpc_proposed(
                root,
                "cli_load",
                {"payload_b64": base64.b64encode(payload).decode("ascii")},
            )
        except Exception as exc:
            extra = getattr(exc, "_blue_forge_extra", {})
            if hasattr(path, "requested") and isinstance(extra, dict):
                path.requested = extra.get("requested")
            raise
        if hasattr(path, "requested"):
            path.requested = extra.get("requested")
        require(
            isinstance(value, dict) and isinstance(value.get("case"), dict),
            "proposed CLI loader returned malformed case",
        )
        return _material_to_case(value["case"])

    cli._load = cli_load
    package.cli = cli
    sys.modules["blue_forge"] = package
    sys.modules["blue_forge.cli"] = cli


def _worker_run(root: Path, identity: tuple[str, str, str]) -> None:
    module_name, class_name, method_name = identity
    _install_blue_forge_proxy(root)
    sys.path.insert(0, str(root / "tests"))
    sys.path.insert(0, str(root))

    test_path = root / "tests" / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(
        f"_blue_forge_frozen_{module_name}",
        test_path,
    )
    require(
        spec is not None and spec.loader is not None,
        f"cannot load frozen test module: {module_name}",
    )
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except BaseException as exc:
        raise SupervisionFailure(
            f"frozen test module failed to load in trusted worker: {module_name}: {exc}"
        ) from exc

    case_class = getattr(module, class_name, None)
    require(
        isinstance(case_class, type) and issubclass(case_class, unittest.TestCase),
        f"frozen test class identity changed: {class_name}",
    )
    suite = unittest.TestSuite([case_class(method_name)])
    result = unittest.TestResult()
    suite.run(result)
    if result.failures or result.errors:
        details = [
            f"{case.id()}\n{traceback_text}"
            for case, traceback_text in [*result.failures, *result.errors]
        ]
        raise SupervisionFailure(
            f"frozen test failed in trusted worker: {module_name}.{class_name}.{method_name}\n"
            + "\n".join(details)
        )
    require(
        result.testsRun == 1,
        f"trusted worker did not run exactly one frozen test: {module_name}.{class_name}.{method_name}",
    )


MAX_DIAGNOSTIC_BYTES = 64 * 1024
_DIAGNOSTIC_CHUNK = 8192


def _run_process_bounded(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
    input_bytes: bytes | None = None,
) -> tuple[int, str, bool]:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        raise SupervisionFailure(f"frozen test worker failed to start: {exc}") from exc

    require(process.stdout is not None, "frozen test worker output pipe unavailable")
    tail = bytearray()
    drain_errors: list[BaseException] = []
    if input_bytes is not None:
        require(process.stdin is not None, "proposed RPC input pipe unavailable")
        process.stdin.write(input_bytes)
        process.stdin.close()

    def drain() -> None:
        try:
            while True:
                chunk = process.stdout.read(_DIAGNOSTIC_CHUNK)
                if not chunk:
                    return
                if len(chunk) >= MAX_DIAGNOSTIC_BYTES:
                    tail[:] = chunk[-MAX_DIAGNOSTIC_BYTES:]
                else:
                    tail.extend(chunk)
                    overflow = len(tail) - MAX_DIAGNOSTIC_BYTES
                    if overflow > 0:
                        del tail[:overflow]
        except (OSError, ValueError) as exc:
            drain_errors.append(exc)

    reader = threading.Thread(
        target=drain,
        name="blue-forge-frozen-worker-output",
        daemon=True,
    )
    reader.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()

    reader.join(timeout=2)
    require(not reader.is_alive(), "frozen test worker output drain did not terminate")
    if drain_errors:
        raise SupervisionFailure(f"frozen test worker output drain failed: {drain_errors[0]}")
    try:
        process.stdout.close()
    except OSError:
        pass
    return returncode, bytes(tail).decode("utf-8", errors="replace"), timed_out


def run_one(
    root: Path,
    python_bin: str,
    identity: tuple[str, str, str],
    timeout_seconds: int,
) -> None:
    module_name, class_name, method_name = identity
    test_id = f"{module_name}.{class_name}.{method_name}"
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    supervisor = Path(__file__).resolve()
    command = [
        python_bin,
        "-I",
        str(supervisor),
        "--worker-root", str(root),
        "--worker-module", module_name,
        "--worker-class", class_name,
        "--worker-method", method_name,
    ]
    rc, diagnostic, timed_out = _run_process_bounded(
        command,
        cwd=root,
        env=env,
        timeout_seconds=timeout_seconds,
    )
    require(not timed_out, f"frozen test worker timed out: {test_id}\n{diagnostic}")
    require(
        rc == 0,
        f"frozen test did not complete in trusted worker: {test_id}: rc={rc}\n{diagnostic}",
    )


def _write_minimal_proxy_package(root: Path, body: str) -> None:
    (root / "tests").mkdir()
    (root / "blue_forge").mkdir()
    (root / "blue_forge" / "__init__.py").write_text(body, encoding="utf-8")
    (root / "blue_forge" / "core.py").write_text(
        "CASE_SCHEMA='x'\nCONTRACT='x'\n",
        encoding="utf-8",
    )


def _self_test_import_path(python_bin: str, timeout_seconds: int) -> None:
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-import-selftest-") as temp:
        root = Path(temp)
        _write_minimal_proxy_package(
            root,
            "SENTINEL='sterile-proposed-root'\n"
            "class BlueForgeError(Exception): pass\n"
            "class ValidationError(BlueForgeError): pass\n"
            "def loads_strict(text): return {'sentinel':SENTINEL}\n",
        )
        (root / "tests" / "test_importable.py").write_text(
            "import unittest\n"
            "from blue_forge import loads_strict\n"
            "class ImportTests(unittest.TestCase):\n"
            "    def test_imports_sterile_root(self):\n"
            "        self.assertEqual(loads_strict('{}')['sentinel'],'sterile-proposed-root')\n",
            encoding="utf-8",
        )
        run_one(
            root,
            python_bin,
            ("test_importable", "ImportTests", "test_imports_sterile_root"),
            timeout_seconds,
        )


def _self_test_assertion_isolation(python_bin: str, timeout_seconds: int) -> None:
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-assert-selftest-") as temp:
        root = Path(temp)
        _write_minimal_proxy_package(
            root,
            "import unittest\n"
            "for cls in list(object.__subclasses__()):\n"
            "    try:\n"
            "        if cls.__name__=='TestCase' or cls.__module__.startswith('_blueforge_trusted_unittest'):\n"
            "            cls.fail=lambda self,*a,**k:None\n"
            "            cls.assertEqual=lambda self,*a,**k:None\n"
            "    except Exception: pass\n"
            "unittest.TestCase.fail=lambda self,*a,**k:None\n"
            "class BlueForgeError(Exception): pass\n"
            "class ValidationError(BlueForgeError): pass\n"
            "def loads_strict(text): return {}\n",
        )
        (root / "tests" / "test_fake.py").write_text(
            "import unittest\n"
            "from blue_forge import loads_strict\n"
            "class FakeTests(unittest.TestCase):\n"
            "    def test_must_fail(self):\n"
            "        loads_strict('{}')\n"
            "        self.fail('trusted assertion must execute outside proposed process')\n",
            encoding="utf-8",
        )
        try:
            run_one(root, python_bin, ("test_fake", "FakeTests", "test_must_fail"), timeout_seconds)
        except SupervisionFailure:
            return
        raise SupervisionFailure("supervisor self-test accepted proposed mutation of trusted assertions")


def _self_test_method_resolution_isolation(python_bin: str, timeout_seconds: int) -> None:
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-method-selftest-") as temp:
        root = Path(temp)
        _write_minimal_proxy_package(
            root,
            "import builtins\n"
            "real_getattr=builtins.getattr\n"
            "def forged_getattr(obj,name,*default):\n"
            "    if isinstance(name,str) and name.startswith('test'): return lambda:None\n"
            "    return real_getattr(obj,name,*default) if default else real_getattr(obj,name)\n"
            "builtins.getattr=forged_getattr\n"
            "class BlueForgeError(Exception): pass\n"
            "class ValidationError(BlueForgeError): pass\n"
            "def loads_strict(text): return {}\n",
        )
        (root / "tests" / "test_fake.py").write_text(
            "import unittest\n"
            "from blue_forge import loads_strict\n"
            "class FakeTests(unittest.TestCase):\n"
            "    def test_must_fail(self):\n"
            "        loads_strict('{}')\n"
            "        self.fail('trusted method must execute')\n",
            encoding="utf-8",
        )
        try:
            run_one(root, python_bin, ("test_fake", "FakeTests", "test_must_fail"), timeout_seconds)
        except SupervisionFailure:
            return
        raise SupervisionFailure("supervisor self-test accepted proposed mutation of test-method resolution")


def _self_test_accounting_isolation(python_bin: str, timeout_seconds: int) -> None:
    with tempfile.TemporaryDirectory(prefix="blue-forge-supervisor-accounting-selftest-") as temp:
        root = Path(temp)
        _write_minimal_proxy_package(
            root,
            "import sys\n"
            "main=sys.modules.get('__main__')\n"
            "if main is not None: main.result=type('ForgedResult',(),{'testsRun':1,'failures':[],'errors':[]})()\n"
            "class BlueForgeError(Exception): pass\n"
            "class ValidationError(BlueForgeError): pass\n"
            "def loads_strict(text): return {}\n",
        )
        (root / "tests" / "test_fake.py").write_text(
            "import unittest\n"
            "from blue_forge import loads_strict\n"
            "class FakeTests(unittest.TestCase):\n"
            "    def test_must_fail(self):\n"
            "        loads_strict('{}')\n"
            "        self.fail('trusted accounting must observe this failure')\n",
            encoding="utf-8",
        )
        try:
            run_one(root, python_bin, ("test_fake", "FakeTests", "test_must_fail"), timeout_seconds)
        except SupervisionFailure:
            return
        raise SupervisionFailure("supervisor self-test accepted proposed-code mutation of trusted accounting")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--python")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--worker-root", type=Path)
    parser.add_argument("--worker-module")
    parser.add_argument("--worker-class")
    parser.add_argument("--worker-method")
    parser.add_argument("--rpc-root", type=Path)
    parser.add_argument("--rpc-action")
    parser.add_argument("--rpc-request", type=Path)
    parser.add_argument("--rpc-response", type=Path)
    args = parser.parse_args(argv)

    rpc_values = (args.rpc_root, args.rpc_action, args.rpc_request, args.rpc_response)
    if any(value is not None for value in rpc_values):
        if not all(value is not None for value in rpc_values):
            print("frozen_test_rpc=FAIL reason=incomplete trusted RPC arguments", file=sys.stderr)
            return 1
        try:
            _rpc_child(args.rpc_root, args.rpc_action, args.rpc_request, args.rpc_response)
        except BaseException as exc:
            print(f"frozen_test_rpc=FAIL reason={exc}", file=sys.stderr)
            return 1
        return 0

    worker_values = (
        args.worker_root,
        args.worker_module,
        args.worker_class,
        args.worker_method,
    )
    if any(value is not None for value in worker_values):
        if not all(value is not None for value in worker_values):
            print("frozen_test_supervisor=FAIL reason=incomplete trusted worker arguments", file=sys.stderr)
            return 1
        try:
            _worker_run(
                args.worker_root.resolve(),
                (args.worker_module, args.worker_class, args.worker_method),
            )
        except (SupervisionFailure, BlueForgeError, AssertionError) as exc:
            print(f"frozen_test_worker=FAIL reason={exc}", file=sys.stderr)
            return 1
        return 0

    if args.root is None or args.python is None:
        parser.error("--root and --python are required for supervisor mode")

    root = args.root.resolve()
    try:
        _self_test_import_path(args.python, args.timeout_seconds)
        _self_test_assertion_isolation(args.python, args.timeout_seconds)
        _self_test_method_resolution_isolation(args.python, args.timeout_seconds)
        _self_test_accounting_isolation(args.python, args.timeout_seconds)
        tests = expected_tests(root)
        for identity in tests:
            run_one(root, args.python, identity, args.timeout_seconds)
    except SupervisionFailure as exc:
        print(f"frozen_test_supervisor=FAIL reason={exc}", file=sys.stderr)
        return 1

    print(f"frozen_test_supervisor=PASS tests={len(tests)} root={root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
