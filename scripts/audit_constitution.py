#!/usr/bin/env python3
"""Fail-closed audit for the BLUE-FORGE constitutional contract."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_VERSION = "blue-forge.core-invariants/v1"
EXPECTED_DECISION_ORDER = ["ALLOW", "REVIEW", "DENY"]
EXPECTED_BLUE_HARDENED = [
    "original_attack_neutralized",
    "attack_class_invariant_holds",
    "benign_controls_pass",
    "provenance_valid",
    "verification_complete",
    "replay_exact",
    "authority_not_expanded",
    "reference_equivalence_preserved",
]
EXPECTED_INVARIANTS = [
    {
        "id": "BF-INV-001",
        "name": "Authority Cannot Silently Expand",
        "rule": "Effective authority must be a subset of requested authority intersected with policy authority.",
        "failure_state": "DENY",
        "constitutional": True,
    },
    {
        "id": "BF-INV-002",
        "name": "Defensive Decisions Are Monotonic",
        "rule": "Within one immutable run, automated stages may preserve or tighten ALLOW < REVIEW < DENY but may not weaken a prior decision.",
        "failure_state": "CONTRACT_ERROR",
        "constitutional": True,
    },
    {
        "id": "BF-INV-003",
        "name": "No Self-Certification",
        "rule": "The component proposing a mitigation cannot be the sole authority declaring that mitigation verified.",
        "failure_state": "VERIFICATION_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-004",
        "name": "Provenance Before Interpretation",
        "rule": "Unverified evidence may be inspected but cannot become load-bearing trusted evidence without required provenance.",
        "failure_state": "VERIFICATION_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-005",
        "name": "Evidence Is Data",
        "rule": "Captured hostile evidence must not gain execution authority merely by being ingested, parsed, inspected, or archived.",
        "failure_state": "DENY",
        "constitutional": True,
    },
    {
        "id": "BF-INV-006",
        "name": "Replay Failure Is Verification Failure",
        "rule": "For a pinned contract, identical captured bytes, policy, and engine identity must reproduce the same canonical result.",
        "failure_state": "VERIFICATION_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-007",
        "name": "Benign Behaviour Must Survive",
        "rule": "A mitigation is incomplete when it neutralizes the hostile case by unnecessarily breaking required legitimate behaviour.",
        "failure_state": "VERIFICATION_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-008",
        "name": "Unknown Is Not Safe",
        "rule": "UNKNOWN, MALFORMED, UNSUPPORTED, INCOMPLETE, TIMEOUT, and resource failures cannot be promoted to ALLOW or VERIFIED.",
        "failure_state": "DENY_OR_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-009",
        "name": "Resource Exhaustion Cannot Produce Verification",
        "rule": "Exhausting a configured CPU, memory, recursion, decompression, worker, fixture, time, or evidence budget must fail explicitly.",
        "failure_state": "VERIFICATION_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-010",
        "name": "Optimisation Cannot Reduce the Proof Surface",
        "rule": "Performance work may reduce proof cost but must not weaken assertions, coverage, provenance, isolation, tolerances, determinism, boundaries, or replay.",
        "failure_state": "CONTRACT_ERROR",
        "constitutional": True,
    },
    {
        "id": "BF-INV-011",
        "name": "Parallelism Is Semantically Invisible",
        "rule": "Worker count and completion order may affect performance but must not alter canonical security results.",
        "failure_state": "VERIFICATION_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-012",
        "name": "Model Agreement Is Not Proof",
        "rule": "Model consensus cannot elevate a claim into verified evidence without an independent verification predicate.",
        "failure_state": "VERIFICATION_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-013",
        "name": "Semantic Changes Require New Contract Identity",
        "rule": "Changes to policy meaning, normalization, trust, decision ordering, receipt meaning, invariant semantics, or verification semantics require explicit versioning and new conformance vectors.",
        "failure_state": "CONTRACT_ERROR",
        "constitutional": True,
    },
    {
        "id": "BF-INV-014",
        "name": "No Silent Degradation",
        "rule": "Unavailable required verification mechanisms must produce an explicit incomplete state rather than a weaker silent substitute.",
        "failure_state": "VERIFICATION_INCOMPLETE",
        "constitutional": True,
    },
    {
        "id": "BF-INV-015",
        "name": "Deception Outward, Truth Inward",
        "rule": "Defensive deception may shape hostile behaviour but must never distort evidence, uncertainty, provenance, or outcomes presented to defenders.",
        "failure_state": "CONTRACT_ERROR",
        "constitutional": True,
    },
    {
        "id": "BF-INV-016",
        "name": "Minimum Necessary Intervention",
        "rule": "For equivalent verified security outcomes, prefer the mitigation that changes the smallest necessary authority, resource, user, service, and time scope.",
        "failure_state": "REVIEW",
        "constitutional": True,
    },
]
EXPECTED_IDS = [item["id"] for item in EXPECTED_INVARIANTS]
ARCHIVE_PATH = Path("archive/HERESY-SEC-0.3.0.zip")
ARCHIVE_SIZE = 120145
ARCHIVE_GIT_OID = "76ad6138023ebe41c6a715980835403b945648f1"
ARCHIVE_GIT_MODE = "100644"
REQUIRED_FILES = [
    Path("README.md"),
    Path("README4AI.md"),
    Path("AGENTS.md"),
    Path("SECURITY.md"),
    Path("CODE_OF_ETHICS.md"),
    Path("CONTRACT_VERSION"),
    Path("contracts/core-invariants-v1.json"),
    Path("docs/CORE_INVARIANTS.md"),
    Path("docs/HERESY_PROVENANCE.md"),
    Path("doctrine/ENGAGEMENT_AREA.md"),
    Path("doctrine/PARSER_DOCTRINE.md"),
    Path("archive/readme.md"),
    ARCHIVE_PATH,
]


class AuditFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditFailure(message)


def read_text(path: Path) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AuditFailure(f"cannot read {path}: {exc}") from exc


def reject_duplicate_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting duplicate member names at every depth."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuditFailure(f"duplicate JSON key in invariant registry: {key!r}")
        result[key] = value
    return result


def load_registry() -> dict:
    path = ROOT / "contracts/core-invariants-v1.json"
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_object_pairs,
        )
    except AuditFailure:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditFailure(f"invalid invariant registry: {exc}") from exc
    require(isinstance(value, dict), "invariant registry must be a JSON object")
    return value


def run_git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuditFailure(f"git {' '.join(args)} failed: {exc}") from exc
    return completed.stdout.strip()


def audit_required_files() -> None:
    missing = [str(path) for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    require(not missing, f"missing required constitutional files: {', '.join(missing)}")


def audit_version(registry: dict) -> None:
    version = read_text(Path("CONTRACT_VERSION")).strip()
    require(version == CONTRACT_VERSION, f"CONTRACT_VERSION changed: {version!r}")
    require(registry.get("schema") == CONTRACT_VERSION, "registry schema does not match CONTRACT_VERSION")
    require(registry.get("status") == "constitutional", "registry must remain constitutional")


def audit_registry(registry: dict) -> None:
    require(
        set(registry) == {"schema", "status", "decision_order", "blue_hardened", "invariants"},
        "registry top-level fields changed",
    )
    require(registry.get("decision_order") == EXPECTED_DECISION_ORDER, "decision lattice changed")

    hardened = registry.get("blue_hardened")
    require(isinstance(hardened, dict), "blue_hardened must be an object")
    require(set(hardened) == {"all_of"}, "blue_hardened fields changed")
    require(hardened.get("all_of") == EXPECTED_BLUE_HARDENED, "BLUE_HARDENED predicate changed")

    invariants = registry.get("invariants")
    require(isinstance(invariants, list), "invariants must be a list")
    require(
        invariants == EXPECTED_INVARIANTS,
        "contract v1 invariant definitions changed; semantic changes require a new contract identity",
    )


def audit_documentation(registry: dict) -> None:
    core = read_text(Path("docs/CORE_INVARIANTS.md"))
    readme = read_text(Path("README.md"))
    ai = read_text(Path("README4AI.md"))
    agents = read_text(Path("AGENTS.md"))

    require(CONTRACT_VERSION in core, "CORE_INVARIANTS does not name the contract")
    require(CONTRACT_VERSION in ai, "README4AI does not name the contract")
    require("ALLOW < REVIEW < DENY" in core, "CORE_INVARIANTS lost the decision lattice")
    require("Proof first. Reuse second." in core, "CORE_INVARIANTS lost the optimization rule")
    require("deception outward, truth inward" in core.lower(), "CORE_INVARIANTS lost the truth rule")

    for item in registry["invariants"]:
        invariant_id = item["id"]
        name = item["name"]
        heading = f"## {invariant_id} - {name}"
        require(core.count(heading) == 1, f"missing or duplicated normative heading: {heading}")
        require(invariant_id in readme, f"README no longer exposes {invariant_id}")

    require("contracts/core-invariants-v1.json" in agents, "AGENTS.md does not point to the registry")
    require("scripts/audit_constitution.py" in agents, "AGENTS.md does not require this audit")

    for predicate in EXPECTED_BLUE_HARDENED:
        require(predicate in core, f"CORE_INVARIANTS lost BLUE_HARDENED predicate {predicate}")
        require(predicate in readme, f"README lost BLUE_HARDENED predicate {predicate}")


def committed_entry(path: Path) -> tuple[str, str]:
    """Return the Git index mode and object ID for exactly one stage-0 path."""
    output = run_git("ls-files", "--stage", "--", str(path))
    lines = [line for line in output.splitlines() if line]
    require(len(lines) == 1, f"expected exactly one committed index entry for {path}")

    metadata, separator, listed_path = lines[0].partition("\t")
    require(separator == "\t" and listed_path == str(path), f"unexpected index entry for {path}")
    fields = metadata.split()
    require(len(fields) == 3, f"malformed index metadata for {path}")
    mode, oid, stage = fields
    require(stage == "0", f"non-stage-0 index entry for {path}")
    return mode, oid


def audit_archive() -> None:
    mode, oid = committed_entry(ARCHIVE_PATH)
    require(mode == ARCHIVE_GIT_MODE, f"archived HERESY file mode changed: {mode}")
    require(oid == ARCHIVE_GIT_OID, f"archived HERESY committed object identity changed: {oid}")

    object_type = run_git("cat-file", "-t", oid)
    require(object_type == "blob", f"archived HERESY object is not a blob: {object_type}")
    object_size_text = run_git("cat-file", "-s", oid)
    try:
        object_size = int(object_size_text)
    except ValueError as exc:
        raise AuditFailure(f"invalid git object size for archived HERESY: {object_size_text!r}") from exc
    require(object_size == ARCHIVE_SIZE, f"archived HERESY committed size changed: {object_size}")

    provenance = read_text(Path("docs/HERESY_PROVENANCE.md"))
    archive_readme = read_text(Path("archive/readme.md"))
    for text, label in ((provenance, "HERESY provenance"), (archive_readme, "archive README")):
        require(str(ARCHIVE_SIZE) in text, f"{label} lost archive size")
        require(ARCHIVE_GIT_OID in text, f"{label} lost archive object identity")


def main() -> int:
    try:
        audit_required_files()
        registry = load_registry()
        audit_version(registry)
        audit_registry(registry)
        audit_documentation(registry)
        audit_archive()
    except AuditFailure as exc:
        print(f"constitution_audit=FAIL reason={exc}", file=sys.stderr)
        return 1

    print(f"constitution_audit=PASS contract={CONTRACT_VERSION} invariants={len(EXPECTED_IDS)}")
    print(
        "heresy_archive=PASS "
        f"path={ARCHIVE_PATH} mode={ARCHIVE_GIT_MODE} size={ARCHIVE_SIZE} git_oid={ARCHIVE_GIT_OID}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
