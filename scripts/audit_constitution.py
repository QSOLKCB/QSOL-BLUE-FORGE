#!/usr/bin/env python3
"""Fail-closed audit for the BLUE-FORGE constitutional contract."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_VERSION = "blue-forge.core-invariants/v1"
EXPECTED_IDS = [f"BF-INV-{index:03d}" for index in range(1, 17)]
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
ARCHIVE_PATH = Path("archive/HERESY-SEC-0.3.0.zip")
ARCHIVE_SIZE = 120145
ARCHIVE_GIT_OID = "76ad6138023ebe41c6a715980835403b945648f1"
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


def load_registry() -> dict:
    path = ROOT / "contracts/core-invariants-v1.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditFailure(f"invalid invariant registry: {exc}") from exc
    require(isinstance(value, dict), "invariant registry must be a JSON object")
    return value


def audit_required_files() -> None:
    missing = [str(path) for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    require(not missing, f"missing required constitutional files: {', '.join(missing)}")


def audit_version(registry: dict) -> None:
    version = read_text(Path("CONTRACT_VERSION")).strip()
    require(version == CONTRACT_VERSION, f"CONTRACT_VERSION changed: {version!r}")
    require(registry.get("schema") == CONTRACT_VERSION, "registry schema does not match CONTRACT_VERSION")
    require(registry.get("status") == "constitutional", "registry must remain constitutional")


def audit_registry(registry: dict) -> None:
    require(registry.get("decision_order") == EXPECTED_DECISION_ORDER, "decision lattice changed")

    hardened = registry.get("blue_hardened")
    require(isinstance(hardened, dict), "blue_hardened must be an object")
    require(hardened.get("all_of") == EXPECTED_BLUE_HARDENED, "BLUE_HARDENED predicate changed")

    invariants = registry.get("invariants")
    require(isinstance(invariants, list), "invariants must be a list")
    require(len(invariants) == len(EXPECTED_IDS), "contract v1 must contain exactly 16 invariants")

    ids = []
    for item in invariants:
        require(isinstance(item, dict), "each invariant must be an object")
        invariant_id = item.get("id")
        ids.append(invariant_id)
        require(item.get("constitutional") is True, f"{invariant_id}: constitutional flag must remain true")
        require(isinstance(item.get("name"), str) and item["name"].strip(), f"{invariant_id}: missing name")
        require(isinstance(item.get("rule"), str) and item["rule"].strip(), f"{invariant_id}: missing rule")
        require(
            isinstance(item.get("failure_state"), str) and item["failure_state"].strip(),
            f"{invariant_id}: missing failure_state",
        )

    require(ids == EXPECTED_IDS, f"invariant IDs changed or were reordered: {ids!r}")
    require(len(set(ids)) == len(ids), "duplicate invariant IDs")


def audit_documentation(registry: dict) -> None:
    core = read_text(Path("docs/CORE_INVARIANTS.md"))
    readme = read_text(Path("README.md"))
    ai = read_text(Path("README4AI.md"))
    agents = read_text(Path("AGENTS.md"))

    require(CONTRACT_VERSION in core, "CORE_INVARIANTS does not name the contract")
    require(CONTRACT_VERSION in ai, "README4AI does not name the contract")
    require("ALLOW < REVIEW < DENY" in core, "CORE_INVARIANTS lost the decision lattice")
    require("Proof first. Reuse second." in core, "CORE_INVARIANTS lost the optimization rule")
    require("Deception outward, truth inward" in core, "CORE_INVARIANTS lost the truth rule")

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


def git_object_id(path: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "hash-object", "--", str(path)],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuditFailure(f"cannot compute git object identity for {path}: {exc}") from exc
    return completed.stdout.strip()


def audit_archive() -> None:
    path = ROOT / ARCHIVE_PATH
    require(path.stat().st_size == ARCHIVE_SIZE, f"archived HERESY size changed: {path.stat().st_size}")
    oid = git_object_id(ARCHIVE_PATH)
    require(oid == ARCHIVE_GIT_OID, f"archived HERESY object identity changed: {oid}")

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
    print(f"heresy_archive=PASS path={ARCHIVE_PATH} size={ARCHIVE_SIZE} git_oid={ARCHIVE_GIT_OID}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
