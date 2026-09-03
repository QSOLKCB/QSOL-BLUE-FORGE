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
EXPECTED_IDS = [f"BF-INV-{index:03d}" for index in range(1, 17)]

REGISTRY_PATH = Path("contracts/core-invariants-v1.json")
REGISTRY_GIT_OID = "78f2a979f9dd3fc8a3d09101baa90f6516e27fd4"
CORE_DOC_PATH = Path("docs/CORE_INVARIANTS.md")
CORE_DOC_GIT_OID = "83ded0892d90e2ea711092104e12caa7b862cd99"
ARCHIVE_PATH = Path("archive/HERESY-SEC-0.3.0.zip")
ARCHIVE_GIT_OID = "76ad6138023ebe41c6a715980835403b945648f1"
ARCHIVE_SIZE = 120145
PINNED_GIT_MODE = "100644"

REQUIRED_FILES = [
    Path("README.md"),
    Path("README4AI.md"),
    Path("AGENTS.md"),
    Path("SECURITY.md"),
    Path("CODE_OF_ETHICS.md"),
    Path("CONTRACT_VERSION"),
    REGISTRY_PATH,
    CORE_DOC_PATH,
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


def reject_nonstandard_constant(value: str) -> object:
    """Reject NaN/Infinity extensions accepted by Python's JSON parser by default."""
    raise AuditFailure(f"non-standard JSON constant in invariant registry: {value}")


def load_registry() -> dict:
    path = ROOT / REGISTRY_PATH
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_object_pairs,
            parse_constant=reject_nonstandard_constant,
        )
    except AuditFailure:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditFailure(f"invalid invariant registry: {exc}") from exc
    require(type(value) is dict, "invariant registry must be a JSON object")
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
    missing = [str(path) for path in REQUIRED_FILES if not (ROOT / path).exists()]
    require(not missing, f"missing required constitutional files: {', '.join(missing)}")


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


def working_tree_oid(path: Path) -> str:
    full_path = ROOT / path
    require(not full_path.is_symlink(), f"pinned constitutional path became a symlink: {path}")
    require(full_path.is_file(), f"pinned constitutional path is not a regular file: {path}")
    return run_git("hash-object", "--", str(path))


def audit_pinned_file(
    path: Path,
    expected_oid: str,
    *,
    expected_size: int | None = None,
) -> None:
    """Verify both the committed object and the checked-out bytes of a pinned file."""
    mode, committed_oid = committed_entry(path)
    require(mode == PINNED_GIT_MODE, f"pinned file mode changed for {path}: {mode}")
    require(committed_oid == expected_oid, f"pinned committed object changed for {path}: {committed_oid}")

    object_type = run_git("cat-file", "-t", committed_oid)
    require(object_type == "blob", f"pinned Git object is not a blob for {path}: {object_type}")

    working_oid = working_tree_oid(path)
    require(working_oid == expected_oid, f"checked-out bytes changed for {path}: {working_oid}")

    if expected_size is not None:
        committed_size_text = run_git("cat-file", "-s", committed_oid)
        try:
            committed_size = int(committed_size_text)
        except ValueError as exc:
            raise AuditFailure(f"invalid committed object size for {path}: {committed_size_text!r}") from exc
        require(committed_size == expected_size, f"committed size changed for {path}: {committed_size}")
        working_size = (ROOT / path).stat().st_size
        require(working_size == expected_size, f"checked-out size changed for {path}: {working_size}")


def audit_version(registry: dict) -> None:
    version = read_text(Path("CONTRACT_VERSION")).strip()
    require(version == CONTRACT_VERSION, f"CONTRACT_VERSION changed: {version!r}")
    require(type(registry.get("schema")) is str, "registry schema must be a string")
    require(registry.get("schema") == CONTRACT_VERSION, "registry schema does not match CONTRACT_VERSION")
    require(type(registry.get("status")) is str, "registry status must be a string")
    require(registry.get("status") == "constitutional", "registry must remain constitutional")


def audit_registry(registry: dict) -> None:
    require(
        set(registry) == {"schema", "status", "decision_order", "blue_hardened", "invariants"},
        "registry top-level fields changed",
    )

    decision_order = registry.get("decision_order")
    require(type(decision_order) is list, "decision_order must be an array")
    require(all(type(item) is str for item in decision_order), "decision_order values must be strings")
    require(decision_order == EXPECTED_DECISION_ORDER, "decision lattice changed")

    hardened = registry.get("blue_hardened")
    require(type(hardened) is dict, "blue_hardened must be an object")
    require(set(hardened) == {"all_of"}, "blue_hardened fields changed")
    hardened_all = hardened.get("all_of")
    require(type(hardened_all) is list, "blue_hardened.all_of must be an array")
    require(all(type(item) is str for item in hardened_all), "BLUE_HARDENED predicates must be strings")
    require(hardened_all == EXPECTED_BLUE_HARDENED, "BLUE_HARDENED predicate changed")

    invariants = registry.get("invariants")
    require(type(invariants) is list, "invariants must be an array")
    require(len(invariants) == len(EXPECTED_IDS), "contract v1 must contain exactly 16 invariants")

    ids: list[str] = []
    expected_fields = {"id", "name", "rule", "failure_state", "constitutional"}
    for index, item in enumerate(invariants):
        require(type(item) is dict, f"invariant {index} must be an object")
        require(set(item) == expected_fields, f"invariant {index} fields changed")
        require(type(item.get("id")) is str, f"invariant {index} id must be a string")
        require(type(item.get("name")) is str, f"invariant {index} name must be a string")
        require(type(item.get("rule")) is str, f"invariant {index} rule must be a string")
        require(type(item.get("failure_state")) is str, f"invariant {index} failure_state must be a string")
        require(
            type(item.get("constitutional")) is bool and item.get("constitutional") is True,
            f"invariant {index} constitutional must be the JSON boolean true",
        )
        ids.append(item["id"])

    require(ids == EXPECTED_IDS, f"invariant IDs changed or were reordered: {ids!r}")
    require(len(set(ids)) == len(ids), "duplicate invariant IDs")

    # Exact machine semantics are additionally frozen by REGISTRY_GIT_OID. This
    # type-aware structural validation gives a useful local failure reason while
    # the pinned blob/working-tree checks reject any textual or semantic drift.


def audit_documentation(registry: dict) -> None:
    core = read_text(CORE_DOC_PATH)
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


def audit_archive_documentation() -> None:
    provenance = read_text(Path("docs/HERESY_PROVENANCE.md"))
    archive_readme = read_text(Path("archive/readme.md"))
    for text, label in ((provenance, "HERESY provenance"), (archive_readme, "archive README")):
        require(str(ARCHIVE_SIZE) in text, f"{label} lost archive size")
        require(ARCHIVE_GIT_OID in text, f"{label} lost archive object identity")


def main() -> int:
    try:
        audit_required_files()

        # Pin the machine contract and normative prose independently of their
        # semantic spot-checks. This makes v1 drift visible even when headings,
        # IDs, or selected phrases remain unchanged.
        audit_pinned_file(REGISTRY_PATH, REGISTRY_GIT_OID)
        audit_pinned_file(CORE_DOC_PATH, CORE_DOC_GIT_OID)
        audit_pinned_file(ARCHIVE_PATH, ARCHIVE_GIT_OID, expected_size=ARCHIVE_SIZE)

        registry = load_registry()
        audit_version(registry)
        audit_registry(registry)
        audit_documentation(registry)
        audit_archive_documentation()
    except AuditFailure as exc:
        print(f"constitution_audit=FAIL reason={exc}", file=sys.stderr)
        return 1

    print(f"constitution_audit=PASS contract={CONTRACT_VERSION} invariants={len(EXPECTED_IDS)}")
    print(f"registry_pin=PASS path={REGISTRY_PATH} git_oid={REGISTRY_GIT_OID}")
    print(f"normative_prose_pin=PASS path={CORE_DOC_PATH} git_oid={CORE_DOC_GIT_OID}")
    print(
        "heresy_archive=PASS "
        f"path={ARCHIVE_PATH} mode={PINNED_GIT_MODE} size={ARCHIVE_SIZE} git_oid={ARCHIVE_GIT_OID}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
