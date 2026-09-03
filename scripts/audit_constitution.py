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
REGISTRY_PATH = Path("contracts/core-invariants-v1.json")
CORE_INVARIANTS_PATH = Path("docs/CORE_INVARIANTS.md")
PARSER_DOCTRINE_PATH = Path("doctrine/PARSER_DOCTRINE.md")

REQUIRED_FILES = [
    Path("README.md"),
    Path("README4AI.md"),
    Path("AGENTS.md"),
    Path("SECURITY.md"),
    Path("CODE_OF_ETHICS.md"),
    Path("CONTRACT_VERSION"),
    REGISTRY_PATH,
    CORE_INVARIANTS_PATH,
    Path("docs/HERESY_PROVENANCE.md"),
    Path("doctrine/ENGAGEMENT_AREA.md"),
    PARSER_DOCTRINE_PATH,
    Path("archive/readme.md"),
    ARCHIVE_PATH,
    Path("scripts/audit_constitution.py"),
    Path(".github/workflows/constitution.yml"),
]

# These artifacts define v1 semantics or provenance. Their expected identities are
# derived from the earliest historical commit that contains the complete, internally
# coherent v1 contract. Expected OIDs are deliberately not stored in this mutable
# audit file.
PINNED_V1_PATHS = [
    Path("README.md"),
    Path("README4AI.md"),
    Path("AGENTS.md"),
    Path("SECURITY.md"),
    Path("CODE_OF_ETHICS.md"),
    Path("CONTRACT_VERSION"),
    REGISTRY_PATH,
    CORE_INVARIANTS_PATH,
    Path("docs/HERESY_PROVENANCE.md"),
    Path("doctrine/ENGAGEMENT_AREA.md"),
    PARSER_DOCTRINE_PATH,
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


def load_json_text(text: str, label: str) -> dict:
    try:
        value = json.loads(text, object_pairs_hook=reject_duplicate_object_pairs)
    except AuditFailure:
        raise
    except json.JSONDecodeError as exc:
        raise AuditFailure(f"invalid {label}: {exc}") from exc
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def load_registry() -> dict:
    try:
        text = (ROOT / REGISTRY_PATH).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AuditFailure(f"cannot read invariant registry: {exc}") from exc
    return load_json_text(text, "invariant registry")


def run_git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuditFailure(f"git {' '.join(args)} failed: {exc}") from exc
    return completed.stdout.strip()


def run_git_bytes(*args: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuditFailure(f"git {' '.join(args)} failed: {exc}") from exc
    return completed.stdout


def tree_entry(commit: str, path: Path) -> tuple[str, str] | None:
    output = run_git("ls-tree", commit, "--", str(path))
    if not output:
        return None
    lines = [line for line in output.splitlines() if line]
    require(len(lines) == 1, f"expected one tree entry for {path} at {commit}")
    metadata, separator, listed_path = lines[0].partition("\t")
    require(separator == "\t" and listed_path == str(path), f"unexpected tree entry for {path} at {commit}")
    fields = metadata.split()
    require(len(fields) == 3, f"malformed tree metadata for {path} at {commit}")
    mode, object_type, oid = fields
    require(object_type == "blob", f"{path} is not a blob at {commit}")
    return mode, oid


def committed_entry(path: Path) -> tuple[str, str]:
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


def commit_text(commit: str, path: Path) -> str | None:
    entry = tree_entry(commit, path)
    if entry is None:
        return None
    try:
        data = run_git_bytes("show", f"{commit}:{path}")
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def find_v1_baseline_commit() -> str:
    """Find the earliest historical commit containing the coherent v1 contract.

    The baseline is derived from immutable Git history rather than OID constants in
    the proposed audit change. The coherence markers intentionally include the fixes
    required for the machine-facing contract identity and agent audit pointer.
    """
    commits = [line for line in run_git("rev-list", "--reverse", "HEAD").splitlines() if line]
    require(commits, "repository history is unavailable; checkout must include full history")

    for commit in commits:
        version = commit_text(commit, Path("CONTRACT_VERSION"))
        if version is None or version.strip() != CONTRACT_VERSION:
            continue
        if any(tree_entry(commit, path) is None for path in PINNED_V1_PATHS):
            continue
        ai = commit_text(commit, Path("README4AI.md"))
        agents = commit_text(commit, Path("AGENTS.md"))
        if ai is None or CONTRACT_VERSION not in ai:
            continue
        if agents is None:
            continue
        if str(REGISTRY_PATH) not in agents or "scripts/audit_constitution.py" not in agents:
            continue
        return commit

    raise AuditFailure("cannot locate historical v1 constitutional baseline")


def audit_required_files() -> None:
    for path in REQUIRED_FILES:
        target = ROOT / path
        require(not target.is_symlink(), f"required constitutional path is a symlink: {path}")
        require(target.is_file(), f"required constitutional path is not a regular file: {path}")
        mode, _ = committed_entry(path)
        require(mode == "100644", f"required constitutional path mode changed: {path} mode={mode}")


def audit_pinned_v1_artifacts(baseline_commit: str) -> dict[Path, str]:
    """Require current committed and checked-out artifacts to equal the history anchor."""
    baseline_oids: dict[Path, str] = {}
    for path in PINNED_V1_PATHS:
        baseline = tree_entry(baseline_commit, path)
        require(baseline is not None, f"baseline missing pinned artifact: {path}")
        baseline_mode, baseline_oid = baseline
        require(baseline_mode == "100644", f"baseline pinned artifact is not regular mode 100644: {path}")

        current_mode, current_oid = committed_entry(path)
        require(current_mode == baseline_mode, f"pinned artifact mode changed: {path} mode={current_mode}")
        require(current_oid == baseline_oid, f"pinned v1 artifact changed without new contract identity: {path}")

        target = ROOT / path
        require(not target.is_symlink() and target.is_file(), f"pinned artifact is not a regular working-tree file: {path}")
        working_oid = run_git("hash-object", "--", str(path))
        require(working_oid == baseline_oid, f"checked-out pinned artifact differs from v1 baseline: {path}")
        baseline_oids[path] = baseline_oid
    return baseline_oids


def audit_version(registry: dict) -> None:
    version = read_text(Path("CONTRACT_VERSION")).strip()
    require(version == CONTRACT_VERSION, f"CONTRACT_VERSION changed: {version!r}")
    require(type(registry.get("schema")) is str and registry["schema"] == CONTRACT_VERSION, "registry schema changed")
    require(type(registry.get("status")) is str and registry["status"] == "constitutional", "registry status changed")


def audit_registry(registry: dict) -> None:
    require(
        set(registry) == {"schema", "status", "decision_order", "blue_hardened", "invariants"},
        "registry top-level fields changed",
    )

    decision_order = registry.get("decision_order")
    require(isinstance(decision_order, list), "decision_order must be a list")
    require(all(type(item) is str for item in decision_order), "decision_order values must be strings")
    require(decision_order == EXPECTED_DECISION_ORDER, "decision lattice changed")

    hardened = registry.get("blue_hardened")
    require(isinstance(hardened, dict), "blue_hardened must be an object")
    require(set(hardened) == {"all_of"}, "blue_hardened fields changed")
    all_of = hardened.get("all_of")
    require(isinstance(all_of, list), "blue_hardened.all_of must be a list")
    require(all(type(item) is str for item in all_of), "BLUE_HARDENED predicates must be strings")
    require(all_of == EXPECTED_BLUE_HARDENED, "BLUE_HARDENED predicate changed")

    invariants = registry.get("invariants")
    require(isinstance(invariants, list), "invariants must be a list")
    require(len(invariants) == len(EXPECTED_IDS), "contract v1 must contain exactly 16 invariants")

    seen: list[str] = []
    expected_fields = {"id", "name", "rule", "failure_state", "constitutional"}
    for item in invariants:
        require(isinstance(item, dict), "each invariant must be an object")
        require(set(item) == expected_fields, "invariant fields changed")
        require(type(item.get("id")) is str, "invariant id must be a string")
        require(type(item.get("name")) is str and bool(item["name"].strip()), f"{item.get('id')}: invalid name")
        require(type(item.get("rule")) is str and bool(item["rule"].strip()), f"{item.get('id')}: invalid rule")
        require(
            type(item.get("failure_state")) is str and bool(item["failure_state"].strip()),
            f"{item.get('id')}: invalid failure_state",
        )
        require(type(item.get("constitutional")) is bool, f"{item.get('id')}: constitutional must be a JSON boolean")
        require(item["constitutional"] is True, f"{item.get('id')}: constitutional must remain true")
        seen.append(item["id"])

    require(seen == EXPECTED_IDS, f"invariant IDs changed or were reordered: {seen!r}")
    require(len(set(seen)) == len(seen), "duplicate invariant IDs")


def audit_documentation(registry: dict) -> None:
    core = read_text(CORE_INVARIANTS_PATH)
    parser = read_text(PARSER_DOCTRINE_PATH)
    readme = read_text(Path("README.md"))
    ai = read_text(Path("README4AI.md"))
    agents = read_text(Path("AGENTS.md"))

    require(CONTRACT_VERSION in core, "CORE_INVARIANTS does not name the contract")
    require(CONTRACT_VERSION in ai, "README4AI does not name the contract")
    require("ALLOW < REVIEW < DENY" in core, "CORE_INVARIANTS lost the decision lattice")
    require("Proof first. Reuse second." in core, "CORE_INVARIANTS lost the optimization rule")
    require("deception outward, truth inward" in core.lower(), "CORE_INVARIANTS lost the truth rule")
    require("canonicalize before authorization" in parser.lower(), "PARSER_DOCTRINE lost canonicalization-before-authorization")

    for item in registry["invariants"]:
        invariant_id = item["id"]
        name = item["name"]
        heading = f"## {invariant_id} - {name}"
        require(core.count(heading) == 1, f"missing or duplicated normative heading: {heading}")
        require(invariant_id in readme, f"README no longer exposes {invariant_id}")

    require(str(REGISTRY_PATH) in agents, "AGENTS.md does not point to the registry")
    require("scripts/audit_constitution.py" in agents, "AGENTS.md does not require this audit")

    for predicate in EXPECTED_BLUE_HARDENED:
        require(predicate in core, f"CORE_INVARIANTS lost BLUE_HARDENED predicate {predicate}")
        require(predicate in readme, f"README lost BLUE_HARDENED predicate {predicate}")


def audit_archive(baseline_oids: dict[Path, str]) -> tuple[str, int]:
    oid = baseline_oids[ARCHIVE_PATH]
    object_type = run_git("cat-file", "-t", oid)
    require(object_type == "blob", f"archived HERESY baseline object is not a blob: {object_type}")
    size_text = run_git("cat-file", "-s", oid)
    try:
        size = int(size_text)
    except ValueError as exc:
        raise AuditFailure(f"invalid archived HERESY object size: {size_text!r}") from exc
    require((ROOT / ARCHIVE_PATH).stat().st_size == size, "checked-out HERESY archive size differs from baseline")

    provenance = read_text(Path("docs/HERESY_PROVENANCE.md"))
    archive_readme = read_text(Path("archive/readme.md"))
    for text, label in ((provenance, "HERESY provenance"), (archive_readme, "archive README")):
        require(str(size) in text, f"{label} lost archive size")
        require(oid in text, f"{label} lost archive object identity")
    return oid, size


def main() -> int:
    try:
        audit_required_files()
        baseline_commit = find_v1_baseline_commit()
        baseline_oids = audit_pinned_v1_artifacts(baseline_commit)
        registry = load_registry()
        audit_version(registry)
        audit_registry(registry)
        audit_documentation(registry)
        archive_oid, archive_size = audit_archive(baseline_oids)
    except AuditFailure as exc:
        print(f"constitution_audit=FAIL reason={exc}", file=sys.stderr)
        return 1

    print(
        f"constitution_audit=PASS contract={CONTRACT_VERSION} "
        f"invariants={len(EXPECTED_IDS)} baseline={baseline_commit}"
    )
    print(
        "heresy_archive=PASS "
        f"path={ARCHIVE_PATH} size={archive_size} git_oid={archive_oid}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
