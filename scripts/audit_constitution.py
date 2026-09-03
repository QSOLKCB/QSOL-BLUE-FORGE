#!/usr/bin/env python3
"""Fail-closed audit for the BLUE-FORGE constitutional contract."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_VERSION = "blue-forge.core-invariants/v1"
TRUSTED_REF = os.environ.get("BLUE_FORGE_TRUSTED_REF", "origin/constitution-v1-baseline")
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
ARCHIVE_README_PATH = Path("archive/readme.md")
REGISTRY_PATH = Path("contracts/core-invariants-v1.json")
CORE_INVARIANTS_PATH = Path("docs/CORE_INVARIANTS.md")
HERESY_PROVENANCE_PATH = Path("docs/HERESY_PROVENANCE.md")
PARSER_DOCTRINE_PATH = Path("doctrine/PARSER_DOCTRINE.md")
ENGAGEMENT_DOCTRINE_PATH = Path("doctrine/ENGAGEMENT_AREA.md")
SECURITY_PATH = Path("SECURITY.md")
ETHICS_PATH = Path("CODE_OF_ETHICS.md")
README4AI_PATH = Path("README4AI.md")
AGENTS_PATH = Path("AGENTS.md")
WORKFLOW_ROOT = Path(".github/workflows")
DEFAULT_WORKFLOW_TRIGGERS = {"push", "pull_request", "pull_request_target"}

REQUIRED_FILES = [
    Path("README.md"),
    README4AI_PATH,
    AGENTS_PATH,
    SECURITY_PATH,
    ETHICS_PATH,
    Path("LICENSE"),
    Path("CONTRACT_VERSION"),
    REGISTRY_PATH,
    CORE_INVARIANTS_PATH,
    HERESY_PROVENANCE_PATH,
    ENGAGEMENT_DOCTRINE_PATH,
    PARSER_DOCTRINE_PATH,
    ARCHIVE_README_PATH,
    ARCHIVE_PATH,
    Path("scripts/audit_constitution.py"),
    Path(".github/workflows/constitution.yml"),
]

# These artifacts define immutable v1 semantics, machine-facing policy,
# security/ethical policy, or source provenance. Their HEAD objects and raw
# checked-out bytes must match the trusted external baseline. General explanatory
# prose remains editable when its targeted semantic checks continue to hold.
PINNED_V1_PATHS = [
    Path("CONTRACT_VERSION"),
    REGISTRY_PATH,
    CORE_INVARIANTS_PATH,
    PARSER_DOCTRINE_PATH,
    ENGAGEMENT_DOCTRINE_PATH,
    README4AI_PATH,
    AGENTS_PATH,
    SECURITY_PATH,
    ETHICS_PATH,
    HERESY_PROVENANCE_PATH,
    ARCHIVE_README_PATH,
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


def head_entry(path: Path) -> tuple[str, str]:
    entry = tree_entry("HEAD", path)
    require(entry is not None, f"required constitutional path is not committed in HEAD: {path}")
    return entry


def commit_text(commit: str, path: Path) -> str | None:
    entry = tree_entry(commit, path)
    if entry is None:
        return None
    try:
        data = run_git_bytes("show", f"{commit}:{path}")
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def tree_paths(commit: str, prefix: Path | None = None) -> list[Path]:
    args = ["ls-tree", "-r", "--name-only", commit]
    if prefix is not None:
        args.extend(["--", str(prefix)])
    output = run_git(*args)
    return [Path(line) for line in output.splitlines() if line]


def agent_policy_paths(commit: str) -> set[Path]:
    return {path for path in tree_paths(commit) if path.name == "AGENTS.md"}


def workflow_paths(commit: str) -> set[Path]:
    return {
        path
        for path in tree_paths(commit, WORKFLOW_ROOT)
        if path.suffix.lower() in {".yml", ".yaml"}
    }


def workflow_has_default_trigger(text: str) -> bool:
    """Recognize mapping, scalar, flow-list, and block-sequence workflow triggers."""
    lines = text.splitlines()
    for index, raw_line in enumerate(lines):
        line = raw_line.split("#", 1)[0].rstrip()
        match = re.match(r"^(?:on|['\"]on['\"])\s*:\s*(.*)$", line)
        if not match:
            continue

        tail = match.group(1).strip().lower()
        if tail:
            return any(
                re.search(rf"\b{re.escape(trigger)}\b", tail)
                for trigger in DEFAULT_WORKFLOW_TRIGGERS
            )

        nested_lines: list[tuple[int, str]] = []
        for nested_raw in lines[index + 1 :]:
            nested = nested_raw.split("#", 1)[0].rstrip()
            if not nested.strip():
                continue
            indent = len(nested) - len(nested.lstrip(" "))
            if indent == 0:
                break
            nested_lines.append((indent, nested.strip()))

        if not nested_lines:
            return False

        direct_indent = min(indent for indent, _ in nested_lines)
        for indent, item in nested_lines:
            if indent != direct_indent:
                continue
            if item.startswith("-"):
                item = item[1:].strip()
            key = item.split(":", 1)[0].strip().strip("'\"").lower()
            if key in DEFAULT_WORKFLOW_TRIGGERS:
                return True
        return False
    return False


def default_workflow_paths(commit: str) -> set[Path]:
    result: set[Path] = set()
    for path in workflow_paths(commit):
        text = commit_text(commit, path)
        require(text is not None, f"workflow is not UTF-8 text at {commit}: {path}")
        if workflow_has_default_trigger(text):
            result.add(path)
    return result


def trusted_baseline_commit() -> str:
    """Resolve the v1 baseline from a ref that is external to the proposed PR head."""
    try:
        commit = run_git("rev-parse", "--verify", f"{TRUSTED_REF}^{{commit}}")
    except AuditFailure as exc:
        raise AuditFailure(
            f"trusted ref {TRUSTED_REF!r} unavailable; fetch the protected baseline before auditing"
        ) from exc

    version = commit_text(commit, Path("CONTRACT_VERSION"))
    require(version is not None and version.strip() == CONTRACT_VERSION, "trusted baseline contract identity changed")
    for path in PINNED_V1_PATHS:
        entry = tree_entry(commit, path)
        require(entry is not None, f"trusted baseline missing pinned artifact: {path}")
        mode, _ = entry
        require(mode == "100644", f"trusted baseline artifact is not regular mode 100644: {path}")
    return commit


def audit_required_files() -> None:
    for path in REQUIRED_FILES:
        target = ROOT / path
        require(not target.is_symlink(), f"required constitutional path is a symlink: {path}")
        require(target.is_file(), f"required constitutional path is not a regular file: {path}")
        mode, _ = head_entry(path)
        require(mode == "100644", f"required constitutional path mode changed: {path} mode={mode}")


def audit_pinned_v1_artifacts(baseline_commit: str) -> dict[Path, str]:
    """Require HEAD objects and raw checked-out bytes to equal the trusted baseline."""
    baseline_oids: dict[Path, str] = {}
    for path in PINNED_V1_PATHS:
        baseline = tree_entry(baseline_commit, path)
        require(baseline is not None, f"trusted baseline missing pinned artifact: {path}")
        baseline_mode, baseline_oid = baseline

        current_mode, current_oid = head_entry(path)
        require(current_mode == baseline_mode, f"pinned artifact mode changed: {path} mode={current_mode}")
        require(current_oid == baseline_oid, f"pinned v1 artifact changed without new contract identity: {path}")

        target = ROOT / path
        require(not target.is_symlink() and target.is_file(), f"pinned artifact is not a regular working-tree file: {path}")
        working_oid = run_git("hash-object", "--no-filters", "--", str(path))
        require(working_oid == baseline_oid, f"checked-out pinned artifact differs from v1 baseline: {path}")
        baseline_oids[path] = baseline_oid
    return baseline_oids


def audit_agent_policy_scope(baseline_commit: str) -> None:
    baseline = agent_policy_paths(baseline_commit)
    current = agent_policy_paths("HEAD")
    added = sorted(str(path) for path in current - baseline)
    removed = sorted(str(path) for path in baseline - current)
    require(not added, f"scoped AGENTS policy introduced outside trusted baseline: {added}")
    require(not removed, f"trusted AGENTS policy removed from HEAD: {removed}")


def audit_default_workflows(baseline_commit: str) -> None:
    """Only trusted-baseline automatic workflows may run on push/PR events."""
    baseline = default_workflow_paths(baseline_commit)
    current = default_workflow_paths("HEAD")
    added = sorted(str(path) for path in current - baseline)
    removed = sorted(str(path) for path in baseline - current)
    require(not added, f"default-triggered workflow introduced outside trusted baseline: {added}")
    require(not removed, f"trusted default-triggered workflow removed from HEAD: {removed}")

    for path in sorted(current, key=str):
        baseline_entry = tree_entry(baseline_commit, path)
        current_entry = tree_entry("HEAD", path)
        require(baseline_entry is not None and current_entry is not None, f"missing governed workflow: {path}")
        require(current_entry == baseline_entry, f"default-triggered workflow changed outside trusted baseline: {path}")


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
    engagement = read_text(ENGAGEMENT_DOCTRINE_PATH)
    readme = read_text(Path("README.md"))
    ai = read_text(README4AI_PATH)
    agents = read_text(AGENTS_PATH)
    security = read_text(SECURITY_PATH)

    require(CONTRACT_VERSION in core, "CORE_INVARIANTS does not name the contract")
    require(CONTRACT_VERSION in ai, "README4AI does not name the contract")
    require("ALLOW < REVIEW < DENY" in core, "CORE_INVARIANTS lost the decision lattice")
    require("Proof first. Reuse second." in core, "CORE_INVARIANTS lost the optimization rule")
    require("deception outward, truth inward" in core.lower(), "CORE_INVARIANTS lost the truth rule")
    require("canonicalize before authorization" in parser.lower(), "PARSER_DOCTRINE lost canonicalization-before-authorization")
    for effect in ("DISRUPT", "TURN", "FIX", "BLOCK"):
        require(effect in engagement, f"ENGAGEMENT_AREA lost defensive effect {effect}")

    # Readable diagnostics; the complete policy documents are baseline-pinned above.
    security_lower = security.lower()
    require(
        "default ci inspects them only with bounded, non-executing mechanisms" in security_lower,
        "SECURITY.md lost the non-executing default-CI boundary",
    )
    require("workflow_dispatch" in security_lower, "SECURITY.md lost the opt-in adversarial execution boundary")
    require("never `pull_request`" in security_lower, "SECURITY.md permits adversarial execution on pull_request")

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

    provenance = read_text(HERESY_PROVENANCE_PATH)
    archive_readme = read_text(ARCHIVE_README_PATH)
    for text, label in ((provenance, "HERESY provenance"), (archive_readme, "archive README")):
        require(str(size) in text, f"{label} lost archive size")
        require(oid in text, f"{label} lost archive object identity")
    return oid, size


def main() -> int:
    try:
        audit_required_files()
        baseline_commit = trusted_baseline_commit()
        baseline_oids = audit_pinned_v1_artifacts(baseline_commit)
        audit_agent_policy_scope(baseline_commit)
        audit_default_workflows(baseline_commit)
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
        f"invariants={len(EXPECTED_IDS)} trusted_ref={TRUSTED_REF} baseline={baseline_commit}"
    )
    print(
        "heresy_archive=PASS "
        f"path={ARCHIVE_PATH} size={archive_size} git_oid={archive_oid}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
