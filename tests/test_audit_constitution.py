"""Regression tests for scripts/audit_constitution.py.

The suite builds disposable Git repositories, anchors v1 to a trusted baseline ref,
and verifies that semantic/provenance tampering fails closed while non-semantic prose
edits remain possible.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_SRC = REPO_ROOT / "scripts" / "audit_constitution.py"
CONTRACT = "blue-forge.core-invariants/v1"
ARCHIVE = Path("archive/HERESY-SEC-0.3.0.zip")
PREDICATES = [
    "original_attack_neutralized",
    "attack_class_invariant_holds",
    "benign_controls_pass",
    "provenance_valid",
    "verification_complete",
    "replay_exact",
    "authority_not_expanded",
    "reference_equivalence_preserved",
]
NAMES = [
    "Authority Cannot Silently Expand",
    "Defensive Decisions Are Monotonic",
    "No Self-Certification",
    "Provenance Before Interpretation",
    "Evidence Is Data",
    "Replay Failure Is Verification Failure",
    "Benign Behaviour Must Survive",
    "Unknown Is Not Safe",
    "Resource Exhaustion Cannot Produce Verification",
    "Optimisation Cannot Reduce the Proof Surface",
    "Parallelism Is Semantically Invisible",
    "Model Agreement Is Not Proof",
    "Semantic Changes Require New Contract Identity",
    "No Silent Degradation",
    "Deception Outward, Truth Inward",
    "Minimum Necessary Intervention",
]
GIT_ENV = {
    "GIT_AUTHOR_NAME": "blue-forge-test",
    "GIT_AUTHOR_EMAIL": "blue-forge-test@example.invalid",
    "GIT_COMMITTER_NAME": "blue-forge-test",
    "GIT_COMMITTER_EMAIL": "blue-forge-test@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **GIT_ENV, **(env or {})},
    )
    return completed.stdout.strip()


def write(repo: Path, relative: str | Path, content: str | bytes) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def registry() -> dict:
    return {
        "schema": CONTRACT,
        "status": "constitutional",
        "decision_order": ["ALLOW", "REVIEW", "DENY"],
        "blue_hardened": {"all_of": list(PREDICATES)},
        "invariants": [
            {
                "id": f"BF-INV-{index:03d}",
                "name": name,
                "rule": f"Rule {index}.",
                "failure_state": "DENY",
                "constitutional": True,
            }
            for index, name in enumerate(NAMES, start=1)
        ],
    }


def core_markdown(value: dict) -> str:
    header = (
        f"# Core Invariants\n\nNormative contract: `{CONTRACT}`\n\n"
        "```text\nALLOW < REVIEW < DENY\n```\n\n"
        "```text\n" + "\n".join(PREDICATES) + "\n```\n\n"
        "**Proof first. Reuse second.**\n\nDeception outward, truth inward.\n\n"
    )
    bodies = "\n".join(
        f"## {item['id']} - {item['name']}\n\n{item['rule']}\n" for item in value["invariants"]
    )
    return header + bodies


def readme_markdown(value: dict) -> str:
    return (
        "# Repo\n\n"
        + "\n".join(item["id"] for item in value["invariants"])
        + "\n\n"
        + "\n".join(PREDICATES)
        + "\n"
    )


def populate(repo: Path, value: dict) -> None:
    write(repo, "CONTRACT_VERSION", CONTRACT + "\n")
    write(repo, "contracts/core-invariants-v1.json", json.dumps(value, indent=2) + "\n")
    write(repo, "docs/CORE_INVARIANTS.md", core_markdown(value))
    write(repo, "README.md", readme_markdown(value))
    write(repo, "README4AI.md", f"# AI\n\nContract `{CONTRACT}`. HERESY verify.\n")
    write(
        repo,
        "AGENTS.md",
        "# AGENTS\n\nRead `contracts/core-invariants-v1.json`.\n"
        "Run `python3 scripts/audit_constitution.py`.\n",
    )
    write(
        repo,
        "SECURITY.md",
        "# Security\n\nDefault CI inspects them only with bounded, non-executing mechanisms.\n"
        "Execution is opt-in through `workflow_dispatch`, never `pull_request`.\n",
    )
    write(
        repo,
        "CODE_OF_ETHICS.md",
        "# Ethics\n\nNo hack-back. No retaliation. No third-party damage.\n",
    )
    write(repo, "LICENSE", "Mozilla Public License Version 2.0\n")
    write(
        repo,
        "doctrine/ENGAGEMENT_AREA.md",
        "# Engagement\n\nDISRUPT TURN FIX BLOCK\n\nTURN may only preserve or reduce authority.\n",
    )
    write(repo, "doctrine/PARSER_DOCTRINE.md", "# Parser\n\nCanonicalize before authorization.\n")
    write(repo, ".github/workflows/constitution.yml", "name: Constitutional Contract\non: [push]\njobs: {}\n")
    write(repo, "scripts/audit_constitution.py", AUDIT_SRC.read_text(encoding="utf-8"))

    archive_path = repo / ARCHIVE
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w") as bundle:
        bundle.writestr("README.txt", "synthetic provenance bundle\n")
    size = archive_path.stat().st_size
    oid = git(repo, "hash-object", "--", str(ARCHIVE))
    provenance = (
        "# Provenance\n\n"
        f"size: {size} bytes\nGitHub blob object id: {oid}\n"
        "source project: https://github.com/QSOLKCB/HERESY-SEC\n"
        "trust status: source provenance; not an automatically trusted dependency or executable fixture\n"
    )
    write(repo, "docs/HERESY_PROVENANCE.md", provenance)
    write(repo, "archive/readme.md", provenance)


def load_audit_module():
    spec = importlib.util.spec_from_file_location("blue_forge_audit_under_test", AUDIT_SRC)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load audit module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConstitutionalAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        git(self.repo, "init", "-b", "main")
        populate(self.repo, registry())
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "trusted v1 baseline")
        git(self.repo, "checkout", "-b", "work")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_audit(self, trusted_ref: str = "main") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [os.fspath(Path(os.sys.executable)), "scripts/audit_constitution.py"],
            cwd=self.repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **GIT_ENV, "BLUE_FORGE_TRUSTED_REF": trusted_ref},
        )

    def commit(self, message: str) -> None:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", message)

    def assert_fails(self, fragment: str, trusted_ref: str = "main") -> None:
        result = self.run_audit(trusted_ref)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(fragment, result.stderr)

    def test_clean_repository_passes(self) -> None:
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("constitution_audit=PASS", result.stdout)

    def test_registry_semantic_change_fails(self) -> None:
        value = registry()
        value["invariants"][7]["rule"] = "UNKNOWN may be promoted to ALLOW."
        write(self.repo, "contracts/core-invariants-v1.json", json.dumps(value, indent=2) + "\n")
        self.commit("weaken invariant")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_core_invariant_prose_change_fails(self) -> None:
        path = self.repo / "docs/CORE_INVARIANTS.md"
        path.write_text(path.read_text(encoding="utf-8") + "\nweakened meaning\n", encoding="utf-8")
        self.commit("change normative prose")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_parser_doctrine_change_fails(self) -> None:
        write(self.repo, "doctrine/PARSER_DOCTRINE.md", "# Parser\n\nAuthorize before canonicalization.\n")
        self.commit("weaken parser doctrine")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_engagement_doctrine_change_fails(self) -> None:
        write(
            self.repo,
            "doctrine/ENGAGEMENT_AREA.md",
            "# Engagement\n\nDISRUPT TURN FIX BLOCK\n\nTURN may silently increase authority.\n",
        )
        self.commit("weaken engagement doctrine")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_ethics_hack_back_policy_change_fails(self) -> None:
        write(
            self.repo,
            "CODE_OF_ETHICS.md",
            "# Ethics\n\nHack-back, retaliation, and third-party damage are permitted.\n",
        )
        self.commit("weaken ethics policy")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_security_contradictory_execution_policy_fails(self) -> None:
        path = self.repo / "SECURITY.md"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\nAdversarial execution is permitted on `pull_request` when sandboxed.\n",
            encoding="utf-8",
        )
        self.commit("contradict default CI boundary")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_provenance_trust_metadata_change_fails(self) -> None:
        path = self.repo / "docs/HERESY_PROVENANCE.md"
        original = path.read_text(encoding="utf-8")
        size_line = next(line for line in original.splitlines() if line.startswith("size:"))
        oid_line = next(line for line in original.splitlines() if line.startswith("GitHub blob object id:"))
        write(
            self.repo,
            "docs/HERESY_PROVENANCE.md",
            "# Provenance\n\n"
            f"{size_line}\n{oid_line}\n"
            "source project: https://example.invalid/not-heresy\n"
            "trust status: trusted executable production dependency\n",
        )
        self.commit("falsify provenance metadata")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_dirty_archive_bytes_fail(self) -> None:
        with (self.repo / ARCHIVE).open("ab") as handle:
            handle.write(b"x")
        self.assert_fails("checked-out pinned artifact differs from v1 baseline")

    def test_clean_filter_cannot_hide_raw_byte_change(self) -> None:
        write(self.repo, ".gitattributes", "docs/CORE_INVARIANTS.md text eol=lf\n")
        self.commit("configure line ending normalization")
        path = self.repo / "docs/CORE_INVARIANTS.md"
        raw = path.read_bytes()
        self.assertNotIn(b"\r\n", raw)
        path.write_bytes(raw.replace(b"\n", b"\r\n"))
        self.assert_fails("checked-out pinned artifact differs from v1 baseline")

    def test_required_path_directory_fails(self) -> None:
        path = self.repo / "SECURITY.md"
        path.unlink()
        path.mkdir()
        self.assert_fails("required constitutional path is not a regular file")

    def test_nonsemantic_readme_edit_is_allowed(self) -> None:
        path = self.repo / "README.md"
        path.write_text(path.read_text(encoding="utf-8") + "\nTypo-only clarification.\n", encoding="utf-8")
        self.commit("clarify readme")
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_security_execution_exception_fails(self) -> None:
        write(self.repo, "SECURITY.md", "# Security\n\nDefault CI may execute adversarial material.\n")
        self.commit("weaken default CI")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_forged_root_cannot_become_baseline(self) -> None:
        git(self.repo, "checkout", "--orphan", "forge")
        value = registry()
        value["invariants"][7]["rule"] = "UNKNOWN may be promoted after model votes."
        populate(self.repo, value)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "forged root")

        git(self.repo, "checkout", "work")
        git(self.repo, "merge", "--allow-unrelated-histories", "-s", "ours", "forge", "-m", "merge forged root")
        git(
            self.repo,
            "checkout",
            "forge",
            "--",
            "contracts/core-invariants-v1.json",
            "docs/CORE_INVARIANTS.md",
            "doctrine/PARSER_DOCTRINE.md",
        )
        self.commit("adopt forged semantics")
        self.assert_fails("pinned v1 artifact changed without new contract identity")

    def test_unavailable_trusted_ref_fails(self) -> None:
        self.assert_fails("trusted ref 'missing-ref' unavailable", trusted_ref="missing-ref")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        module = load_audit_module()
        with self.assertRaises(module.AuditFailure):
            module.load_json_text('{"schema":"a","schema":"b"}', "test registry")

    def test_constitutional_boolean_is_type_sensitive(self) -> None:
        module = load_audit_module()
        value = registry()
        value["invariants"][0]["constitutional"] = 1
        with self.assertRaises(module.AuditFailure):
            module.audit_registry(value)


if __name__ == "__main__":
    unittest.main()
