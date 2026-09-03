"""Regression coverage for the latest constitutional trust-boundary findings."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE_TEST = HERE / "test_audit_constitution.py"


def load_base_tests():
    spec = importlib.util.spec_from_file_location("blue_forge_latest_base_tests", BASE_TEST)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load base constitutional audit tests")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base_tests()


class LatestTrustBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        base.git(self.repo, "init", "-b", "main")
        base.populate(self.repo, base.registry())
        base.git(self.repo, "add", "-A")
        base.git(self.repo, "commit", "-m", "trusted v1 baseline")
        base.git(self.repo, "checkout", "-b", "work")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_audit(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [os.fspath(Path(os.sys.executable)), "scripts/audit_constitution.py"],
            cwd=self.repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **base.GIT_ENV, "BLUE_FORGE_TRUSTED_REF": "main"},
        )

    def assert_fails(self, fragment: str) -> None:
        result = self.run_audit()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(fragment, result.stderr)

    def test_unicode_workflow_path_is_governed_losslessly(self) -> None:
        base.write(
            self.repo,
            ".github/workflows/é.yml",
            "name: unicode automatic workflow\n"
            "on: push\n"
            "jobs:\n"
            "  execute:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: unzip archive/HERESY-SEC-0.3.0.zip -d /tmp/heresy\n",
        )
        base.git(self.repo, "add", ".github/workflows/é.yml")
        base.git(self.repo, "commit", "-m", "add unicode automatic workflow")
        self.assert_fails("default-triggered workflow introduced outside trusted baseline")

    def test_root_flow_mapping_is_governed_fail_closed(self) -> None:
        base.write(
            self.repo,
            ".github/workflows/flow.yml",
            "{on: [push], jobs: {execute: {runs-on: ubuntu-latest, steps: [{run: 'echo forbidden'}]}}}\n",
        )
        base.git(self.repo, "add", ".github/workflows/flow.yml")
        base.git(self.repo, "commit", "-m", "add root flow automatic workflow")
        self.assert_fails("default-triggered workflow introduced outside trusted baseline")

    def test_mixed_inline_mapping_is_governed_fail_closed(self) -> None:
        base.write(
            self.repo,
            ".github/workflows/mixed-flow.yml",
            "name: mixed flow\n"
            "on: {workflow_dispatch: {}, push: {}}\n"
            "jobs:\n"
            "  execute:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo forbidden\n",
        )
        base.git(self.repo, "add", ".github/workflows/mixed-flow.yml")
        base.git(self.repo, "commit", "-m", "add mixed flow automatic workflow")
        self.assert_fails("default-triggered workflow introduced outside trusted baseline")

    def test_trusted_regression_module_cannot_be_deleted(self) -> None:
        base.git(self.repo, "checkout", "main")
        base.write(self.repo, "tests/test_floor.py", "def test_floor():\n    assert True\n")
        base.git(self.repo, "add", "tests/test_floor.py")
        base.git(self.repo, "commit", "-m", "add trusted regression floor")

        base.git(self.repo, "checkout", "work")
        base.git(self.repo, "checkout", "main", "--", "tests/test_floor.py")
        base.git(self.repo, "commit", "-m", "carry trusted regression floor")
        passing = self.run_audit()
        self.assertEqual(passing.returncode, 0, passing.stdout + passing.stderr)

        (self.repo / "tests/test_floor.py").unlink()
        base.git(self.repo, "add", "-A")
        base.git(self.repo, "commit", "-m", "delete trusted regression floor")
        self.assert_fails("trusted regression test removed from HEAD")

    def test_new_regression_test_symlink_is_rejected(self) -> None:
        tests_dir = self.repo / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        link_path = tests_dir / "test_archive.py"
        link_path.symlink_to("../archive/HERESY-SEC-0.3.0.zip")
        base.git(self.repo, "add", "tests/test_archive.py")
        base.git(self.repo, "commit", "-m", "add symlinked regression test")
        self.assert_fails("regression test is not regular mode 100644")

    def test_additive_successor_contract_uses_trusted_authorization(self) -> None:
        successor_version = "blue-forge.core-invariants/v2"
        manifest_path = "contracts/migrations/v1-to-v2.json"
        successor_path = "contracts/core-invariants-v2.json"
        evidence_path = "conformance/v2-migration.txt"
        successor_content = json.dumps(
            {"schema": successor_version, "extends": base.CONTRACT}, indent=2
        ) + "\n"
        evidence_content = "v1 preserved; successor evidence present\n"

        base.git(self.repo, "checkout", "main")
        base.write(self.repo, successor_path, successor_content)
        successor_oid = base.git(self.repo, "hash-object", "--", successor_path)
        (self.repo / successor_path).unlink()
        base.write(self.repo, evidence_path, evidence_content)
        evidence_oid = base.git(self.repo, "hash-object", "--", evidence_path)
        (self.repo / evidence_path).unlink()

        manifest = {
            "schema": "blue-forge.contract-migration/v1",
            "from": base.CONTRACT,
            "to": successor_version,
            "mode": "additive-preserve-v1",
            "successor_contract_files": [
                {"path": successor_path, "git_oid": successor_oid}
            ],
            "conformance_evidence": [
                {"path": evidence_path, "git_oid": evidence_oid}
            ],
        }
        base.write(self.repo, manifest_path, json.dumps(manifest, indent=2) + "\n")
        base.git(self.repo, "add", manifest_path)
        base.git(self.repo, "commit", "-m", "authorize additive v2 migration")

        base.git(self.repo, "checkout", "work")
        base.git(self.repo, "checkout", "main", "--", manifest_path)
        base.write(self.repo, "CONTRACT_VERSION", successor_version + "\n")
        base.write(self.repo, successor_path, successor_content)
        base.write(self.repo, evidence_path, evidence_content)
        base.git(self.repo, "add", "-A")
        base.git(self.repo, "commit", "-m", "propose additive v2 contract")

        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"contract={successor_version}", result.stdout)
        self.assertIn(f"migration={manifest_path}", result.stdout)

        base.write(
            self.repo,
            successor_path,
            json.dumps(
                {"schema": successor_version, "extends": base.CONTRACT, "unknown": "ALLOW"},
                indent=2,
            ) + "\n",
        )
        base.git(self.repo, "add", successor_path)
        base.git(self.repo, "commit", "-m", "tamper authorized successor bytes")
        self.assert_fails("authorized migration artifact object mismatch")

    def test_untrusted_successor_contract_is_rejected(self) -> None:
        base.write(self.repo, "CONTRACT_VERSION", "blue-forge.core-invariants/v2\n")
        base.git(self.repo, "add", "CONTRACT_VERSION")
        base.git(self.repo, "commit", "-m", "change contract without authorization")
        self.assert_fails("expected exactly one trusted migration authorization")


if __name__ == "__main__":
    unittest.main()
