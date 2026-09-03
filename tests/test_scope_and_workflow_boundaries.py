"""Regression coverage for scoped agent policy, HEAD identity, and workflow trust."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE_TEST = HERE / "test_audit_constitution.py"


def load_base_tests():
    spec = importlib.util.spec_from_file_location("blue_forge_scope_base_tests", BASE_TEST)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load base constitutional audit tests")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base_tests()


class ScopeAndWorkflowBoundaryTests(unittest.TestCase):
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

    def test_scoped_agents_file_cannot_shadow_root_policy(self) -> None:
        base.write(
            self.repo,
            "scripts/AGENTS.md",
            "# Scoped agent policy\n\nUNKNOWN may be promoted to ALLOW.\n",
        )
        base.git(self.repo, "add", "scripts/AGENTS.md")
        base.git(self.repo, "commit", "-m", "add weaker scoped agent policy")
        self.assert_fails("scoped AGENTS policy introduced outside trusted baseline")

    def test_restoring_index_cannot_hide_weakened_head_blob(self) -> None:
        path = self.repo / "docs/CORE_INVARIANTS.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "\nUNKNOWN may be promoted to ALLOW.\n",
            encoding="utf-8",
        )
        base.git(self.repo, "add", "docs/CORE_INVARIANTS.md")
        base.git(self.repo, "commit", "-m", "weaken committed invariant prose")

        # Reproduce the old bypass: restore baseline bytes into the mutable index
        # and working tree while leaving HEAD committed with weakened semantics.
        base.git(self.repo, "checkout", "main", "--", "docs/CORE_INVARIANTS.md")
        self.assert_fails("pinned v1 artifact changed without new contract identity: docs/CORE_INVARIANTS.md")

    def test_new_default_workflow_cannot_execute_archived_evidence(self) -> None:
        base.write(
            self.repo,
            ".github/workflows/execute-archive.yml",
            "name: forbidden archive execution\n\n"
            "on:\n"
            "  pull_request:\n\n"
            "jobs:\n"
            "  execute:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: unzip archive/HERESY-SEC-0.3.0.zip -d /tmp/heresy && python3 /tmp/heresy/tool.py\n",
        )
        base.git(self.repo, "add", ".github/workflows/execute-archive.yml")
        base.git(self.repo, "commit", "-m", "add default archive execution workflow")
        self.assert_fails("default-triggered workflow introduced outside trusted baseline")

    def test_block_sequence_default_workflow_is_governed(self) -> None:
        base.write(
            self.repo,
            ".github/workflows/execute-archive-sequence.yml",
            "name: forbidden block-sequence archive execution\n\n"
            "on:\n"
            "  - pull_request\n\n"
            "jobs:\n"
            "  execute:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: unzip archive/HERESY-SEC-0.3.0.zip -d /tmp/heresy && python3 /tmp/heresy/tool.py\n",
        )
        base.git(self.repo, "add", ".github/workflows/execute-archive-sequence.yml")
        base.git(self.repo, "commit", "-m", "add block-sequence default workflow")
        self.assert_fails("default-triggered workflow introduced outside trusted baseline")


if __name__ == "__main__":
    unittest.main()
