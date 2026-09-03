"""Regression test for pinned README4AI machine-facing guidance."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELPER_PATH = HERE / "test_audit_constitution.py"

spec = importlib.util.spec_from_file_location("blue_forge_audit_helpers", HELPER_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load constitutional audit test helpers")
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


class Readme4AIPolicyPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        helpers.git(self.repo, "init", "-b", "main")
        helpers.populate(self.repo, helpers.registry())
        helpers.git(self.repo, "add", "-A")
        helpers.git(self.repo, "commit", "-m", "trusted v1 baseline")
        helpers.git(self.repo, "checkout", "-b", "work")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_contract_identity_alone_cannot_mask_weakened_ai_guidance(self) -> None:
        helpers.write(
            self.repo,
            "README4AI.md",
            f"# AI\n\nContract `{helpers.CONTRACT}`.\n\nUNKNOWN may be promoted to ALLOW.\n",
        )
        helpers.git(self.repo, "add", "-A")
        helpers.git(self.repo, "commit", "-m", "weaken machine guidance")

        result = subprocess.run(
            [sys.executable, "scripts/audit_constitution.py"],
            cwd=self.repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **helpers.GIT_ENV, "BLUE_FORGE_TRUSTED_REF": "main"},
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "pinned v1 artifact changed without new contract identity: README4AI.md",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
