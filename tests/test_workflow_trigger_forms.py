"""Unit coverage for automatic GitHub Actions trigger recognition."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_SRC = REPO_ROOT / "scripts" / "audit_constitution.py"


def load_audit_module():
    spec = importlib.util.spec_from_file_location("blue_forge_workflow_trigger_audit", AUDIT_SRC)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load constitutional audit module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load_audit_module()


class WorkflowTriggerFormTests(unittest.TestCase):
    def test_automatic_trigger_forms_are_recognized(self) -> None:
        samples = (
            "on: pull_request\n",
            "on: schedule\n",
            "on: release\n",
            "on: workflow_run\n",
            "on: [workflow_dispatch, push]\n",
            "on: [workflow_dispatch, schedule]\n",
            "on:\n  pull_request:\n",
            "on:\n  schedule:\n    - cron: '0 0 * * *'\n",
            "on:\n  - pull_request\n  - workflow_dispatch\n",
            "'on':\n  - push\n",
            "{on: [push], jobs: {probe: {runs-on: ubuntu-latest, steps: []}}}\n",
            "{\"on\": [schedule], \"jobs\": {}}\n",
            "name: unsupported-without-recognized-on\njobs: {}\n",
        )
        for text in samples:
            with self.subTest(text=text):
                self.assertTrue(audit.workflow_has_default_trigger(text))

    def test_manual_only_workflow_is_not_default_triggered(self) -> None:
        samples = (
            "on: workflow_dispatch\n",
            "on: [workflow_dispatch]\n",
            "on: {workflow_dispatch: {}}\n",
            "on:\n  workflow_dispatch:\n",
            "on:\n  - workflow_dispatch\n",
        )
        for text in samples:
            with self.subTest(text=text):
                self.assertFalse(audit.workflow_has_default_trigger(text))


if __name__ == "__main__":
    unittest.main()
