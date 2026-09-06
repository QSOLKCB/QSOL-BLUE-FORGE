from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

from blue_forge import HardeningCase, ValidationError


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "v1" / "path-traversal-case.json"
SUPERVISOR = ROOT / "scripts" / "run_frozen_tests_supervised.py"


def _load_supervisor():
    spec = importlib.util.spec_from_file_location("blue_forge_round17_supervisor", SUPERVISOR)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load trusted supervisor module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CodexRoundSeventeenTests(unittest.TestCase):
    def test_case_factory_rejects_list_subclass_before_iteration(self) -> None:
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))

        class ExplodingList(list):
            def __len__(self):
                return 0

            def __iter__(self):
                raise AssertionError("list subclass iterator must never be consumed")

        raw["proposal"]["requested_authority"] = ExplodingList()
        with self.assertRaisesRegex(ValidationError, "exact list"):
            HardeningCase.from_dict(raw)

    def test_isolated_worker_imports_only_the_sterile_proposed_root(self) -> None:
        supervisor = _load_supervisor()
        supervisor._self_test_import_path(sys.executable, 10)

    def test_real_unittest_monkeypatch_cannot_neutralize_frozen_assertions(self) -> None:
        supervisor = _load_supervisor()
        supervisor._self_test_assertion_isolation(sys.executable, 10)

    def test_worker_output_is_not_buffered_in_trusted_memory(self) -> None:
        supervisor = _load_supervisor()
        captured: dict[str, object] = {}

        class Completed:
            returncode = 0

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return Completed()

        original = supervisor.subprocess.run
        supervisor.subprocess.run = fake_run
        try:
            supervisor.run_one(
                ROOT,
                sys.executable,
                ("test_fake", "FakeTests", "test_fake"),
                1,
            )
        finally:
            supervisor.subprocess.run = original

        self.assertEqual(captured["stdout"], subprocess.DEVNULL)
        self.assertEqual(captured["stderr"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
