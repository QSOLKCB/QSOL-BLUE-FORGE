"""Regression coverage for the sixth Codex review round on PR #2."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from blue_forge import HardeningCase, loads_strict

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"
SCHEMA = ROOT / "schemas/hardening-case-v1.schema.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundSixTests(unittest.TestCase):
    def test_schema_and_runtime_agree_on_bom_edges(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        nonempty = schema["$defs"]["nonempty"]
        self.assertNotIn("pattern", nonempty)
        explicit = re.compile(nonempty["allOf"][0]["pattern"])

        for case_id in ("\ufeffvalue", "value\ufeff"):
            with self.subTest(case_id=repr(case_id)):
                self.assertIsNotNone(explicit.fullmatch(case_id))
                value = fixture()
                value["case_id"] = case_id
                parsed = HardeningCase.from_dict(value)
                self.assertEqual(parsed.case_id, case_id)


if __name__ == "__main__":
    unittest.main()
