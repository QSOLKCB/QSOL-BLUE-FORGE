"""Regression coverage for the fifth Codex review round on PR #2."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict, regression_record

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"
SCHEMA = ROOT / "schemas/hardening-case-v1.schema.json"
DOC = ROOT / "docs/REFERENCE_CORE.md"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundFiveTests(unittest.TestCase):
    def test_regression_record_is_independent_of_evidence_map_order(self) -> None:
        left_value = fixture()
        right_value = copy.deepcopy(left_value)
        right_value["verification"]["variants"] = dict(
            reversed(list(right_value["verification"]["variants"].items()))
        )
        right_value["verification"]["benign_controls"] = dict(
            reversed(list(right_value["verification"]["benign_controls"].items()))
        )

        left_case = HardeningCase.from_dict(left_value)
        right_case = HardeningCase.from_dict(right_value)
        left_result = evaluate(left_case)
        right_result = evaluate(right_case)

        self.assertEqual(left_result.payload["case_sha256"], right_result.payload["case_sha256"])
        self.assertEqual(left_result.receipt_sha256, right_result.receipt_sha256)
        self.assertEqual(
            regression_record(left_case, left_result),
            regression_record(right_case, right_result),
        )

    def test_schema_explicitly_rejects_python_strip_edge_whitespace(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        nonempty = schema["$defs"]["nonempty"]
        explicit = nonempty["allOf"][0]["pattern"]
        compiled = re.compile(explicit)

        for invalid in ("\u0085", "\u001c", "\u00a0", "\u3000", "\u0085value", "value\u001c"):
            with self.subTest(invalid=repr(invalid)):
                self.assertIsNone(compiled.fullmatch(invalid))

        self.assertIsNotNone(compiled.fullmatch("value with internal spaces"))

        value = fixture()
        value["case_id"] = "\u0085"
        with self.assertRaisesRegex(ValidationError, "non-empty trimmed string"):
            HardeningCase.from_dict(value)

    def test_replay_documentation_states_case_wide_engine_pin(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("same pinned reference engine identity", text)
        self.assertIn("replay_engine_sha256", text)
        self.assertIn("reference_engine_sha256", text)

    def test_large_valid_evidence_case_can_emit_regression_record(self) -> None:
        value = fixture()
        variant_template = next(iter(value["verification"]["variants"].values()))
        benign_template = next(iter(value["verification"]["benign_controls"].values()))

        value["verification"]["variants"] = {
            f"variant:V{index:03d}": copy.deepcopy(variant_template)
            for index in range(128)
        }
        value["verification"]["benign_controls"] = {
            f"benign:B{index:03d}": copy.deepcopy(benign_template)
            for index in range(128)
        }

        case = HardeningCase.from_dict(value)
        result = evaluate(case)
        self.assertTrue(result.hardened)
        record = regression_record(case, result)

        self.assertEqual(len(record["hostile_evidence_ids"]), 129)
        self.assertEqual(len(record["benign_control_ids"]), 128)
        self.assertEqual(len(record["source_sha256"]), 257)
        self.assertEqual(len(record["reference_engine_sha256"]), 257)
        self.assertEqual(len(record["replay_engine_sha256"]), 257)
        self.assertRegex(record["record_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
