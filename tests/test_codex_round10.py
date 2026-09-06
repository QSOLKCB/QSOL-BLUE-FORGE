"""Regression coverage for the tenth Codex review round on PR #2."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import unittest

from blue_forge import HardeningCase, HardeningResult, ValidationError, digest, evaluate, loads_strict

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"
SCHEMA = ROOT / "schemas/hardening-case-v1.schema.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundTenTests(unittest.TestCase):
    def test_private_result_factory_requires_originating_case_not_payload(self) -> None:
        case = HardeningCase.from_dict(fixture())
        genuine = evaluate(case)

        fabricated = copy.deepcopy(genuine.payload)
        fabricated["case_id"] = "invented-case"
        fabricated["case_sha256"] = "a" * 64
        material = dict(fabricated)
        material.pop("receipt_sha256")
        fabricated["receipt_sha256"] = digest(material)

        with self.assertRaisesRegex(ValidationError, "HardeningCase"):
            HardeningResult._from_evaluation(fabricated)  # type: ignore[arg-type]

        private_result = HardeningResult._from_evaluation(case)
        self.assertEqual(private_result.payload, genuine.payload)
        self.assertTrue(private_result.hardened)

    def test_schema_shared_string_domain_rejects_surrogate_codepoints(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        patterns = [item["pattern"] for item in schema["$defs"]["nonempty"]["allOf"]]
        surrogate_pattern = next(pattern for pattern in patterns if "D800" in pattern)
        compiled = re.compile(surrogate_pattern)

        self.assertIsNone(compiled.fullmatch("\ud800"))
        self.assertIsNone(compiled.fullmatch("left\udfff-right"))
        self.assertIsNotNone(compiled.fullmatch("valid-unicode-π"))


if __name__ == "__main__":
    unittest.main()
