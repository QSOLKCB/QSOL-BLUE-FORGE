"""Regression coverage for the fourth Codex review round on PR #2."""

from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import re
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"
SCHEMA = ROOT / "schemas/hardening-case-v1.schema.json"
ORIGINAL = "original:HOSTILE-PATH-001"
VARIANT = "variant:HOSTILE-PATH-ENCODED-001"
BENIGN = "benign:BENIGN-PATH-001"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundFourTests(unittest.TestCase):
    def test_evaluate_revalidates_directly_constructed_case(self) -> None:
        case = HardeningCase.from_dict(fixture())
        tampered_verification = replace(
            case.verification,
            producer=case.proposal.producer,
        )
        tampered_case = replace(case, verification=tampered_verification)
        with self.assertRaisesRegex(ValidationError, "sole verifier"):
            evaluate(tampered_case)

    def test_schema_uses_role_keyed_evidence_maps_for_global_unique_ids(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        defs = schema["$defs"]
        roles = {
            "originalEvidenceMap": "original:",
            "variantEvidenceMap": "variant:",
            "benignEvidenceMap": "benign:",
        }
        patterns = []
        for name, prefix in roles.items():
            definition = defs[name]
            self.assertEqual(definition["type"], "object")
            pattern = definition["propertyNames"]["pattern"]
            self.assertTrue(re.match(pattern, prefix + "ID"))
            patterns.append(re.compile(pattern))
        for evidence_id in (ORIGINAL, VARIANT, BENIGN):
            self.assertEqual(sum(bool(p.fullmatch(evidence_id)) for p in patterns), 1)

        with self.assertRaisesRegex(ValidationError, "duplicate JSON key"):
            loads_strict(
                '{"variant:ID":{"kind":"hostile"},'
                '"variant:ID":{"kind":"hostile"}}'
            )

    def test_replay_requires_same_pinned_engine_identity(self) -> None:
        baseline = HardeningCase.from_dict(fixture())
        baseline_result = evaluate(baseline)
        self.assertTrue(baseline_result.payload["predicates"]["replay_exact"])

        value = copy.deepcopy(fixture())
        value["verification"]["variants"][VARIANT]["replay_engine_sha256"] = "0" * 64
        changed = HardeningCase.from_dict(value)
        changed_result = evaluate(changed)
        self.assertFalse(changed_result.hardened)
        self.assertFalse(changed_result.payload["predicates"]["replay_exact"])
        self.assertNotEqual(
            baseline_result.payload["case_sha256"],
            changed_result.payload["case_sha256"],
        )
        self.assertNotEqual(baseline_result.receipt_sha256, changed_result.receipt_sha256)


if __name__ == "__main__":
    unittest.main()
