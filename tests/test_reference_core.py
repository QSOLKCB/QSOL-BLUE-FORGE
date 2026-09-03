"""Regression coverage for the deterministic defensive reference core."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from blue_forge import (
    HardeningCase,
    ValidationError,
    canonical_text,
    digest,
    evaluate,
    loads_strict,
    regression_record,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class ReferenceCoreTests(unittest.TestCase):
    def test_reference_fixture_is_blue_hardened(self) -> None:
        result = evaluate(HardeningCase.from_dict(fixture()))
        self.assertTrue(result.hardened)
        self.assertEqual(result.payload["decision"], "DENY")
        self.assertEqual(result.payload["failed_predicates"], [])
        self.assertTrue(all(result.payload["predicates"].values()))

    def test_canonical_json_is_key_order_independent(self) -> None:
        left = {"b": [2, 1], "a": {"y": True, "x": None}}
        right = {"a": {"x": None, "y": True}, "b": [2, 1]}
        self.assertEqual(canonical_text(left), canonical_text(right))
        self.assertEqual(digest(left), digest(right))

    def test_duplicate_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValidationError, "duplicate JSON key"):
            loads_strict('{"schema":"a","schema":"b"}')

    def test_float_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "floating-point"):
            loads_strict('{"score":0.5}')

    def test_self_certification_is_rejected(self) -> None:
        value = fixture()
        value["verification"]["producer"] = value["proposal"]["producer"]
        with self.assertRaisesRegex(ValidationError, "sole verifier"):
            HardeningCase.from_dict(value)

    def test_monotonic_decision_is_enforced(self) -> None:
        value = fixture()
        value["proposal"]["decision"] = "DENY"
        value["verification"]["decision"] = "REVIEW"
        with self.assertRaisesRegex(ValidationError, "weakens proposal decision"):
            HardeningCase.from_dict(value)

    def test_unknown_cannot_be_hardened(self) -> None:
        value = fixture()
        value["verification"]["original"]["after"] = "UNKNOWN"
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(result.hardened)
        self.assertIn("verification_complete", result.payload["failed_predicates"])
        self.assertIn("original_attack_neutralized", result.payload["failed_predicates"])

    def test_authority_expansion_prevents_hardening(self) -> None:
        value = fixture()
        value["verification"]["observed_authority"].append("fs:read:system")
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(result.payload["predicates"]["authority_not_expanded"])
        self.assertFalse(result.hardened)

    def test_benign_control_regression_prevents_hardening(self) -> None:
        value = fixture()
        value["verification"]["benign_controls"][0]["after"] = "BLOCKED"
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(result.payload["predicates"]["benign_controls_pass"])

    def test_replay_divergence_prevents_hardening(self) -> None:
        value = fixture()
        value["verification"]["variants"][0]["replay_result_sha256"] = "0" * 64
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(result.payload["predicates"]["replay_exact"])

    def test_reference_divergence_prevents_hardening(self) -> None:
        value = fixture()
        value["verification"]["candidate_result_sha256"] = "1" * 64
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(
            result.payload["predicates"]["reference_equivalence_preserved"]
        )

    def test_regression_memory_is_deterministic(self) -> None:
        case = HardeningCase.from_dict(fixture())
        result = evaluate(case)
        self.assertEqual(
            regression_record(case, result),
            regression_record(case, result),
        )

    def test_duplicate_evidence_ids_are_rejected(self) -> None:
        value = fixture()
        value["verification"]["variants"][0]["id"] = value["verification"]["original"]["id"]
        with self.assertRaisesRegex(ValidationError, "duplicate evidence id"):
            HardeningCase.from_dict(value)

    def test_over_deep_json_fails_closed(self) -> None:
        value = "null"
        for _ in range(40):
            value = "[" + value + "]"
        with self.assertRaises(ValidationError):
            loads_strict(value)

    def test_input_is_not_mutated(self) -> None:
        value = fixture()
        before = copy.deepcopy(value)
        evaluate(HardeningCase.from_dict(value))
        self.assertEqual(value, before)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "blue_forge", *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_cli_verify_and_regression(self) -> None:
        verified = self.run_cli("verify", str(FIXTURE))
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout)["status"], "BLUE_HARDENED")

        memory = self.run_cli("regression", str(FIXTURE))
        self.assertEqual(memory.returncode, 0, memory.stderr)
        self.assertEqual(
            json.loads(memory.stdout)["schema"],
            "blue-forge.regression-record/v1",
        )

    def test_cli_incomplete_case_is_nonzero_and_not_allow(self) -> None:
        value = fixture()
        value["verification"]["original"]["after"] = "UNKNOWN"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "case.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_cli("verify", str(path))
        self.assertEqual(result.returncode, 3)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "NOT_HARDENED")
        self.assertNotEqual(payload["decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
