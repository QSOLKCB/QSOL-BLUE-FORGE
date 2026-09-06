"""Regression coverage for the eleventh Codex review round on PR #2."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import blue_forge.core as core
from blue_forge import (
    HardeningCase,
    HardeningResult,
    ValidationError,
    canonical_bytes,
    digest,
    evaluate,
    loads_strict,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundElevenTests(unittest.TestCase):
    def test_direct_result_constructor_recomputes_only_from_originating_case(self) -> None:
        case = HardeningCase.from_dict(fixture())
        genuine = evaluate(case)

        fabricated = copy.deepcopy(genuine.payload)
        fabricated["case_id"] = "nonexistent-case"
        fabricated["case_sha256"] = "a" * 64
        material = dict(fabricated)
        material.pop("receipt_sha256")
        fabricated["receipt_sha256"] = digest(material)

        with self.assertRaisesRegex(ValidationError, "originating HardeningCase"):
            HardeningResult(fabricated, _token=core._EVALUATION_TOKEN)  # type: ignore[arg-type]

        reconstructed = HardeningResult(case, _token=core._EVALUATION_TOKEN)
        self.assertEqual(reconstructed.payload, genuine.payload)
        self.assertTrue(reconstructed.hardened)

    def test_case_factory_enforces_shared_string_domain(self) -> None:
        oversized = fixture()
        oversized["case_id"] = "x" * 4097
        with self.assertRaisesRegex(ValidationError, "exceeds 4096 characters"):
            HardeningCase.from_dict(oversized)

        surrogate = fixture()
        surrogate["attack_class"] = "bad\ud800value"
        with self.assertRaisesRegex(ValidationError, "Unicode surrogate"):
            HardeningCase.from_dict(surrogate)

    def test_vocabulary_decision_types_fail_closed_in_cli(self) -> None:
        malformed = fixture()
        malformed["proposal"]["decision"] = []

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "malformed-decision.json"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "blue_forge", "verify", str(path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(completed.returncode, 2)
        self.assertNotIn(b"Traceback", completed.stderr)
        self.assertIn(b"decision", completed.stderr)
        self.assertIn(b"strings", completed.stderr)

    def test_canonicalization_has_cumulative_expansion_budget(self) -> None:
        value: object = "leaf"
        for _ in range(20):
            value = [value, value]

        with self.assertRaisesRegex(
            ValidationError,
            "expanded JSON exceeds|canonical JSON exceeds",
        ):
            canonical_bytes(value)

        modest: object = "leaf"
        for _ in range(10):
            modest = [modest, modest]
        encoded = canonical_bytes(modest)
        self.assertGreater(len(encoded), 0)
        self.assertLessEqual(len(encoded), core.MAX_CANONICAL_BYTES)


if __name__ == "__main__":
    unittest.main()
