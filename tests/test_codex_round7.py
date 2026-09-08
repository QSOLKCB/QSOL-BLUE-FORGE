"""Regression coverage for the seventh Codex review round on PR #2."""

from __future__ import annotations

import copy
from pathlib import Path
import unittest

from blue_forge import (
    HardeningCase,
    ValidationError,
    canonical_bytes,
    canonical_text,
    digest,
    evaluate,
    loads_strict,
    regression_record,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"
ORIGINAL = "original:HOSTILE-PATH-001"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class FakeHardeningResult:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.receipt_sha256 = "0" * 64


class CodexRoundSevenTests(unittest.TestCase):
    def test_regression_record_rejects_duck_typed_result_receipt(self) -> None:
        case = HardeningCase.from_dict(fixture())
        result = evaluate(case)
        fake = FakeHardeningResult(result.payload)

        with self.assertRaisesRegex(ValidationError, "exact HardeningResult"):
            regression_record(case, fake)  # type: ignore[arg-type]

        record = regression_record(case, result)
        self.assertEqual(
            record["hardening_receipt_sha256"],
            result.payload["receipt_sha256"],
        )

    def test_canonicalization_enforces_integer_digit_ceiling(self) -> None:
        accepted = {"value": 10**128 - 1}
        self.assertEqual(loads_strict(canonical_text(accepted)), accepted)

        oversized = {"value": 10**128}
        for function in (canonical_bytes, canonical_text, digest):
            with self.subTest(function=function.__name__):
                with self.assertRaisesRegex(ValidationError, "128 decimal digits"):
                    function(oversized)

    def test_source_evidence_is_unique_across_all_coverage_roles(self) -> None:
        baseline = fixture()
        original_source = baseline["verification"]["original"][ORIGINAL]["source_sha256"]

        cases = []

        variant_reuse = copy.deepcopy(baseline)
        first_variant = next(iter(variant_reuse["verification"]["variants"].values()))
        first_variant["source_sha256"] = original_source
        cases.append(variant_reuse)

        benign_reuse = copy.deepcopy(baseline)
        first_benign = next(iter(benign_reuse["verification"]["benign_controls"].values()))
        first_benign["source_sha256"] = original_source
        cases.append(benign_reuse)

        duplicate_variants = copy.deepcopy(baseline)
        variant_values = list(duplicate_variants["verification"]["variants"].values())
        variant_values[1]["source_sha256"] = variant_values[0]["source_sha256"]
        cases.append(duplicate_variants)

        for value in cases:
            with self.subTest(case=value["case_id"]):
                with self.assertRaisesRegex(
                    ValidationError,
                    "source_sha256 values must be unique across coverage roles",
                ):
                    HardeningCase.from_dict(value)


if __name__ == "__main__":
    unittest.main()
