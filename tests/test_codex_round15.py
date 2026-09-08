"""Regression coverage for the fifteenth Codex review round on PR #2."""

from __future__ import annotations

from pathlib import Path
import unittest

import blue_forge.core as core
from blue_forge import HardeningCase, ValidationError, canonical_bytes, evaluate, loads_strict

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundFifteenTests(unittest.TestCase):
    def test_valid_case_origin_cannot_be_swapped_after_evaluation(self) -> None:
        failed_data = fixture()
        benign = next(iter(failed_data["verification"]["benign_controls"].values()))
        benign["after"] = "BLOCKED"
        failed_case = HardeningCase.from_dict(failed_data)
        result = evaluate(failed_case)
        self.assertFalse(result.hardened)

        hardened_case = HardeningCase.from_dict(fixture())
        hardened_case_bytes = canonical_bytes(core._case_input_material(hardened_case))
        self.assertTrue(evaluate(hardened_case).hardened)

        with self.assertRaises((AttributeError, TypeError)):
            object.__setattr__(result, "_case_bytes", hardened_case_bytes)

        self.assertFalse(result.hardened)
        self.assertEqual(result.payload["status"], "NOT_HARDENED")

    def test_canonicalization_rejects_mutating_container_subclasses(self) -> None:
        class ShiftingList(list):
            def __iter__(self):  # pragma: no cover - must never be trusted
                yield from range(300)

        value = ShiftingList(["validated-view"])
        with self.assertRaisesRegex(
            ValidationError,
            "exact built-in list/dict",
        ):
            canonical_bytes(value)

        self.assertEqual(canonical_bytes(["stable"]), b'["stable"]')


if __name__ == "__main__":
    unittest.main()
