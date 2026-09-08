"""Regression for bounded reconstruction of case-derived hardening results."""

from __future__ import annotations

from pathlib import Path
import unittest

import blue_forge
import blue_forge.core as core


class LatestResultBindingBudgetTests(unittest.TestCase):
    def _reconstruct(self, binding: bytes):
        result_type = blue_forge.HardeningResult
        tuple_base = result_type.__base__
        self.assertEqual(tuple_base.__name__, "tuple")
        # Resolve the actual base allocator in the implementation interpreter.
        # A worker-local tuple.__new__ cannot accept an opaque RPC type handle.
        # Read the class dictionary so the proxy's own inherited __new__ is not
        # selected. This still bypasses HardeningResult.__new__ and __init__.
        allocator = tuple_base.__dict__["__new__"]
        return allocator(result_type, (binding,))

    def _reference_case(self):
        fixture = Path(__file__).resolve().parents[1] / "fixtures/v1/path-traversal-case.json"
        return blue_forge.HardeningCase.from_dict(
            core.loads_strict(fixture.read_text(encoding="utf-8"))
        )

    def test_reconstructed_result_binding_is_bounded_before_utf8_decode(self) -> None:
        oversized = b"\xff" * (core.MAX_JSON_BYTES + 1)
        reconstructed = self._reconstruct(oversized)

        with self.assertRaisesRegex(
            blue_forge.ValidationError,
            rf"hardening result case binding exceeds {core.MAX_JSON_BYTES} bytes",
        ):
            _ = reconstructed.hardened

    def test_all_result_consumers_reject_oversized_binding(self) -> None:
        reconstructed = self._reconstruct(b"\xff" * (core.MAX_JSON_BYTES + 1))
        message = rf"hardening result case binding exceeds {core.MAX_JSON_BYTES} bytes"
        for attribute in ("payload", "receipt_sha256"):
            with self.subTest(attribute=attribute):
                with self.assertRaisesRegex(blue_forge.ValidationError, message):
                    getattr(reconstructed, attribute)
        with self.assertRaisesRegex(blue_forge.ValidationError, message):
            blue_forge.regression_record(self._reference_case(), reconstructed)

    def test_exact_byte_limit_reaches_utf8_validation(self) -> None:
        reconstructed = self._reconstruct(b"\xff" * core.MAX_JSON_BYTES)
        with self.assertRaisesRegex(
            blue_forge.ValidationError, "^hardening result case binding is invalid$"
        ):
            _ = reconstructed.hardened

    def test_valid_base_allocated_result_matches_evaluation(self) -> None:
        case = self._reference_case()
        evaluated = blue_forge.evaluate(case)
        reconstructed = self._reconstruct(evaluated._case_bytes)
        self.assertTrue(reconstructed.hardened)
        self.assertEqual(reconstructed.payload, evaluated.payload)
        self.assertEqual(reconstructed.receipt_sha256, evaluated.receipt_sha256)
        self.assertEqual(
            blue_forge.regression_record(case, reconstructed),
            blue_forge.regression_record(case, evaluated),
        )


if __name__ == "__main__":
    unittest.main()
