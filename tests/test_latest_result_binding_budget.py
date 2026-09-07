"""Regression for bounded reconstruction of case-derived hardening results."""

from __future__ import annotations

import unittest

import blue_forge
import blue_forge.core as core


class LatestResultBindingBudgetTests(unittest.TestCase):
    def test_reconstructed_result_binding_is_bounded_before_utf8_decode(self) -> None:
        oversized = b"\xff" * (core.MAX_JSON_BYTES + 1)
        reconstructed = tuple.__new__(blue_forge.HardeningResult, (oversized,))

        with self.assertRaisesRegex(
            blue_forge.ValidationError,
            rf"hardening result case binding exceeds {core.MAX_JSON_BYTES} bytes",
        ):
            _ = reconstructed.hardened


if __name__ == "__main__":
    unittest.main()
