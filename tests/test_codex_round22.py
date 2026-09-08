"""Regression coverage for the twenty-second Codex review round on PR #2."""

from __future__ import annotations

import unittest

from blue_forge import ValidationError, loads_strict


class CodexRoundTwentyTwoTests(unittest.TestCase):
    def test_near_budget_float_token_has_bounded_diagnostic(self) -> None:
        token = "1." + ("0" * 900_000)
        self.assertLess(len(token.encode("utf-8")), 1024 * 1024)

        with self.assertRaises(ValidationError) as raised:
            loads_strict(token)

        diagnostic = str(raised.exception)
        self.assertEqual(diagnostic, "floating-point values are not allowed")
        self.assertLess(len(diagnostic), 128)
        self.assertNotIn(token[:4096], diagnostic)

    def test_ordinary_float_remains_rejected(self) -> None:
        with self.assertRaisesRegex(
            ValidationError, "^floating-point values are not allowed$"
        ):
            loads_strict("1.5")


if __name__ == "__main__":
    unittest.main()
