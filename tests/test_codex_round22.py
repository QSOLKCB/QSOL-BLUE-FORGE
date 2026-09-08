"""Regression coverage for the twenty-second Codex review round on PR #2."""

from __future__ import annotations

import os
import unittest

from blue_forge import ValidationError, loads_strict


class CodexRoundTwentyTwoTests(unittest.TestCase):
    def test_float_tokens_have_bounded_diagnostics(self) -> None:
        # The independent direct suite exercises the exact near-1 MiB review
        # reproduction. The supervised current floor uses a still-large token
        # so the same diagnostic property is checked without spending its
        # aggregate sandbox lifetime moving ~900 KiB through the RPC bridge.
        digits = 64_000 if os.environ.get("BLUE_FORGE_SUPERVISED_MARKER") else 900_000
        token = "1." + ("0" * digits)
        self.assertLess(len(token.encode("utf-8")), 1024 * 1024)

        with self.assertRaises(ValidationError) as raised:
            loads_strict(token)

        diagnostic = str(raised.exception)
        self.assertEqual(diagnostic, "floating-point values are not allowed")
        self.assertLess(len(diagnostic), 128)
        self.assertNotIn(token[:4096], diagnostic)

        with self.assertRaisesRegex(
            ValidationError, "^floating-point values are not allowed$"
        ):
            loads_strict("1.5")


if __name__ == "__main__":
    unittest.main()
