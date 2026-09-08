"""Regression coverage for the twenty-first Codex review round on PR #2."""

from __future__ import annotations

import unittest

from blue_forge import ValidationError, loads_strict


class CodexRoundTwentyOneTests(unittest.TestCase):
    def test_overlong_duplicate_key_fails_with_bounded_diagnostic(self) -> None:
        key = "k" * 400_000
        text = '{"' + key + '":0,"' + key + '":1}'
        self.assertLess(len(text.encode("utf-8")), 1024 * 1024)

        with self.assertRaises(ValidationError) as raised:
            loads_strict(text)

        diagnostic = str(raised.exception)
        self.assertIn("object key exceeds", diagnostic)
        self.assertLess(len(diagnostic), 128)

    def test_in_domain_duplicate_key_remains_rejected(self) -> None:
        with self.assertRaises(ValidationError) as raised:
            loads_strict('{"safe":0,"safe":1}')
        self.assertEqual(str(raised.exception), "duplicate JSON key")


if __name__ == "__main__":
    unittest.main()
