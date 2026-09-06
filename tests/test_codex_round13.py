"""Regression coverage for the thirteenth Codex review round on PR #2."""

from __future__ import annotations

import unittest

import blue_forge.core as core
from blue_forge import ValidationError, canonical_bytes, loads_strict


class CodexRoundThirteenTests(unittest.TestCase):
    def test_canonical_and_parser_byte_budgets_are_identical(self) -> None:
        self.assertEqual(core.MAX_CANONICAL_BYTES, core.MAX_JSON_TEXT_BYTES)
        self.assertEqual(core.MAX_CANONICAL_BYTES, core.MAX_JSON_BYTES)

        supported = {f"k{i:03d}": "x" * 4096 for i in range(200)}
        encoded = canonical_bytes(supported)
        self.assertLessEqual(len(encoded), core.MAX_JSON_BYTES)
        self.assertEqual(loads_strict(encoded.decode("utf-8")), supported)

        oversized = {f"k{i:03d}": "x" * 4096 for i in range(300)}
        with self.assertRaisesRegex(ValidationError, "canonical JSON exceeds"):
            canonical_bytes(oversized)


if __name__ == "__main__":
    unittest.main()
