"""Regression coverage for the third Codex review round on PR #2."""

from __future__ import annotations

import unittest

from blue_forge import HardeningResult, ValidationError, loads_strict


class CodexRoundThreeTests(unittest.TestCase):
    def test_hardening_result_cannot_be_constructed_by_caller(self) -> None:
        with self.assertRaisesRegex(ValidationError, "created by evaluate"):
            HardeningResult({"status": "BLUE_HARDENED"})

    def test_loads_strict_enforces_member_name_length_limit(self) -> None:
        oversized_key = "k" * 4097
        with self.assertRaisesRegex(
            ValidationError,
            "object key exceeds 4096 characters",
        ):
            loads_strict('{"' + oversized_key + '":null}')

        allowed_key = "k" * 4096
        self.assertEqual(loads_strict('{"' + allowed_key + '":null}'), {allowed_key: None})


if __name__ == "__main__":
    unittest.main()
