"""Regression coverage for the nineteenth Codex review round on PR #2."""

from __future__ import annotations

import unittest

from blue_forge import HardeningCase, ValidationError


class CodexRoundNineteenTests(unittest.TestCase):
    def test_case_factory_bounds_exact_object_before_field_scan(self) -> None:
        # This is an exact built-in dict, not a subclass. The shared 512-member
        # ceiling must fire before _exact_keys() builds/scans the unexpected-key
        # set, preserving the programmatic resource boundary.
        oversized = {f"unexpected_{index:04d}": None for index in range(513)}
        with self.assertRaisesRegex(ValidationError, "case exceeds 512 members"):
            HardeningCase.from_dict(oversized)


if __name__ == "__main__":
    unittest.main()
