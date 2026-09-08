"""Regressions for the September 2026 Astra review findings."""

from __future__ import annotations

from pathlib import Path
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict

CURRENT_SUITE_ONLY = True
ROOT = Path(__file__).resolve().parents[1]
CASE_PATH = ROOT / "fixtures" / "v1" / "path-traversal-case.json"


class AstraReviewRegressions(unittest.TestCase):
    def _case_value(self):
        return loads_strict(CASE_PATH.read_text(encoding="utf-8"))

    def _case(self):
        return HardeningCase.from_dict(self._case_value())

    def _delete_required_attr(self, value, name):
        # Ordinary/direct execution receives the actual frozen dataclass and can
        # bypass its generated __delattr__ through object.__delattr__. Supervised
        # execution receives an actor proxy; object.__delattr__ then fails on the
        # proxy itself, so fall back to its bridged __delattr__ operation. In both
        # paths the deletion occurs on the exact proposed dataclass instance.
        try:
            object.__delattr__(value, name)
        except AttributeError:
            delattr(value, name)

    def test_deleted_direct_case_field_uses_validation_error(self):
        case = self._case()
        self._delete_required_attr(case, "proposal")
        with self.assertRaises(ValidationError):
            evaluate(case)

    def test_deleted_nested_field_uses_validation_error(self):
        case = self._case()
        self._delete_required_attr(case.verification, "original")
        with self.assertRaises(ValidationError):
            evaluate(case)

    def test_oversized_unexpected_key_has_bounded_diagnostic(self):
        value = self._case_value()
        oversized = "x" * 5000
        value[oversized] = None
        with self.assertRaises(ValidationError) as caught:
            HardeningCase.from_dict(value)
        message = str(caught.exception)
        self.assertLess(len(message), 256)
        self.assertNotIn(oversized, message)
        self.assertIn("object key exceeds", message)


if __name__ == "__main__":
    unittest.main()
