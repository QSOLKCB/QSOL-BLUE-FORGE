"""Regressions for the September 2026 Astra and Codex review findings."""

from __future__ import annotations

import dataclasses
import importlib
import os
from pathlib import Path
import unittest

import blue_forge
from blue_forge import (
    HardeningCase,
    ValidationError,
    evaluate,
    loads_strict,
    regression_record,
)

CURRENT_SUITE_ONLY = True
ROOT = Path(__file__).resolve().parents[1]
CASE_PATH = ROOT / "fixtures" / "v1" / "path-traversal-case.json"


class AstraReviewRegressions(unittest.TestCase):
    def _case_value(self):
        return loads_strict(CASE_PATH.read_text(encoding="utf-8"))

    def test_uninitialized_direct_case_uses_validation_error(self):
        if os.environ.get("BLUE_FORGE_SUPERVISED_MARKER"):
            # The supervised worker intentionally exposes proposed classes as
            # actor proxies, so local object.__new__(HardeningCase) would target
            # the proxy type rather than the proposed dataclass. Exercise the
            # same evaluator preflight through a transport-native malformed exact
            # HardeningCase: dataclasses.replace runs inside the actor and keeps
            # the top-level record type exact while invalidating a required field.
            case = HardeningCase.from_dict(self._case_value())
            malformed = dataclasses.replace(case, proposal=None)
        else:
            # The independent direct suite reproduces Astra's exact construction:
            # an exact HardeningCase allocated without any required attributes.
            malformed = object.__new__(HardeningCase)

        with self.assertRaises(ValidationError):
            evaluate(malformed)

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

    def test_result_patch_reinstall_preserves_regression_record(self):
        if os.environ.get("BLUE_FORGE_SUPERVISED_MARKER"):
            # Module reload itself is intentionally not proxied across the actor
            # boundary. Keep this execution mode as a transport-native positive
            # control; the independent direct suite below reproduces the reload.
            case = HardeningCase.from_dict(self._case_value())
            result = evaluate(case)
            record = regression_record(case, result)
        else:
            # Reproduce the reported public consumer path exactly. Before the
            # idempotence fix this stacked regression_record wrappers around
            # incompatible HardeningResult classes and failed here.
            package = importlib.reload(blue_forge)
            case = package.HardeningCase.from_dict(self._case_value())
            result = package.evaluate(case)
            record = package.regression_record(case, result)

        self.assertTrue(result.hardened)
        self.assertEqual(record["hardening_status"], "BLUE_HARDENED")
        self.assertEqual(
            record["hardening_receipt_sha256"], result.receipt_sha256
        )


if __name__ == "__main__":
    unittest.main()
