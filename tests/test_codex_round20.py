"""Regression coverage for the twentieth Codex review round on PR #2."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict


FIXTURE = Path("fixtures/v1/path-traversal-case.json")


class _ExplodingDecision:
    @property
    def value(self):
        raise AssertionError("decision.value was read before exact-type validation")


class _DuckDecision:
    value = "DENY"


class CodexRoundTwentyTests(unittest.TestCase):
    def _case(self) -> HardeningCase:
        value = loads_strict(FIXTURE.read_text(encoding="utf-8"))
        return HardeningCase.from_dict(value)

    def test_direct_proposal_decision_requires_exact_enum_before_value_access(self) -> None:
        case = self._case()
        malformed = replace(
            case,
            proposal=replace(case.proposal, decision=_ExplodingDecision()),
        )
        with self.assertRaisesRegex(
            ValidationError, "proposal.decision must be an exact Decision"
        ):
            evaluate(malformed)

    def test_direct_verification_decision_requires_exact_enum_before_value_access(self) -> None:
        case = self._case()
        malformed = replace(
            case,
            verification=replace(case.verification, decision=_ExplodingDecision()),
        )
        with self.assertRaisesRegex(
            ValidationError, "verification.decision must be an exact Decision"
        ):
            evaluate(malformed)

    def test_duck_typed_deny_cannot_be_normalized_into_blue_hardened(self) -> None:
        case = self._case()
        malformed = replace(
            case,
            proposal=replace(case.proposal, decision=_DuckDecision()),
            verification=replace(case.verification, decision=_DuckDecision()),
        )
        with self.assertRaises(ValidationError):
            evaluate(malformed)

    def test_valid_case_still_evaluates_blue_hardened(self) -> None:
        self.assertTrue(evaluate(self._case()).hardened)


if __name__ == "__main__":
    unittest.main()
