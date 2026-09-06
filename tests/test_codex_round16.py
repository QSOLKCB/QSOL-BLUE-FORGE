"""Regression coverage for the sixteenth Codex review round on PR #2."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class ExplodingFrozenSet(frozenset[str]):
    def __iter__(self):  # type: ignore[override]
        raise AssertionError("malformed authority container was iterated before preflight")


class CodexRoundSixteenTests(unittest.TestCase):
    def test_direct_case_authority_container_is_rejected_before_sorting(self) -> None:
        case = HardeningCase.from_dict(fixture())
        malformed = ExplodingFrozenSet({"cap:read"})
        proposal = replace(case.proposal, requested_authority=malformed)
        forged = replace(case, proposal=proposal)

        with self.assertRaisesRegex(
            ValidationError,
            r"proposal\.requested_authority must be an exact frozenset",
        ):
            evaluate(forged)

    def test_exact_bounded_frozenset_authority_still_evaluates(self) -> None:
        case = HardeningCase.from_dict(fixture())
        result = evaluate(case)
        self.assertIn(result.payload["status"], {"BLUE_HARDENED", "NOT_HARDENED"})


if __name__ == "__main__":
    unittest.main()
