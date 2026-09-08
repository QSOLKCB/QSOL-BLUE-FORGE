"""Regression coverage for exact direct-case record types before field access."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict


FIXTURE = Path("fixtures/v1/path-traversal-case.json")


class DirectCaseRecordTypeTests(unittest.TestCase):
    def _case(self) -> HardeningCase:
        return HardeningCase.from_dict(
            loads_strict(FIXTURE.read_text(encoding="utf-8"))
        )

    def test_proposal_record_is_rejected_before_member_access(self) -> None:
        malformed = replace(self._case(), proposal=None)
        with self.assertRaisesRegex(
            ValidationError, "case.proposal must be an exact Proposal"
        ):
            evaluate(malformed)

    def test_verification_record_is_rejected_before_member_access(self) -> None:
        malformed = replace(self._case(), verification=None)
        with self.assertRaisesRegex(
            ValidationError, "case.verification must be an exact Verification"
        ):
            evaluate(malformed)

    def test_original_evidence_record_is_exact(self) -> None:
        case = self._case()
        verification = replace(case.verification, original=None)
        malformed = replace(case, verification=verification)
        with self.assertRaisesRegex(
            ValidationError, "verification.original must be an exact Evidence"
        ):
            evaluate(malformed)

    def test_variant_evidence_records_are_exact_before_id_access(self) -> None:
        case = self._case()
        verification = replace(case.verification, variants=(None,))
        malformed = replace(case, verification=verification)
        with self.assertRaisesRegex(
            ValidationError, "verification.variants entries must be exact Evidence"
        ):
            evaluate(malformed)

    def test_benign_evidence_records_are_exact_before_id_access(self) -> None:
        case = self._case()
        verification = replace(case.verification, benign_controls=(None,))
        malformed = replace(case, verification=verification)
        with self.assertRaisesRegex(
            ValidationError, "verification.benign_controls entries must be exact Evidence"
        ):
            evaluate(malformed)


if __name__ == "__main__":
    unittest.main()
