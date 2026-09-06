"""Literal v1 conformance vectors, independent of the proposed hash function.

These constants were computed from the trusted fixture and the documented v1
material using both hashlib.sha256 and OpenSSL SHA-256, not evaluate()/digest().
Changing the fixture, algorithm, or hashed material requires explicit governance.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from blue_forge import HardeningCase, canonical_bytes, digest, evaluate, loads_strict, regression_record

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/v1/path-traversal-case.json"
FIXTURE_SHA256 = "2f948514b66a7a935f3dbe029e4e9e8b5f75e4cc63a0d3d343f9476f55a7cb4e"
CASE_SHA256 = "7e2292d271c1aa87bb00e0fdc485985ef36ef8b62688a2f98ae33803d938f555"
RECEIPT_SHA256 = "342740a44021fc3a5dc660a825c106f7c7a4f9032170d4c98e07de097ad7247b"
RECORD_SHA256 = "866fd4987c2858814de9d7ccff955d18b4dad38e1abb62c66ee37f3e7e49cb61"


class V1GoldenReceiptTests(unittest.TestCase):
    def test_canonical_primitive_and_sha256_are_frozen(self) -> None:
        self.assertEqual(canonical_bytes(None), b"null")
        self.assertEqual(
            digest(None),
            "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
        )
        self.assertEqual(canonical_bytes({"b": [2, 1], "a": True}), b'{"a":true,"b":[2,1]}')

    def test_v1_case_result_and_regression_receipts_match_golden(self) -> None:
        raw = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), FIXTURE_SHA256)
        case = HardeningCase.from_dict(loads_strict(raw.decode("utf-8")))
        result = evaluate(case)
        record = regression_record(case, result)
        self.assertTrue(result.hardened)
        self.assertEqual(result.payload["case_sha256"], CASE_SHA256)
        self.assertEqual(result.receipt_sha256, RECEIPT_SHA256)
        self.assertEqual(record["case_sha256"], CASE_SHA256)
        self.assertEqual(record["hardening_receipt_sha256"], RECEIPT_SHA256)
        self.assertEqual(record["record_sha256"], RECORD_SHA256)
        self.assertEqual(len(record["hostile_evidence_ids"]), 3)
        self.assertEqual(len(record["benign_control_ids"]), 2)


if __name__ == "__main__":
    unittest.main()
