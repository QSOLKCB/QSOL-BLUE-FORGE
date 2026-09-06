"""Regression coverage for the ninth Codex review round on PR #2."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

import blue_forge.core as core
from blue_forge import (
    HardeningCase,
    ValidationError,
    canonical_bytes,
    evaluate,
    loads_strict,
)
from blue_forge.schema_vocabulary import (
    BLUE_FORGE_VOCABULARY,
    validate_case_schema_vocabulary,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"
SCHEMA = ROOT / "schemas/hardening-case-v1.schema.json"
META_SCHEMA = ROOT / "schemas/blue-forge-hardening-meta-v1.schema.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundNineTests(unittest.TestCase):
    def test_hardening_result_private_paths_still_require_originating_case(self) -> None:
        with self.assertRaisesRegex(ValidationError, "HardeningCase"):
            core.HardeningResult._from_evaluation({"status": "BLUE_HARDENED"})

        with self.assertRaisesRegex(ValidationError, "originating HardeningCase"):
            core.HardeningResult(
                {"status": "BLUE_HARDENED"},
                _token=core._EVALUATION_TOKEN,
            )

        result = evaluate(HardeningCase.from_dict(fixture()))
        forged = result.payload
        forged["receipt_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValidationError, "originating HardeningCase"):
            core.HardeningResult(
                forged,
                _token=core._EVALUATION_TOKEN,
            )
        with self.assertRaisesRegex(ValidationError, "HardeningCase"):
            core.HardeningResult._from_evaluation(forged)

    def test_required_vocabulary_has_executable_cross_field_semantics(self) -> None:
        self.assertEqual(
            set(BLUE_FORGE_VOCABULARY),
            {
                "blueForgeUniqueSourceSha256",
                "blueForgeDistinctProducers",
                "blueForgeDecisionMonotonic",
            },
        )
        validate_case_schema_vocabulary(fixture())

        same_producer = fixture()
        same_producer["verification"]["producer"] = same_producer["proposal"]["producer"]
        with self.assertRaisesRegex(ValidationError, "sole verifier"):
            validate_case_schema_vocabulary(same_producer)

        weakened = fixture()
        weakened["proposal"]["decision"] = "DENY"
        weakened["verification"]["decision"] = "REVIEW"
        with self.assertRaisesRegex(ValidationError, "weakens proposal decision"):
            validate_case_schema_vocabulary(weakened)

        duplicate_source = fixture()
        original = next(iter(duplicate_source["verification"]["original"].values()))
        variant = next(iter(duplicate_source["verification"]["variants"].values()))
        variant["source_sha256"] = original["source_sha256"]
        with self.assertRaisesRegex(ValidationError, "source_sha256 values must be unique"):
            validate_case_schema_vocabulary(duplicate_source)

    def test_schema_declares_all_implemented_vocabulary_keywords(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        meta = json.loads(META_SCHEMA.read_text(encoding="utf-8"))
        for keyword in BLUE_FORGE_VOCABULARY:
            self.assertIn(keyword, meta["properties"])
        self.assertIs(schema["blueForgeDistinctProducers"], True)
        self.assertIs(schema["blueForgeDecisionMonotonic"], True)
        self.assertIs(
            schema["$defs"]["verification"]["blueForgeUniqueSourceSha256"],
            True,
        )
        self.assertIn("schema_vocabulary", schema["$comment"])

    def test_unpaired_unicode_surrogates_fail_shared_json_domain(self) -> None:
        for encoded in (r'"\ud800"', r'{"\udfff":"value"}'):
            with self.subTest(encoded=encoded):
                with self.assertRaisesRegex(ValidationError, "Unicode surrogate"):
                    loads_strict(encoded)

        for value in ("\ud800", {"bad\udfff": "value"}):
            with self.subTest(value=repr(value)):
                with self.assertRaisesRegex(ValidationError, "Unicode surrogate"):
                    canonical_bytes(value)


if __name__ == "__main__":
    unittest.main()
