"""Regression coverage for the first Codex review round on PR #2."""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict, regression_record
import blue_forge.cli as cli

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"
SCHEMA = ROOT / "schemas/hardening-case-v1.schema.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class _FakePath:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.requested: int | None = None

    def open(self, mode: str):
        if mode != "rb":
            raise AssertionError(mode)
        outer = self

        class _Stream(io.BytesIO):
            def read(self, size: int = -1) -> bytes:
                outer.requested = size
                return super().read(size)

        return _Stream(self.payload)


class CodexRoundOneTests(unittest.TestCase):
    def test_regression_record_rejects_result_from_other_case(self) -> None:
        case_a = HardeningCase.from_dict(fixture())
        result_a = evaluate(case_a)

        value_b = copy.deepcopy(fixture())
        value_b["case_id"] = "BF-CASE-PATH-OTHER"
        value_b["proposal"]["mitigation_id"] = "MIT-PATH-ROOT-OTHER"
        case_b = HardeningCase.from_dict(value_b)

        with self.assertRaisesRegex(ValidationError, "does not match supplied case"):
            regression_record(case_b, result_a)

    def test_cli_stream_budget_is_applied_to_read(self) -> None:
        fake = _FakePath(b"x" * (cli.MAX_CASE_BYTES + 1))
        with self.assertRaisesRegex(Exception, "input budget"):
            cli._load(fake)  # type: ignore[arg-type]
        self.assertEqual(fake.requested, cli.MAX_CASE_BYTES + 1)

    def test_oversized_json_integer_is_validation_error(self) -> None:
        with self.assertRaisesRegex(ValidationError, "integer exceeds"):
            loads_strict('{"value":' + ("9" * 129) + "}")

    def test_cli_oversized_integer_returns_malformed_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "huge-int.json"
            path.write_text('{"value":' + ("9" * 5000) + "}", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "blue_forge", "verify", str(path)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("integer exceeds", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_loads_strict_enforces_array_limit_directly(self) -> None:
        text = json.dumps([None] * 257)
        with self.assertRaisesRegex(ValidationError, "array exceeds 256 items"):
            loads_strict(text)

    def test_unrecognized_evidence_state_is_incomplete(self) -> None:
        value = fixture()
        value["verification"]["original"]["after"] = "RESOURCE_LIMIT"
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(result.payload["predicates"]["verification_complete"])
        self.assertIn("verification_complete", result.payload["failed_predicates"])

        value = fixture()
        value["verification"]["original"]["after"] = "NOVEL_STATE"
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(result.payload["predicates"]["verification_complete"])

    def test_schema_constrains_evidence_kind_by_position(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        defs = schema["$defs"]
        self.assertEqual(
            defs["hostileEvidence"]["allOf"][1]["properties"]["kind"]["const"],
            "hostile",
        )
        self.assertEqual(
            defs["benignEvidence"]["allOf"][1]["properties"]["kind"]["const"],
            "benign",
        )
        verification = defs["verification"]["properties"]
        self.assertEqual(verification["original"]["$ref"], "#/$defs/hostileEvidence")
        self.assertEqual(
            verification["variants"]["items"]["$ref"], "#/$defs/hostileEvidence"
        )
        self.assertEqual(
            verification["benign_controls"]["items"]["$ref"],
            "#/$defs/benignEvidence",
        )

    def test_unicode_equivalent_producer_ids_are_rejected(self) -> None:
        value = fixture()
        value["proposal"]["producer"] = "verifier-é"
        value["verification"]["producer"] = "verifier-e\u0301"
        with self.assertRaisesRegex(ValidationError, "canonical ASCII producer-id syntax"):
            HardeningCase.from_dict(value)


if __name__ == "__main__":
    unittest.main()
