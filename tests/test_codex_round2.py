"""Regression coverage for the second Codex review round on PR #2."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict, regression_record

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"
SCHEMA = ROOT / "schemas/hardening-case-v1.schema.json"
ORIGINAL = "original:HOSTILE-PATH-001"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundTwoTests(unittest.TestCase):
    def test_evaluated_result_payload_is_defensive_copy(self) -> None:
        value = fixture()
        value["verification"]["original"][ORIGINAL]["after"] = "UNKNOWN"
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(result.hardened)

        payload = result.payload
        payload["status"] = "BLUE_HARDENED"
        payload["failed_predicates"].clear()
        payload["predicates"]["verification_complete"] = True

        self.assertFalse(result.hardened)
        self.assertEqual(result.payload["status"], "NOT_HARDENED")
        self.assertIn("verification_complete", result.payload["failed_predicates"])
        self.assertFalse(result.payload["predicates"]["verification_complete"])

    def test_hardening_result_binds_complete_case_digest(self) -> None:
        case_a = HardeningCase.from_dict(fixture())
        result_a = evaluate(case_a)

        value_b = copy.deepcopy(fixture())
        value_b["verification"]["original"][ORIGINAL]["source_sha256"] = "0" * 64
        case_b = HardeningCase.from_dict(value_b)
        result_b = evaluate(case_b)

        self.assertNotEqual(result_a.payload["case_sha256"], result_b.payload["case_sha256"])
        self.assertNotEqual(result_a.receipt_sha256, result_b.receipt_sha256)
        with self.assertRaisesRegex(ValidationError, "does not match supplied case"):
            regression_record(case_b, result_a)

    def test_schema_nonempty_requires_trimmed_nonwhitespace_strings(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        nonempty = schema["$defs"]["nonempty"]
        self.assertNotIn("pattern", nonempty)
        pattern = nonempty["allOf"][0]["pattern"]
        compiled = re.compile(pattern)
        for invalid in ("", " ", "  value", "value  ", "\tvalue", "value\n"):
            with self.subTest(invalid=invalid):
                self.assertIsNone(compiled.fullmatch(invalid))
        for valid in (
            "value",
            "value with spaces",
            "évidence",
            "a\nb",
            "\ufeffvalue",
            "value\ufeff",
        ):
            with self.subTest(valid=valid):
                self.assertIsNotNone(compiled.fullmatch(valid))

    def test_cli_writes_utf8_under_ascii_stdout_locale(self) -> None:
        value = fixture()
        value["case_id"] = "BF-CASE-PATH-é"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unicode-case.json"
            path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
            env = os.environ.copy()
            env.update({
                "LC_ALL": "C",
                "LANG": "C",
                "PYTHONUTF8": "0",
                "PYTHONCOERCECLOCALE": "0",
            })
            result = subprocess.run(
                [sys.executable, "-m", "blue_forge", "verify", str(path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        decoded = result.stdout.decode("utf-8")
        self.assertIn("BF-CASE-PATH-é", decoded)
        self.assertNotIn("Traceback", result.stderr.decode("utf-8", errors="replace"))

    def test_authority_expansion_forces_deny(self) -> None:
        value = fixture()
        value["proposal"]["decision"] = "ALLOW"
        value["verification"]["decision"] = "ALLOW"
        value["verification"]["observed_authority"].append("fs:read:system")
        result = evaluate(HardeningCase.from_dict(value))
        self.assertFalse(result.hardened)
        self.assertFalse(result.payload["predicates"]["authority_not_expanded"])
        self.assertEqual(result.payload["decision"], "DENY")


if __name__ == "__main__":
    unittest.main()
