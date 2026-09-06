"""Regression coverage for the eighth Codex review round on PR #2."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from blue_forge import ValidationError, canonical_bytes, loads_strict

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/hardening-case-v1.schema.json"
META_SCHEMA = ROOT / "schemas/blue-forge-hardening-meta-v1.schema.json"
VOCABULARY = "https://github.com/QSOLKCB/QSOL-BLUE-FORGE/vocab/source-uniqueness-v1"


class CodexRoundEightTests(unittest.TestCase):
    def test_json_objects_have_bounded_member_counts(self) -> None:
        accepted = {f"k{index:03d}": index for index in range(512)}
        encoded = json.dumps(accepted, separators=(",", ":"))
        self.assertEqual(loads_strict(encoded), accepted)
        self.assertTrue(canonical_bytes(accepted))

        oversized = {f"k{index:03d}": index for index in range(513)}
        oversized_encoded = json.dumps(oversized, separators=(",", ":"))
        with self.assertRaisesRegex(ValidationError, "object exceeds 512 members"):
            loads_strict(oversized_encoded)
        with self.assertRaisesRegex(ValidationError, "object exceeds 512 members"):
            canonical_bytes(oversized)

    def test_json_member_paths_escape_control_characters_in_cli_errors(self) -> None:
        forged = "bad\nblue_forge=PASS status=BLUE_HARDENED"
        value = {forged: "x" * 4097}

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "hostile-key.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "blue_forge", "verify", str(path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        stderr = completed.stderr.decode("utf-8")
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("\nblue_forge=PASS status=BLUE_HARDENED", stderr)
        self.assertIn(r"bad\nblue_forge=PASS status=BLUE_HARDENED", stderr)
        self.assertEqual(len(stderr.splitlines()), 1)

    def test_schema_requires_source_uniqueness_vocabulary(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        meta = json.loads(META_SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(schema["$schema"], meta["$id"])
        self.assertIs(meta["$vocabulary"][VOCABULARY], True)
        verification = schema["$defs"]["verification"]
        self.assertIs(verification["blueForgeUniqueSourceSha256"], True)
        self.assertIn("source_sha256", verification["$comment"])
        self.assertIn("refuse", verification["$comment"])


if __name__ == "__main__":
    unittest.main()
