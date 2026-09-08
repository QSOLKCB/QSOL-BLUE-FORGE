"""Regression coverage for the twelfth Codex review round on PR #2."""

from __future__ import annotations

from pathlib import Path
import unittest
from unittest import mock

import blue_forge._validation_patch as validation_patch
import blue_forge.core as core
from blue_forge import HardeningCase, ValidationError, loads_strict

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundTwelveTests(unittest.TestCase):
    def test_loads_strict_rejects_oversized_text_before_json_parser(self) -> None:
        oversized = " " * (core.MAX_JSON_TEXT_BYTES + 1)
        with mock.patch.object(
            validation_patch.json,
            "loads",
            side_effect=AssertionError("json.loads must not be called"),
        ):
            with self.assertRaisesRegex(ValidationError, "before parsing"):
                loads_strict(oversized)

        multibyte = "é" * ((core.MAX_JSON_TEXT_BYTES // 2) + 1)
        with mock.patch.object(
            validation_patch.json,
            "loads",
            side_effect=AssertionError("json.loads must not be called"),
        ):
            with self.assertRaisesRegex(ValidationError, "UTF-8 bytes before parsing"):
                loads_strict(multibyte)

    def test_case_factory_rejects_non_string_keys_before_sorting_diagnostics(self) -> None:
        malformed = fixture()
        malformed[1] = "non-string-key"
        malformed["extra"] = "extra-string-key"

        with self.assertRaisesRegex(ValidationError, "object keys must be strings"):
            HardeningCase.from_dict(malformed)


if __name__ == "__main__":
    unittest.main()
