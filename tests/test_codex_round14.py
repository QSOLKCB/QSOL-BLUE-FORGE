"""Regression coverage for the fourteenth Codex review round on PR #2."""

from __future__ import annotations

import copy
from pathlib import Path
import unittest

import blue_forge.core as core
from blue_forge import HardeningCase, ValidationError, evaluate, loads_strict
from blue_forge.cli import MAX_CASE_BYTES
from blue_forge.schema_vocabulary import validate_case_schema_vocabulary

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/v1/path-traversal-case.json"


def fixture() -> dict:
    return loads_strict(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundFourteenTests(unittest.TestCase):
    def test_evaluator_result_has_no_mutable_instance_dictionary(self) -> None:
        data = fixture()
        benign = next(iter(data["verification"]["benign_controls"].values()))
        benign["after"] = "BLOCKED"
        result = evaluate(HardeningCase.from_dict(data))
        self.assertFalse(result.hardened)

        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises(AttributeError):
            result._case_bytes = b'{}'  # type: ignore[misc]

        # Even a deliberate low-level slot overwrite cannot expose a forged
        # hardened state without revalidating the originating case material.
        object.__setattr__(result, "_case_bytes", b'{"status":"BLUE_HARDENED"}')
        with self.assertRaises(ValidationError):
            _ = result.hardened

    def test_schema_vocabulary_rejects_semantic_cases_over_cli_byte_budget(self) -> None:
        data = fixture()
        oversized_authority: list[str] = []
        for index in range(256):
            prefix = f"cap-{index:03d}-"
            oversized_authority.append(prefix + "x" * (4096 - len(prefix)))
        data["proposal"]["pre_mitigation_authority"] = oversized_authority

        with self.assertRaisesRegex(
            ValidationError,
            r"case canonical JSON exceeds 1048576 byte budget",
        ):
            validate_case_schema_vocabulary(data)

        self.assertEqual(MAX_CASE_BYTES, core.MAX_JSON_BYTES)
        validate_case_schema_vocabulary(copy.deepcopy(fixture()))


if __name__ == "__main__":
    unittest.main()
