from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "v1" / "path-traversal-case.json"


def _fixture() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class CodexRoundEighteenTests(unittest.TestCase):
    def test_evidence_maps_require_exact_dict_before_limits_or_iteration(self) -> None:
        raw = _fixture()

        class ExplodingDict(dict):
            def __len__(self):
                return 1

            def items(self):
                raise AssertionError("dict subclass items must never be consumed")

        verification = raw["verification"]
        assert isinstance(verification, dict)
        variants = verification["variants"]
        assert isinstance(variants, dict)
        verification["variants"] = ExplodingDict(variants)

        with self.assertRaisesRegex(ValidationError, "exact object"):
            HardeningCase.from_dict(raw)

    def test_direct_case_evidence_tuples_are_preflighted_before_iteration(self) -> None:
        case = HardeningCase.from_dict(_fixture())

        class ExplodingTuple(tuple):
            def __iter__(self):
                raise AssertionError("tuple subclass iterator must never be consumed")

        bad_verification = replace(
            case.verification,
            variants=ExplodingTuple(case.verification.variants),
        )
        bad_case = replace(case, verification=bad_verification)

        with self.assertRaisesRegex(ValidationError, "variants must be an exact tuple"):
            evaluate(bad_case)

    def test_case_factory_enforces_shared_cumulative_semantic_byte_budget(self) -> None:
        raw = _fixture()
        proposal = raw["proposal"]
        assert isinstance(proposal, dict)

        capabilities: list[str] = []
        for index in range(256):
            prefix = f"cap-{index:03d}-"
            capabilities.append(prefix + ("x" * (4096 - len(prefix))))
        proposal["pre_mitigation_authority"] = capabilities

        with self.assertRaisesRegex(ValidationError, "canonical JSON exceeds"):
            HardeningCase.from_dict(raw)


if __name__ == "__main__":
    unittest.main()
