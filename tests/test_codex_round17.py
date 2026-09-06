from __future__ import annotations

import json
from pathlib import Path
import unittest

from blue_forge import HardeningCase, ValidationError


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "v1" / "path-traversal-case.json"


class CodexRoundSeventeenTests(unittest.TestCase):
    def test_case_factory_rejects_list_subclass_before_iteration(self) -> None:
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))

        class ExplodingList(list):
            def __len__(self):
                return 0

            def __iter__(self):
                raise AssertionError("list subclass iterator must never be consumed")

        raw["proposal"]["requested_authority"] = ExplodingList()
        with self.assertRaisesRegex(ValidationError, "exact list"):
            HardeningCase.from_dict(raw)


if __name__ == "__main__":
    unittest.main()
