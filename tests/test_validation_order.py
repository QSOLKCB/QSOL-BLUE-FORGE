"""Regression coverage for type and size checks preceding string operations."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate
import blue_forge.core as core


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/v1/path-traversal-case.json"


def reference_case():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class ValidationOrderTests(unittest.TestCase):
    def test_discriminator_hooks_are_not_executed(self):
        class EqualityHook:
            def __eq__(self, other):
                raise AssertionError("discriminator equality hook executed")

        class InequalityHook:
            def __ne__(self, other):
                raise AssertionError("discriminator inequality hook executed")

        class RepresentationHook:
            def __repr__(self):
                raise AssertionError("discriminator representation hook executed")

        class StringHook:
            def __str__(self):
                raise AssertionError("discriminator string conversion hook executed")

        for field in ("schema", "contract"):
            for hook in (EqualityHook, InequalityHook, RepresentationHook, StringHook):
                with self.subTest(field=field, hook=hook.__name__):
                    value = reference_case()
                    value[field] = hook()
                    with self.assertRaisesRegex(
                        ValidationError,
                        rf"case\.{field} must be a non-empty trimmed string",
                    ):
                        HardeningCase.from_dict(value)

    def test_discriminators_require_exact_strings(self):
        # Decision is a str subclass, not an exact built-in str. Keeping it as
        # an actor-owned value also exercises this check through the CI bridge.
        invalid = (None, False, 1, 1.5, b"v1", [], {}, core.Decision.ALLOW)
        for field in ("schema", "contract"):
            for index, item in enumerate(invalid):
                with self.subTest(field=field, index=index):
                    value = reference_case()
                    value[field] = item
                    with self.assertRaisesRegex(
                        ValidationError,
                        rf"case\.{field} must be a non-empty trimmed string",
                    ):
                        HardeningCase.from_dict(value)

    def test_unknown_string_discriminators_remain_unsupported(self):
        for field, message in (
            ("schema", "unsupported case schema"),
            ("contract", "unsupported contract"),
        ):
            with self.subTest(field=field):
                value = reference_case()
                value[field] += "-unknown"
                with self.assertRaisesRegex(ValidationError, message):
                    HardeningCase.from_dict(value)

    def test_string_size_failure_precedes_trim_validation(self):
        limit = core.MAX_STRING_CHARS
        oversized = (
            "x" * (limit + 1),
            " " * (limit + 1),
            " " + "x" * (limit - 1) + " ",
            "\u3000" + "x" * (limit - 1) + "\u3000",
        )
        for index, value in enumerate(oversized):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    ValidationError, rf"^field exceeds {limit} characters$"
                ):
                    core._string(value, "field")

    def test_case_factory_bounds_strings_before_trimming(self):
        limit = core.MAX_STRING_CHARS
        for field in ("schema", "contract", "case_id", "attack_class"):
            with self.subTest(field=field):
                value = reference_case()
                value[field] = " " + "x" * (limit - 1) + " "
                with self.assertRaisesRegex(
                    ValidationError, rf"^case\.{field} exceeds {limit} characters$"
                ):
                    HardeningCase.from_dict(value)

    def test_bounded_string_domain_is_preserved(self):
        for size in (1, core.MAX_STRING_CHARS - 1, core.MAX_STRING_CHARS):
            with self.subTest(size=size):
                value = "x" * size
                self.assertEqual(core._string(value, "field"), value)
        self.assertEqual(core._string("inner space", "field"), "inner space")
        self.assertEqual(core._string("\ufeffvalue", "field"), "\ufeffvalue")
        for value in ("", " ", " value", "value ", "\u3000value", "value\u0085"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValidationError, "non-empty trimmed string"):
                    core._string(value, "field")
        with self.assertRaisesRegex(ValidationError, "unpaired Unicode surrogate"):
            core._string("\ud800", "field")

    def test_reference_case_and_string_boundary_still_evaluate(self):
        value = reference_case()
        self.assertTrue(evaluate(HardeningCase.from_dict(value)).hardened)
        value["case_id"] = "x" * core.MAX_STRING_CHARS
        case = HardeningCase.from_dict(value)
        self.assertEqual(case.case_id, value["case_id"])
        self.assertTrue(evaluate(case).hardened)


if __name__ == "__main__":
    unittest.main()
