from __future__ import annotations

import json
import unittest

from blue_forge import ValidationError, canonical_bytes, loads_strict


class CodexRound23Regressions(unittest.TestCase):
    def _nested_long_key_value(self):
        key = "k" * 4096
        value: object = "leaf"
        for _ in range(34):
            value = {key: value}
        return key, value

    def _assert_bounded_nesting_diagnostic(self, caught, key):
        message = str(caught.exception)
        self.assertIn("JSON nesting exceeds", message)
        self.assertLess(len(message), 1024)
        self.assertNotIn(key, message)
        self.assertIn("elided", message)

    def test_nested_long_key_diagnostic_path_is_bounded(self):
        key, value = self._nested_long_key_value()
        text = json.dumps(value, separators=(",", ":"))
        self.assertLess(len(text.encode("utf-8")), 1024 * 1024)

        with self.assertRaises(ValidationError) as caught:
            loads_strict(text)

        self._assert_bounded_nesting_diagnostic(caught, key)

    def test_canonicalization_nested_long_key_diagnostic_path_is_bounded(self):
        key, value = self._nested_long_key_value()

        with self.assertRaises(ValidationError) as caught:
            canonical_bytes(value)

        self._assert_bounded_nesting_diagnostic(caught, key)


if __name__ == "__main__":
    unittest.main()
