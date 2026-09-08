"""Regressions for evidence-ID preflight and nonblocking CLI file boundaries."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest

from blue_forge import HardeningCase, ValidationError, evaluate
import blue_forge.core as core
import blue_forge.cli as cli

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/v1/path-traversal-case.json"


def case():
    return HardeningCase.from_dict(json.loads(FIXTURE.read_text(encoding="utf-8")))


def with_id(original_case, role, value):
    verification = original_case.verification
    if role == "original":
        verification = replace(verification, original=replace(verification.original, evidence_id=value))
    else:
        items = list(getattr(verification, role))
        items[0] = replace(items[0], evidence_id=value)
        verification = replace(verification, **{role: tuple(items)})
    return replace(original_case, verification=verification)


class EvidenceIdPreflightTests(unittest.TestCase):
    def test_hash_hooks_are_rejected_in_every_evidence_role(self):
        class HashHook:
            def __hash__(self):
                raise RuntimeError("unvalidated evidence ID was hashed")

            def __eq__(self, other):
                raise RuntimeError("unvalidated evidence ID was compared")

            def __repr__(self):
                raise RuntimeError("unvalidated evidence ID was formatted")

        for role in ("original", "variants", "benign_controls"):
            with self.subTest(role=role):
                with self.assertRaisesRegex(ValidationError, "evidence id must be a non-empty trimmed string"):
                    evaluate(with_id(case(), role, HashHook()))

    def test_string_subclasses_and_oversized_ids_are_rejected_in_every_role(self):
        # This actor-owned Enum retains its str-subclass identity across the RPC.
        for role in ("original", "variants", "benign_controls"):
            with self.subTest(role=role):
                with self.assertRaisesRegex(ValidationError, "evidence id must be a non-empty trimmed string"):
                    evaluate(with_id(case(), role, core.Decision.ALLOW))
                with self.assertRaisesRegex(ValidationError, "evidence id exceeds 4096 characters"):
                    evaluate(with_id(case(), role, "x" * 4097))

    def test_duplicate_valid_ids_still_fail(self):
        original = case()
        duplicate = original.verification.variants[1].evidence_id
        with self.assertRaisesRegex(ValidationError, "duplicate evidence id"):
            evaluate(with_id(original, "variants", duplicate))

    def test_valid_role_ids_and_reference_case_still_evaluate(self):
        self.assertTrue(evaluate(case()).hardened)
        for role, prefix in (("original", "original"), ("variants", "variant"), ("benign_controls", "benign")):
            with self.subTest(role=role):
                self.assertTrue(evaluate(with_id(case(), role, prefix + ":" + "x" * 127)).hardened)


class CaseFileBoundaryTests(unittest.TestCase):
    def test_fifo_without_writer_fails_both_cli_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp).chmod(0o755)
            fifo = Path(temp) / "case.fifo"
            os.mkfifo(fifo, 0o644)
            for command in ("verify", "regression"):
                with self.subTest(command=command):
                    self.assertEqual(cli.main([command, str(fifo)]), 2)
            with self.assertRaisesRegex(cli.BlueForgeError, "regular file"):
                cli._load(cli.Path(str(fifo)))

    def test_fifo_with_short_payload_and_live_writer_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp).chmod(0o755)
            fifo = Path(temp) / "case.fifo"
            os.mkfifo(fifo, 0o644)
            writer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                os.write(writer, b"{}")
                for command in ("verify", "regression"):
                    self.assertEqual(cli.main([command, str(fifo)]), 2)
            finally:
                os.close(writer)

    def test_directory_device_and_fifo_symlink_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp).chmod(0o755)
            fifo = Path(temp) / "case.fifo"
            os.mkfifo(fifo, 0o644)
            link = Path(temp) / "case-link"
            link.symlink_to(fifo)
            for path in (Path(temp), Path("/dev/zero"), link):
                with self.subTest(path=str(path)):
                    with self.assertRaisesRegex(cli.BlueForgeError, "regular file"):
                        cli._load(cli.Path(str(path)))

    def test_regular_case_and_regular_symlink_still_work(self):
        self.assertTrue(evaluate(cli._load(cli.Path(str(FIXTURE)))).hardened)
        with tempfile.TemporaryDirectory() as temp:
            Path(temp).chmod(0o755)
            link = Path(temp) / "case-link.json"
            link.symlink_to(FIXTURE)
            self.assertTrue(evaluate(cli._load(cli.Path(str(link)))).hardened)


if __name__ == "__main__":
    unittest.main()
