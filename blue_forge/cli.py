"""CLI for deterministic BLUE-FORGE verification and regression records."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

MAX_CASE_BYTES = 1_048_576

from .core import (
    BlueForgeError,
    HardeningCase,
    canonical_bytes,
    evaluate,
    loads_strict,
    regression_record,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="blue-forge",
        description="Deterministic, non-executing BLUE-FORGE reference core.",
    )
    sub = result.add_subparsers(dest="command", required=True)
    for name in ("verify", "regression"):
        command = sub.add_parser(name)
        command.add_argument("case", type=Path)
    return result


def _load(path: Path) -> HardeningCase:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_CASE_BYTES + 1)
    except OSError as exc:
        raise BlueForgeError(f"cannot read case: {exc}") from exc
    if len(raw) > MAX_CASE_BYTES:
        raise BlueForgeError(f"case exceeds {MAX_CASE_BYTES} byte input budget")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise BlueForgeError(f"case is not UTF-8: {exc}") from exc
    return HardeningCase.from_dict(loads_strict(text))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        case = _load(args.case)
        result = evaluate(case)
        payload = result.payload
        if args.command == "regression":
            payload = regression_record(case, result)
        sys.stdout.buffer.write(canonical_bytes(payload) + b"\n")
        return 0 if result.hardened else 3
    except BlueForgeError as exc:
        print(f"blue_forge=FAIL reason={exc}", file=sys.stderr)
        return 2
