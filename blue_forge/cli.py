"""CLI for deterministic BLUE-FORGE verification and regression records."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys

from .core import (
    BlueForgeError,
    HardeningCase,
    canonical_bytes,
    evaluate,
    loads_strict,
    regression_record,
)

MAX_CASE_BYTES = 1_048_576


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
    if not hasattr(os, "O_NONBLOCK"):
        raise BlueForgeError("nonblocking case-file validation is unavailable")
    try:
        # Open first without waiting for a FIFO peer, then inspect that exact
        # descriptor. A path stat followed by a blocking open would race a swap.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise BlueForgeError("case must be a regular file")
            chunks = []
            remaining = MAX_CASE_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
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
