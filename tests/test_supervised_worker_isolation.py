"""Kernel regression for PR-controlled test-module isolation.

The current test floor is itself untrusted proposed code. When the governed
supervised-suite launcher is active, this module deliberately performs its
probes at import time, before unittest invokes the test method. That exercises
the exact boundary identified in review: module-level code must already be in
the aggregate cgroup/read-only filesystem/PID namespace.

Ordinary local discovery and the independent direct-suite diagnostic skip this
integration assertion because BLUE_FORGE_SUPERVISED_MARKER is intentionally
present only in the supervised current-floor sandbox.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import subprocess
import sys
import unittest


MARKER = os.environ.get("BLUE_FORGE_SUPERVISED_MARKER")
WRITE_ERRNO = None
CHILD_PID = None
CGROUP = None

if MARKER:
    target = Path("/var/tmp") / (MARKER + "-host-write")
    try:
        target.write_bytes(b"must not reach host storage")
    except OSError as exc:
        WRITE_ERRNO = exc.errno
    else:
        WRITE_ERRNO = 0
        target.unlink(missing_ok=True)

    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            CGROUP = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
            break

    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(300)",
            MARKER,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    CHILD_PID = child.pid


class SupervisedWorkerIsolationTests(unittest.TestCase):
    @unittest.skipUnless(MARKER, "requires the governed supervised current-floor sandbox")
    def test_module_level_code_is_already_kernel_bounded(self) -> None:
        self.assertEqual(WRITE_ERRNO, errno.EROFS)
        self.assertIsNotNone(CGROUP)
        self.assertTrue(CGROUP.is_dir())

        memory = (CGROUP / "memory.max").read_text(encoding="ascii").strip()
        swap = (CGROUP / "memory.swap.max").read_text(encoding="ascii").strip()
        pids = (CGROUP / "pids.max").read_text(encoding="ascii").strip()
        cpu = (CGROUP / "cpu.max").read_text(encoding="ascii").split()

        self.assertNotEqual(memory, "max")
        self.assertLessEqual(int(memory), 768 * 1024 * 1024)
        self.assertEqual(swap, "0")
        self.assertNotEqual(pids, "max")
        self.assertLessEqual(int(pids), 96)
        self.assertGreaterEqual(len(cpu), 2)
        self.assertNotEqual(cpu[0], "max")
        self.assertGreater(int(cpu[0]), 0)
        self.assertGreater(int(cpu[1]), 0)

        self.assertIsNotNone(CHILD_PID)
        # The worker's own process-group cleanup cannot reach this setsid()
        # descendant. The outer namespace/cgroup teardown is responsible for it.
        os.kill(CHILD_PID, 0)


if __name__ == "__main__":
    unittest.main()
