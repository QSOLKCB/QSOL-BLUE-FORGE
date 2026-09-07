"""Kernel regression for PR-controlled test-module isolation.

The current test floor is itself untrusted proposed code. When the governed
supervised-suite launcher is active, this module deliberately performs its
probes at import time, before unittest invokes the test method. That exercises
the exact boundary identified in review: module-level code must already be in
the aggregate cgroup/read-only filesystem/PID namespace.

This module is explicitly CURRENT_SUITE_ONLY. The baseline-owned supervisor
includes it only when the governed supervised current-floor marker is present;
it is never promoted into the frozen proposed-core oracle. Ordinary local
discovery and the independent direct-suite diagnostic still discover the module
but skip its kernel assertion because the marker is intentionally absent there.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import subprocess
import sys
import unittest


CURRENT_SUITE_ONLY = True
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

    @unittest.skipUnless(MARKER, "requires the governed supervised current-floor sandbox")
    def test_nested_helper_containment_is_kernel_derived(self) -> None:
        helper = Path(os.environ["BLUE_FORGE_RPC_HELPER"])
        self.assertTrue(helper.is_file())
        source = helper.read_text(encoding="utf-8")

        # Exact regression for the caller-controlled environment escape: nested
        # scope reuse must not depend on BLUE_FORGE_PARENT_AGGREGATE at all.
        self.assertNotIn("BLUE_FORGE_PARENT_AGGREGATE", source)
        self.assertIn('/proc/self/cgroup', source)
        self.assertIn('memory.max', source)
        self.assertIn('pids.max', source)
        self.assertIn('cpu.max', source)


if __name__ == "__main__":
    unittest.main()
