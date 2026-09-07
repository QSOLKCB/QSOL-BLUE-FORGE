"""Kernel integration checks for aggregate disposable actor resources.

The helper is installed by CI from the externally authorized baseline. Local
checkouts without that helper skip this integration check, not any core test.
The same file is an inert, fixed actor probe when invoked by that helper.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(os.environ.get("BLUE_FORGE_RPC_HELPER", "/usr/local/libexec/blue-forge-rpc"))
STORAGE_BYTES = 32 * 1024 * 1024
STORAGE_INODES = 1024
MEMORY_BYTES = 512 * 1024 * 1024
TASKS_MAX = 64


def _cgroup_v2_path() -> Path:
    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        hierarchy, controllers, relative = line.split(":", 2)
        if hierarchy == "0" and controllers == "":
            return Path("/sys/fs/cgroup") / relative.lstrip("/")
    raise RuntimeError("actor is not attached to cgroup v2")


def filesystem_probe(marker):
    home = Path(os.environ["HOME"])
    results = {"home": str(home), "outside": {}}
    for directory in ("/var/tmp", "/tmp", "/dev/shm"):
        target = Path(directory) / marker
        try:
            with target.open("xb") as stream:
                stream.write(b"must not reach host storage")
        except OSError as exc:
            results["outside"][directory] = exc.errno
        else:
            target.unlink()
            results["outside"][directory] = 0
    probe = home / "write-control"
    probe.write_bytes(b"disposable")
    results["write_control"] = probe.read_bytes() == b"disposable"
    probe.unlink()
    link = home / "outside-link"
    link.symlink_to(Path("/var/tmp") / marker)
    try:
        with link.open("wb") as stream:
            stream.write(b"must not escape")
    except OSError as exc:
        results["symlink_errno"] = exc.errno
    else:
        Path("/var/tmp", marker).unlink()
        results["symlink_errno"] = 0
    link.unlink()
    space = os.statvfs(home)
    results["capacity"] = space.f_blocks * space.f_frsize
    results["inodes"] = space.f_files

    cgroup = _cgroup_v2_path()
    results["cgroup"] = {
        "memory_max": (cgroup / "memory.max").read_text(encoding="ascii").strip(),
        "memory_swap_max": (cgroup / "memory.swap.max").read_text(encoding="ascii").strip(),
        "pids_max": (cgroup / "pids.max").read_text(encoding="ascii").strip(),
        "cpu_max": (cgroup / "cpu.max").read_text(encoding="ascii").strip(),
    }

    files = []
    written = 0
    results["byte_errno"] = 0
    try:
        for index in range(16):
            path = home / f"data-{index}"
            files.append(path)
            with path.open("wb", buffering=0) as stream:
                for chunk in range(4):
                    written += stream.write(b"x" * (1024 * 1024))
    except OSError as exc:
        results["byte_errno"] = exc.errno
    results["written"] = written
    for path in files:
        path.unlink(missing_ok=True)
    created = 0
    results["inode_errno"] = 0
    try:
        for index in range(2048):
            (home / f"empty-{index}").touch(exist_ok=False)
            created += 1
    except OSError as exc:
        results["inode_errno"] = exc.errno
    results["created"] = created
    print(json.dumps(results, sort_keys=True))


class ActorFilesystemTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux" and HELPER.is_file(), "requires the CI-installed kernel isolation helper")
    def test_only_bounded_disposable_storage_is_writable(self):
        with tempfile.TemporaryDirectory(prefix="blue-forge-storage-probe-") as source, \
                tempfile.TemporaryDirectory(prefix="blue-forge-storage-control-") as control_dir:
            root = Path(source)
            root.chmod(0o755)
            control = Path(control_dir) / "lifeline"
            os.mkfifo(control, 0o600)
            fd = os.open(control, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                completed = subprocess.run(
                    ["sudo", "-n", str(HELPER), sys.executable, str(Path(__file__).resolve()), str(root), str(control)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, check=False, timeout=20,
                )
            finally:
                os.close(fd)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["outside"], {path: errno.EROFS for path in ("/var/tmp", "/tmp", "/dev/shm")})
            self.assertTrue(result["write_control"])
            self.assertEqual(result["symlink_errno"], errno.EROFS)
            self.assertEqual(result["capacity"], STORAGE_BYTES)
            self.assertEqual(result["inodes"], STORAGE_INODES)

            cgroup = result["cgroup"]
            self.assertEqual(cgroup["memory_max"], str(MEMORY_BYTES))
            self.assertEqual(cgroup["memory_swap_max"], "0")
            self.assertEqual(cgroup["pids_max"], str(TASKS_MAX))
            quota, period = cgroup["cpu_max"].split()
            self.assertNotEqual(quota, "max")
            self.assertGreater(int(quota), 0)
            self.assertGreater(int(period), 0)
            self.assertLessEqual(int(quota) * 2, int(period))

            self.assertEqual(result["byte_errno"], errno.ENOSPC)
            self.assertGreater(result["written"], 0)
            self.assertLessEqual(result["written"], STORAGE_BYTES)
            self.assertEqual(result["inode_errno"], errno.ENOSPC)
            self.assertGreater(result["created"], 0)
            self.assertLess(result["created"], STORAGE_INODES)
            self.assertFalse(Path(result["home"]).exists(), "actor home survived teardown")
            for directory in ("/var/tmp", "/tmp", "/dev/shm"):
                self.assertFalse((Path(directory) / (root.name + "-write-probe")).exists(), "probe escaped onto host storage")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--actor-root":
        filesystem_probe(Path(sys.argv[2]).name + "-write-probe")
    else:
        unittest.main()
