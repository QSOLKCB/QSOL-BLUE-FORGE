#!/usr/bin/python3 -I
"""Root-owned fixed launcher for bounded proposed-code execution.

The launcher creates an aggregate systemd cgroup plus private mount/PID/network
namespaces before proposed Python starts.  The cgroup bounds memory, task count,
and aggregate CPU rate across the complete descendant tree.  The namespace
provides a read-only host view, one bounded disposable writable tmpfs, and
lifecycle teardown that also catches detached descendants.

Two fixed modes are supported:

* actor mode, used by the trusted RPC supervisor and tied to its private FIFO;
* direct-suite mode, used for the mandated ordinary unittest discovery pass.

No proposed Python runs with elevated authority.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

ACTOR_SECONDS = 35
ACTOR_STORAGE_BYTES = 32 * 1024 * 1024
ACTOR_STORAGE_INODES = 1024
ACTOR_MEMORY_BYTES = 512 * 1024 * 1024
ACTOR_TASKS = 64
# Fifty percent of one CPU for at most 35 wall-clock seconds bounds aggregate
# descendant CPU below the existing 20 CPU-second per-process ceiling.
ACTOR_CPU_QUOTA = "50%"
DIRECT_OUTPUT_BYTES = 1024 * 1024
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")

# This fixed code runs with the system interpreter (-I -S) only after unshare
# creates private mount/PID/network namespaces, and before proposed imports.
# mount_setattr changes per-mount attributes, not the host superblock's flags.
# There is deliberately no fallback to a writable host tree.
FILESYSTEM_SETUP = r'''
import ctypes
import os
import sys

if os.geteuid() != 0 or os.getpid() != 1:
    raise RuntimeError("filesystem setup requires the private namespace init")
home, uid, gid, size, inodes, workdir = sys.argv[1:7]
command = sys.argv[7:]
if not command or command[0] != "/usr/bin/prlimit":
    raise RuntimeError("invalid fixed actor command")
if not os.path.isabs(workdir) or not os.path.isdir(workdir):
    raise RuntimeError("invalid fixed actor working directory")
libc = ctypes.CDLL(None, use_errno=True)

class MountAttr(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("attr_set", "attr_clr", "propagation", "userns_fd")]

mount_setattr = libc.mount_setattr
mount_setattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
                         ctypes.POINTER(MountAttr), ctypes.c_size_t]
mount_setattr.restype = ctypes.c_int
mount = libc.mount
mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                  ctypes.c_ulong, ctypes.c_void_p]
mount.restype = ctypes.c_int

def checked(rc, operation):
    if rc != 0:
        error = ctypes.get_errno()
        raise OSError(error, operation + ": " + os.strerror(error))

os.chdir("/")
# MS_REC | MS_PRIVATE prevents propagation back into the runner namespace.
checked(mount(None, b"/", None, (1 << 14) | (1 << 18), None), "private mount tree")
# AT_FDCWD, AT_RECURSIVE; MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID.
attributes = MountAttr(1 | 2, 0, 0, 0)
checked(mount_setattr(-100, b"/", 0x8000, ctypes.byref(attributes),
                     ctypes.sizeof(attributes)), "recursive read-only mount tree")
# One aggregate byte/inode budget for every actor and detached descendant.
# MS_NOSUID | MS_NODEV | MS_NOEXEC. The underlying host directory stays empty.
options = f"size={size},nr_inodes={inodes},mode=0700,uid={uid},gid={gid}".encode("ascii")
checked(mount(b"tmpfs", os.fsencode(home), b"tmpfs", 2 | 4 | 8, options), "private actor tmpfs")
# Restore the validated materialized source root after mount setup.  unittest
# discovery and repository tests intentionally resolve fixtures relative to it.
os.chdir(workdir)
os.execv(command[0], command)
'''


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def stop(process: subprocess.Popen) -> None:
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            continue
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def stop_scope(unit: str) -> None:
    """Kill the complete aggregate cgroup and retire the transient scope."""
    for command in (
        [str(SYSTEMCTL), "kill", "--kill-whom=all", "--signal=KILL", unit],
        [str(SYSTEMCTL), "stop", unit],
        [str(SYSTEMCTL), "reset-failed", unit],
    ):
        subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )


def scoped(command: list[str], unit: str) -> list[str]:
    """Wrap a namespace command in one aggregate cgroup budget."""
    check(SYSTEMD_RUN.is_file() and SYSTEMCTL.is_file(),
          "aggregate cgroup controller is unavailable")
    check(Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
          "cgroup v2 is required for aggregate resource limits")
    return [
        str(SYSTEMD_RUN), "--system", "--scope", "--quiet",
        f"--unit={unit}",
        "-p", f"MemoryMax={ACTOR_MEMORY_BYTES}",
        "-p", "MemorySwapMax=0",
        "-p", f"TasksMax={ACTOR_TASKS}",
        "-p", f"CPUQuota={ACTOR_CPU_QUOTA}",
        "--",
        *command,
    ]


def direct_drain(stream, retained: bytearray, overflow: threading.Event) -> None:
    try:
        while chunk := stream.read(8192):
            if len(retained) + len(chunk) > DIRECT_OUTPUT_BYTES:
                overflow.set()
                remaining = max(0, DIRECT_OUTPUT_BYTES - len(retained))
                if remaining:
                    retained.extend(chunk[:remaining])
            elif not overflow.is_set():
                retained.extend(chunk)
    finally:
        stream.close()


def parse_invocation():
    direct = len(sys.argv) >= 2 and sys.argv[1] == "--direct-suite"
    if direct:
        check(len(sys.argv) == 4, "direct suite requires Python and source root")
        return True, Path(sys.argv[2]), None, Path(sys.argv[3]), None
    check(len(sys.argv) == 5, "expected root launcher and four path arguments")
    return False, Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])


def main() -> int:
    check(os.geteuid() == 0, "expected root launcher")
    direct, python_bin, supervisor, source_root, control_path = parse_invocation()
    paths = [python_bin, source_root]
    if supervisor is not None:
        paths.append(supervisor)
    if control_path is not None:
        paths.append(control_path)
    check(all(path.is_absolute() for path in paths), "absolute paths required")
    check(python_bin.is_file() and os.access(python_bin, os.X_OK), "Python executable missing")
    if supervisor is not None:
        info = supervisor.lstat()
        check(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
              "supervisor must be a root-owned non-writable regular file")
    check(source_root.is_dir() and not source_root.is_symlink(), "invalid source root")

    caller = int(os.environ.get("SUDO_UID", "-1"))
    test_user = pwd.getpwnam("blueforge-test")
    current_user = pwd.getpwnam("blueforge-current")
    rpc = pwd.getpwnam("blueforge-rpc")
    permitted = {test_user.pw_uid, current_user.pw_uid}
    check(caller in permitted, "launcher caller is not an authorized test worker")
    check(rpc.pw_uid not in permitted and rpc.pw_uid != 0,
          "actor UID must be distinct and unprivileged")
    tests_dir = source_root / "tests" if direct else None
    if direct:
        check(caller == current_user.pw_uid,
              "direct proposed suite is restricted to blueforge-current")
        root_info = source_root.stat()
        check(root_info.st_uid == 0 and not root_info.st_mode & 0o022,
              "direct suite source root must be root-owned and non-writable")
        check(tests_dir.is_dir() and not tests_dir.is_symlink(),
              "direct suite tests directory is unavailable")
        tests_info = tests_dir.stat()
        check(tests_info.st_uid == 0 and not tests_info.st_mode & 0o022,
              "direct suite tests directory must be root-owned and non-writable")

    control = None
    selector = selectors.DefaultSelector()
    if not direct:
        control = os.open(
            control_path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        control_info = os.fstat(control)
        check(
            stat.S_ISFIFO(control_info.st_mode)
            and control_info.st_uid == caller
            and not control_info.st_mode & 0o077,
            "invalid private worker lifeline",
        )
        selector.register(control, selectors.EVENT_READ)

    target = current_user if direct else rpc
    home = Path(tempfile.mkdtemp(prefix="blue-forge-actor-home-", dir="/tmp"))
    process = None
    reader = None
    retained = bytearray()
    overflow = threading.Event()
    unit = f"blue-forge-proposed-{os.getpid()}-{time.monotonic_ns()}.scope"
    interrupted = []

    def interrupted_by(signum, frame):
        interrupted.append(signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted_by)

    try:
        home.chmod(0o700)
        if direct:
            proposed_command = [
                str(python_bin), "-m", "unittest", "discover",
                "-s", str(tests_dir), "-v",
            ]
        else:
            proposed_command = [
                str(python_bin), "-I", str(supervisor), "--actor-root", str(source_root)
            ]

        actor_command = [
            "/usr/bin/prlimit",
            "--as=536870912", "--cpu=20", "--nproc=64",
            "--fsize=16777216", "--nofile=128", "--core=0", "--",
            "/usr/bin/setpriv",
            f"--reuid={target.pw_uid}", f"--regid={target.pw_gid}", "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            "--no-new-privs", "--pdeathsig=KILL", "--",
            "/usr/bin/env", "-i",
            f"HOME={home}", f"TMPDIR={home}", "PATH=/usr/bin:/bin",
            "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1",
            f"LD_LIBRARY_PATH={python_bin.parent.parent / 'lib'}",
        ]
        if direct:
            # The helper is exercised by the earlier supervised current-floor
            # integration test.  A no-suid direct sandbox cannot recursively sudo
            # the root helper, so make that duplicate diagnostic test skip exactly
            # as it does in ordinary environments without the installed helper.
            actor_command.append("BLUE_FORGE_RPC_HELPER=/nonexistent")
        actor_command.extend(proposed_command)

        namespace_command = [
            "/usr/bin/setpriv", "--pdeathsig=KILL", "--",
            "/usr/bin/unshare", "--mount", "--propagation", "private",
            "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--net", "--",
            "/usr/bin/python3", "-I", "-S", "-c", FILESYSTEM_SETUP,
            str(home), str(target.pw_uid), str(target.pw_gid),
            str(ACTOR_STORAGE_BYTES), str(ACTOR_STORAGE_INODES), str(source_root),
            *actor_command,
        ]
        command = scoped(namespace_command, unit)
        popen_kwargs = {
            "cwd": source_root,
            "start_new_session": True,
            "env": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        }
        if direct:
            popen_kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        process = subprocess.Popen(command, **popen_kwargs)
        if direct:
            reader = threading.Thread(
                target=direct_drain, args=(process.stdout, retained, overflow), daemon=True
            )
            reader.start()

        deadline = time.monotonic() + ACTOR_SECONDS
        while process.poll() is None:
            if interrupted:
                return 128 + interrupted[0]
            if overflow.is_set():
                print("isolated_direct_suite=FAIL reason=output budget exceeded", file=sys.stderr)
                return 125
            if time.monotonic() >= deadline:
                label = "isolated_direct_suite" if direct else "isolated_actor"
                print(f"{label}=FAIL reason=lifetime budget exceeded", file=sys.stderr)
                return 124
            if not direct:
                for _key, _mask in selector.select(0.05):
                    data = os.read(control, 1)
                    check(data == b"", "worker lifeline carried unexpected data")
                    return 0
            else:
                time.sleep(0.05)

        if direct:
            if reader is not None:
                reader.join(timeout=3)
                check(not reader.is_alive(), "direct-suite output drain did not terminate")
            sys.stdout.buffer.write(bytes(retained))
            sys.stdout.buffer.flush()
            if overflow.is_set():
                print("isolated_direct_suite=FAIL reason=output budget exceeded", file=sys.stderr)
                return 125
            if process.returncode == 0:
                print("isolated_direct_suite=PASS")
            return process.returncode if process.returncode >= 0 else 128 - process.returncode
        return process.returncode if process.returncode >= 0 else 128 - process.returncode
    finally:
        # The transient scope is the aggregate authority for descendant cleanup.
        # Stop it even if the namespace leader or systemd-run wrapper has exited.
        stop_scope(unit)
        if process is not None:
            try:
                stop(process)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        if reader is not None:
            reader.join(timeout=3)
        selector.close()
        if control is not None:
            os.close(control)
        shutil.rmtree(home, ignore_errors=False)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        label = "isolated_direct_suite" if len(sys.argv) > 1 and sys.argv[1] == "--direct-suite" else "isolated_actor"
        print(f"{label}=FAIL reason={str(exc)!r}", file=sys.stderr)
        raise SystemExit(1)
