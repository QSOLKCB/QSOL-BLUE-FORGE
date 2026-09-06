#!/usr/bin/python3 -I
"""Root-owned fixed launcher for an unprivileged proposed-code PID namespace.

The only elevated operations are creating a private home, applying kernel
isolation/limits, and destroying the namespace. No proposed Python is imported
until after setpriv drops all authority. A private FIFO held only by the trusted
worker ties namespace lifetime to that worker, including abnormal worker death.
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
import time

ACTOR_SECONDS = 35
ACTOR_STORAGE_BYTES = 32 * 1024 * 1024
ACTOR_STORAGE_INODES = 1024

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
home, uid, gid, size, inodes = sys.argv[1:6]
command = sys.argv[6:]
if not command or command[0] != "/usr/bin/prlimit":
    raise RuntimeError("invalid fixed actor command")
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
os.execv(command[0], command)
'''


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def stop(process: subprocess.Popen) -> None:
    # We own this session and can terminate it even after its leader has exited.
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


def main() -> int:
    check(os.geteuid() == 0 and len(sys.argv) == 5, "expected root launcher and four path arguments")
    python_bin, supervisor, source_root, control_path = map(Path, sys.argv[1:])
    check(all(p.is_absolute() for p in (python_bin, supervisor, source_root, control_path)), "absolute paths required")
    check(python_bin.is_file() and os.access(python_bin, os.X_OK), "Python executable missing")
    info = supervisor.lstat()
    check(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
          "supervisor must be a root-owned non-writable regular file")
    check(source_root.is_dir() and not source_root.is_symlink(), "invalid source root")
    caller = int(os.environ.get("SUDO_UID", "-1"))
    permitted = {pwd.getpwnam(name).pw_uid for name in ("blueforge-test", "blueforge-current")}
    check(caller in permitted, "launcher caller is not an authorized test worker")
    control = os.open(control_path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    control_info = os.fstat(control)
    check(stat.S_ISFIFO(control_info.st_mode) and control_info.st_uid == caller
          and not control_info.st_mode & 0o077, "invalid private worker lifeline")
    rpc = pwd.getpwnam("blueforge-rpc")
    check(rpc.pw_uid not in permitted and rpc.pw_uid != 0, "actor UID must be distinct and unprivileged")
    home = Path(tempfile.mkdtemp(prefix="blue-forge-actor-home-", dir="/tmp"))
    process = None
    selector = selectors.DefaultSelector()
    interrupted = []

    def interrupted_by(signum, frame):
        interrupted.append(signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted_by)
    try:
        # The host mountpoint remains root-owned. Only the namespace-local tmpfs
        # is owned by the actor, preventing hidden writes below its mount.
        home.chmod(0o700)
        actor_command = [
            "/usr/bin/prlimit", "--as=536870912", "--cpu=20", "--nproc=64", "--fsize=16777216", "--nofile=128", "--core=0", "--",
            "/usr/bin/setpriv", f"--reuid={rpc.pw_uid}", f"--regid={rpc.pw_gid}", "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--pdeathsig=KILL", "--",
            "/usr/bin/env", "-i", f"HOME={home}", f"TMPDIR={home}", "PATH=/usr/bin:/bin",
            f"LD_LIBRARY_PATH={python_bin.parent.parent / 'lib'}",
            str(python_bin), "-I", str(supervisor), "--actor-root", str(source_root),
        ]
        command = [
            "/usr/bin/setpriv", "--pdeathsig=KILL", "--",
            "/usr/bin/unshare", "--mount", "--propagation", "private", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--net", "--",
            "/usr/bin/python3", "-I", "-S", "-c", FILESYSTEM_SETUP,
            str(home), str(rpc.pw_uid), str(rpc.pw_gid),
            str(ACTOR_STORAGE_BYTES), str(ACTOR_STORAGE_INODES), *actor_command,
        ]
        process = subprocess.Popen(command, cwd=source_root, start_new_session=True,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        selector.register(control, selectors.EVENT_READ)
        deadline = time.monotonic() + ACTOR_SECONDS
        while process.poll() is None:
            if interrupted:
                return 128 + interrupted[0]
            if time.monotonic() >= deadline:
                print("isolated_actor=FAIL reason=actor lifetime budget exceeded", file=sys.stderr)
                return 124
            for key, mask in selector.select(0.05):
                data = os.read(control, 1)
                check(data == b"", "worker lifeline carried unexpected data")
                # EOF means the trusted worker completed, failed, or died. Actor
                # code cannot keep this FIFO open: it is owned by another UID.
                return 0
        return process.returncode if process.returncode >= 0 else 128 - process.returncode
    finally:
        if process is not None:
            stop(process)
        selector.close()
        os.close(control)
        # PID namespace teardown destroys its tmpfs and even setsid() descendants.
        shutil.rmtree(home)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"isolated_actor=FAIL reason={str(exc)!r}", file=sys.stderr)
        raise SystemExit(1)
