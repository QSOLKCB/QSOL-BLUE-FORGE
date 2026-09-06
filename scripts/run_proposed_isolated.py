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
        os.chown(home, rpc.pw_uid, rpc.pw_gid)
        home.chmod(0o700)
        command = [
            "/usr/bin/setpriv", "--pdeathsig=KILL", "--",
            "/usr/bin/unshare", "--mount", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--net", "--",
            "/usr/bin/prlimit", "--as=536870912", "--cpu=20", "--nproc=64", "--fsize=16777216", "--nofile=128", "--core=0", "--",
            "/usr/bin/setpriv", f"--reuid={rpc.pw_uid}", f"--regid={rpc.pw_gid}", "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--pdeathsig=KILL", "--",
            "/usr/bin/env", "-i", f"HOME={home}", f"TMPDIR={home}", "PATH=/usr/bin:/bin",
            f"LD_LIBRARY_PATH={python_bin.parent.parent / 'lib'}",
            str(python_bin), "-I", str(supervisor), "--actor-root", str(source_root),
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
        # PID namespace teardown has already killed even setsid() descendants.
        shutil.rmtree(home)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"isolated_actor=FAIL reason={str(exc)!r}", file=sys.stderr)
        raise SystemExit(1)
