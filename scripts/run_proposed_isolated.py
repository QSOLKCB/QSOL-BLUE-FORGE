#!/usr/bin/python3 -I
"""Root-owned fixed launcher for bounded proposed-code execution.

The launcher creates aggregate cgroup and private mount/PID/network boundaries
before proposed Python starts. Three fixed modes are supported:

* actor mode: isolated application actor for the trusted RPC supervisor;
* direct-suite mode: ordinary unittest discovery under bounded diagnostics;
* supervised-suite mode: the complete PR-controlled test-worker tree, including
  test-module import/top-level code, inside an aggregate resource/filesystem
  boundary while retaining access only to the fixed nested actor helper.

No proposed Python runs with elevated authority. Trusted RPC actor mode
additionally masks /proc after PID-namespace setup so proposed BLUE-FORGE Python
cannot use /proc/self/mem to rewrite inherited trusted mappings. Fixed-helper
kernel diagnostics may retain the namespace-local read-only procfs because they
inherit no trusted RPC mailbox. In supervised-suite mode the filesystem is
recursively read-only and nosuid except for an isolated bind mount of
/usr/bin/sudo. Sudo policy permits only this fixed launcher, so PR-controlled
test code cannot turn that narrow elevation path into arbitrary root execution.
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
ACTOR_CPU_QUOTA = "50%"
ACTOR_GRACEFUL_TEARDOWN_SECONDS = 3

SUPERVISED_SECONDS = 180
SUPERVISED_STORAGE_BYTES = 64 * 1024 * 1024
SUPERVISED_STORAGE_INODES = 4096
# The whole PR-controlled test tree retains the actor-strength memory and CPU
# ceilings. Its task budget includes trusted supervisor/worker/helper machinery,
# so it has bounded headroom beyond the standalone actor's 64-task cgroup.
SUPERVISED_MEMORY_BYTES = ACTOR_MEMORY_BYTES
SUPERVISED_TASKS = 96
SUPERVISED_CPU_QUOTA = ACTOR_CPU_QUOTA

OUTPUT_BYTES = 1024 * 1024
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
FIXED_HELPER = Path("/usr/local/libexec/blue-forge-rpc")

# Actor/direct setup: all host mounts become read-only+nosuid, followed by one
# private writable tmpfs owned by the unprivileged target. The governed RPC
# actor overlays /proc with an empty read-only tmpfs after unshare --mount-proc;
# fixed-helper diagnostics/direct-suite retain procfs for kernel assertions.
FILESYSTEM_SETUP = r'''
import ctypes
import os
import sys

if os.geteuid() != 0 or os.getpid() != 1:
    raise RuntimeError("filesystem setup requires the private namespace init")
home, uid, gid, size, inodes, workdir, mask_proc = sys.argv[1:8]
command = sys.argv[8:]
if mask_proc not in {"0", "1"}:
    raise RuntimeError("invalid procfs isolation mode")
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
checked(mount(None, b"/", None, (1 << 14) | (1 << 18), None), "private mount tree")
attributes = MountAttr(1 | 2, 0, 0, 0)  # RDONLY | NOSUID
checked(mount_setattr(-100, b"/", 0x8000, ctypes.byref(attributes),
                     ctypes.sizeof(attributes)), "recursive read-only mount tree")
if mask_proc == "1":
    # The trusted RPC actor needs no procfs API after namespace setup. Cover the
    # namespace's procfs mount with a private, empty, read-only filesystem before
    # dropping privileges. Fixed-helper diagnostics use mask_proc=0 because they
    # inherit no trusted response mailbox and need /proc for cgroup assertions.
    proc_options = b"size=4096,nr_inodes=16,mode=0555,uid=0,gid=0"
    checked(mount(b"tmpfs", b"/proc", b"tmpfs", 1 | 2 | 4 | 8, proc_options),
            "mask actor procfs")
options = f"size={size},nr_inodes={inodes},mode=0700,uid={uid},gid={gid}".encode("ascii")
checked(mount(b"tmpfs", os.fsencode(home), b"tmpfs", 2 | 4 | 8, options), "private actor tmpfs")
os.chdir(workdir)
os.execv(command[0], command)
'''

# Current-suite worker setup. The source/test trees and all host temporary paths
# are read-only. One root-owned sticky tmpfs is writable. A worker-owned HOME is
# created beneath it. /usr/bin/sudo alone is isolated as its own mount before the
# recursive NOSUID operation and then has only NOSUID cleared, leaving it read-
# only. No other setuid/file-capability path is reopened.
SUPERVISED_FILESYSTEM_SETUP = r'''
import ctypes
import os
import stat
import sys

if os.geteuid() != 0 or os.getpid() != 1:
    raise RuntimeError("supervised setup requires the private namespace init")
scratch, uid, gid, size, inodes, workdir = sys.argv[1:7]
command = sys.argv[7:]
if not command or command[0] != "/usr/bin/prlimit":
    raise RuntimeError("invalid fixed supervised command")
if not os.path.isabs(workdir) or not os.path.isdir(workdir):
    raise RuntimeError("invalid supervised working directory")
if not stat.S_ISREG(os.stat("/usr/bin/sudo", follow_symlinks=False).st_mode):
    raise RuntimeError("fixed sudo executable is unavailable")
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
checked(mount(None, b"/", None, (1 << 14) | (1 << 18), None), "private mount tree")
# MS_BIND: give sudo a dedicated mount so NOSUID can be restored nowhere else.
checked(mount(b"/usr/bin/sudo", b"/usr/bin/sudo", None, 1 << 12, None), "isolate fixed sudo mount")
attributes = MountAttr(1 | 2, 0, 0, 0)  # RDONLY | NOSUID
checked(mount_setattr(-100, b"/", 0x8000, ctypes.byref(attributes),
                     ctypes.sizeof(attributes)), "recursive read-only nosuid mount tree")
# Clear only MOUNT_ATTR_NOSUID on the exact sudo bind mount. RDONLY remains.
sudo_attributes = MountAttr(0, 2, 0, 0)
checked(mount_setattr(-100, b"/usr/bin/sudo", 0, ctypes.byref(sudo_attributes),
                     ctypes.sizeof(sudo_attributes)), "enable fixed sudo mount")
# Root-owned sticky aggregate scratch prevents the worker from replacing a
# root-created nested-actor mountpoint even though both share the same tmpfs.
options = f"size={size},nr_inodes={inodes},mode=1777,uid=0,gid=0".encode("ascii")
checked(mount(b"tmpfs", os.fsencode(scratch), b"tmpfs", 2 | 4 | 8, options), "private supervised tmpfs")
worker_home = os.path.join(scratch, "worker-home")
os.mkdir(worker_home, 0o700)
os.chown(worker_home, int(uid), int(gid))
os.chdir(workdir)
# Replace placeholders after mount setup so the worker sees namespace-local paths.
command = [worker_home if item == "@WORKER_HOME@" else item for item in command]
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


def _cgroup_path() -> Path:
    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            relative = line[3:]
            return Path("/sys/fs/cgroup") / relative.lstrip("/")
    raise RuntimeError("cgroup v2 membership is unavailable")


def _bounded_parent_scope() -> bool:
    """Reuse an already-bounded parent based only on trusted kernel state."""
    group = _cgroup_path()
    memory = (group / "memory.max").read_text(encoding="ascii").strip()
    pids = (group / "pids.max").read_text(encoding="ascii").strip()
    cpu = (group / "cpu.max").read_text(encoding="ascii").split()

    # An ordinary hosted-runner/service cgroup is normally looser or unbounded.
    # In that case create our own fixed scope below. A nested helper launched
    # from the supervised suite, however, is already in the verified aggregate
    # and must remain there regardless of caller-controlled environment changes.
    if memory == "max" or pids == "max" or not cpu or cpu[0] == "max":
        return False
    try:
        memory_limit = int(memory)
        pids_limit = int(pids)
        quota, period = (int(value) for value in cpu)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("malformed cgroup v2 resource limits") from exc
    check(memory_limit > 0 and pids_limit > 0 and quota > 0 and period > 0,
          "invalid cgroup v2 resource limits")
    return (
        memory_limit <= SUPERVISED_MEMORY_BYTES
        and pids_limit <= SUPERVISED_TASKS
        and quota * 2 <= period
    )


def scoped(
    command: list[str],
    unit: str,
    *,
    memory_bytes: int,
    tasks: int,
    cpu_quota: str,
) -> list[str]:
    # Nested actor helpers launched by a sandboxed current-test worker remain in
    # the already-verified parent aggregate cgroup. Containment is derived from
    # live cgroup state, never an environment variable the test can unset. They
    # still create their own PID/mount/network namespace and keep prlimits.
    if _bounded_parent_scope():
        return command
    check(SYSTEMD_RUN.is_file() and SYSTEMCTL.is_file(),
          "aggregate cgroup controller is unavailable")
    check(Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
          "cgroup v2 is required for aggregate resource limits")
    return [
        str(SYSTEMD_RUN), "--system", "--scope", "--quiet",
        f"--unit={unit}",
        "-p", f"MemoryMax={memory_bytes}",
        "-p", "MemorySwapMax=0",
        "-p", f"TasksMax={tasks}",
        "-p", f"CPUQuota={cpu_quota}",
        "--",
        *command,
    ]


def bounded_drain(stream, retained: bytearray, overflow: threading.Event) -> None:
    try:
        while chunk := stream.read(8192):
            if len(retained) + len(chunk) > OUTPUT_BYTES:
                overflow.set()
                remaining = max(0, OUTPUT_BYTES - len(retained))
                if remaining:
                    retained.extend(chunk[:remaining])
            elif not overflow.is_set():
                retained.extend(chunk)
    finally:
        stream.close()


def _secure_scratch_parent() -> Path:
    parent = Path(os.environ.get("BLUE_FORGE_ISOLATED_TMPDIR", "/tmp"))
    check(parent.is_absolute() and parent.is_dir() and not parent.is_symlink(),
          "isolated scratch parent is invalid")
    info = parent.stat()
    writable_by_unprivileged = bool(info.st_mode & 0o022)
    check(
        info.st_uid == 0
        and (
            not writable_by_unprivileged
            or bool(info.st_mode & stat.S_ISVTX)
        ),
        "isolated scratch parent must be root-owned and either protected or sticky",
    )
    return parent


def parse_invocation():
    if len(sys.argv) >= 2 and sys.argv[1] == "--direct-suite":
        check(len(sys.argv) == 4, "direct suite requires Python and source root")
        return "direct", Path(sys.argv[2]), None, Path(sys.argv[3]), None
    if len(sys.argv) >= 2 and sys.argv[1] == "--supervised-suite":
        check(len(sys.argv) == 5,
              "supervised suite requires Python, supervisor, and source root")
        return "supervised", Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), None
    check(len(sys.argv) == 5, "expected root launcher and four actor path arguments")
    return "actor", Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])


def _live_marker(marker: str) -> bool:
    encoded = marker.encode("ascii")
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if encoded in path.read_bytes().split(b"\x00"):
                return True
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return False


def main() -> int:
    check(os.geteuid() == 0, "expected root launcher")
    mode, python_bin, supervisor, source_root, control_path = parse_invocation()
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

    tests_dir = source_root / "tests" if mode in {"direct", "supervised"} else None
    if mode in {"direct", "supervised"}:
        check(caller == current_user.pw_uid,
              f"{mode} proposed suite is restricted to blueforge-current")
        root_info = source_root.stat()
        check(root_info.st_uid == 0 and not root_info.st_mode & 0o022,
              f"{mode} suite source root must be root-owned and non-writable")
        check(tests_dir.is_dir() and not tests_dir.is_symlink(),
              f"{mode} suite tests directory is unavailable")
        tests_info = tests_dir.stat()
        check(tests_info.st_uid == 0 and not tests_info.st_mode & 0o022,
              f"{mode} suite tests directory must be root-owned and non-writable")

    control = None
    selector = selectors.DefaultSelector()
    if mode == "actor":
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

    target = rpc if mode == "actor" else current_user
    parent = _secure_scratch_parent()
    home = Path(tempfile.mkdtemp(prefix="blue-forge-isolated-home-", dir=parent))
    process = None
    reader = None
    retained = bytearray()
    overflow = threading.Event()
    unit = f"blue-forge-proposed-{os.getpid()}-{time.monotonic_ns()}.scope"
    interrupted = []
    lifeline_deadline = None
    marker = (
        f"blue-forge-supervised-child-{os.getpid()}-{time.monotonic_ns()}"
        if mode == "supervised" else None
    )

    def interrupted_by(signum, frame):
        interrupted.append(signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted_by)

    try:
        home.chmod(0o700)
        if mode == "direct":
            proposed_command = [
                str(python_bin), "-m", "unittest", "discover",
                "-s", str(tests_dir), "-v",
            ]
        elif mode == "supervised":
            proposed_command = [
                str(python_bin), "-I", str(supervisor),
                "--root", str(source_root), "--python", str(python_bin),
            ]
        else:
            proposed_command = [
                str(python_bin), "-I", str(supervisor), "--actor-root", str(source_root)
            ]

        if mode == "supervised":
            # The cgroup is the aggregate task authority for the whole proposed
            # worker tree. Do not duplicate that ceiling with RLIMIT_NPROC: that
            # per-real-UID limit can reject a legitimate subprocess before the
            # cgroup's descendant-wide TasksMax is reached.
            actor_command = [
                "/usr/bin/prlimit",
                "--as=536870912", "--cpu=120",
                "--fsize=16777216", "--nofile=256", "--core=0", "--",
                "/usr/bin/setpriv",
                f"--reuid={target.pw_uid}", f"--regid={target.pw_gid}", "--clear-groups",
                "--inh-caps=-all", "--ambient-caps=-all", "--pdeathsig=KILL", "--",
                "/usr/bin/env", "-i",
                "HOME=@WORKER_HOME@", f"TMPDIR={home}", "PATH=/usr/bin:/bin",
                "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1",
                f"LD_LIBRARY_PATH={python_bin.parent.parent / 'lib'}",
                f"BLUE_FORGE_RPC_HELPER={FIXED_HELPER}",
                f"BLUE_FORGE_ISOLATED_TMPDIR={home}",
                "BLUE_FORGE_SUPERVISED_SANDBOX=1",
                f"BLUE_FORGE_SUPERVISED_MARKER={marker}",
                *proposed_command,
            ]
            setup = SUPERVISED_FILESYSTEM_SETUP
            storage_bytes = SUPERVISED_STORAGE_BYTES
            storage_inodes = SUPERVISED_STORAGE_INODES
            memory_bytes = SUPERVISED_MEMORY_BYTES
            tasks = SUPERVISED_TASKS
            cpu_quota = SUPERVISED_CPU_QUOTA
            lifetime = SUPERVISED_SECONDS
        else:
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
            if mode == "direct":
                actor_command.append("BLUE_FORGE_RPC_HELPER=/nonexistent")
            actor_command.extend(proposed_command)
            setup = FILESYSTEM_SETUP
            storage_bytes = ACTOR_STORAGE_BYTES
            storage_inodes = ACTOR_STORAGE_INODES
            memory_bytes = ACTOR_MEMORY_BYTES
            tasks = ACTOR_TASKS
            cpu_quota = ACTOR_CPU_QUOTA
            lifetime = ACTOR_SECONDS

        setup_args = [
            str(home), str(target.pw_uid), str(target.pw_gid),
            str(storage_bytes), str(storage_inodes), str(source_root),
        ]
        if mode != "supervised":
            mask_rpc_proc = (
                mode == "actor"
                and supervisor is not None
                and supervisor.name == "run_frozen_tests_supervised.py"
            )
            setup_args.append("1" if mask_rpc_proc else "0")
        namespace_command = [
            "/usr/bin/setpriv", "--pdeathsig=KILL", "--",
            "/usr/bin/unshare", "--mount", "--propagation", "private",
            "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "--net", "--",
            "/usr/bin/python3", "-I", "-S", "-c", setup,
            *setup_args,
            *actor_command,
        ]
        command = scoped(
            namespace_command,
            unit,
            memory_bytes=memory_bytes,
            tasks=tasks,
            cpu_quota=cpu_quota,
        )
        popen_kwargs = {
            "cwd": source_root,
            "start_new_session": True,
            "env": {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        }
        if mode in {"direct", "supervised"}:
            popen_kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        process = subprocess.Popen(command, **popen_kwargs)
        if mode in {"direct", "supervised"}:
            reader = threading.Thread(
                target=bounded_drain, args=(process.stdout, retained, overflow), daemon=True
            )
            reader.start()

        deadline = time.monotonic() + lifetime
        while process.poll() is None:
            now = time.monotonic()
            if interrupted:
                return 128 + interrupted[0]
            if overflow.is_set():
                print(f"isolated_{mode}_suite=FAIL reason=output budget exceeded", file=sys.stderr)
                return 125
            if mode == "actor" and lifeline_deadline is not None and now >= lifeline_deadline:
                # The trusted worker is gone or closing. Give the broker a short
                # window to reap its executor and exit naturally, then force the
                # existing namespace/cgroup teardown without treating that forced
                # cleanup as an application result.
                return 0
            if now >= deadline:
                label = "isolated_actor" if mode == "actor" else f"isolated_{mode}_suite"
                print(f"{label}=FAIL reason=lifetime budget exceeded", file=sys.stderr)
                return 124
            if mode == "actor":
                if lifeline_deadline is None:
                    for _key, _mask in selector.select(0.05):
                        data = os.read(control, 1)
                        check(data == b"", "worker lifeline carried unexpected data")
                        selector.unregister(control)
                        lifeline_deadline = min(
                            deadline,
                            time.monotonic() + ACTOR_GRACEFUL_TEARDOWN_SECONDS,
                        )
                        break
                else:
                    time.sleep(0.05)
            else:
                time.sleep(0.05)

        if mode in {"direct", "supervised"}:
            if reader is not None:
                reader.join(timeout=3)
                check(not reader.is_alive(), f"{mode}-suite output drain did not terminate")
            sys.stdout.buffer.write(bytes(retained))
            sys.stdout.buffer.flush()
            if overflow.is_set():
                print(f"isolated_{mode}_suite=FAIL reason=output budget exceeded", file=sys.stderr)
                return 125
            if process.returncode == 0:
                print(f"isolated_{mode}_suite=PASS")
            return process.returncode if process.returncode >= 0 else 128 - process.returncode
        return process.returncode if process.returncode >= 0 else 128 - process.returncode
    finally:
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
        if marker is not None:
            deadline = time.monotonic() + 5
            while _live_marker(marker) and time.monotonic() < deadline:
                time.sleep(0.05)
            check(not _live_marker(marker),
                  "detached proposed test descendant survived supervised sandbox teardown")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        if len(sys.argv) > 1 and sys.argv[1] == "--direct-suite":
            label = "isolated_direct_suite"
        elif len(sys.argv) > 1 and sys.argv[1] == "--supervised-suite":
            label = "isolated_supervised_suite"
        else:
            label = "isolated_actor"
        print(f"{label}=FAIL reason={str(exc)!r}", file=sys.stderr)
        raise SystemExit(1)
