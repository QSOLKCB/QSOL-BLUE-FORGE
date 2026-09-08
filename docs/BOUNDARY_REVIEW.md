# Evidence, case-file and actor-storage boundary correction

This correction preserves `blue-forge.core-invariants/v1`, its accepted JSON
case meaning, and the existing SHA-256 conformance vectors. It implements
BF-INV-005, BF-INV-008, BF-INV-009 and BF-INV-014.

## Evidence IDs

The direct-case preflight validates original, variant and benign evidence IDs
through the same exact-type, length and role-syntax checks as parsed cases.
These checks precede set construction and mapping-key insertion. Caller-supplied
hash, equality and representation hooks are not needed to reject invalid IDs.

## CLI inputs

The CLI opens case paths with `O_NONBLOCK`, verifies `S_ISREG` on that exact open
descriptor, and only then reads at most `MAX_CASE_BYTES + 1` bytes. The descriptor
is closed on every post-open path. Short reads are handled without increasing
the total byte budget. FIFOs, directories, devices and symlinks to nonregular
files fail as malformed input. Symlinks to regular case files remain supported.
Platforms without nonblocking open support fail explicitly. This is a special-
file blocking fix, not a guarantee about latency of arbitrary network-backed
or malfunctioning regular-file storage.

The original read-budget regression now uses a real regular descriptor and an
actor-side read spy; its exact `MAX_CASE_BYTES + 1` assertion is retained.
The frozen CLI receives the same descriptor-reader correction independently,
without importing newer proposed schema or evaluator behavior into that source.

## Disposable storage

Before dropping to the actor UID, the fixed launcher uses a system Python
interpreter in isolated mode inside fresh private mount/PID/network namespaces.
It applies recursive read-only, nosuid mount attributes to the namespace's root
mount tree using `mount_setattr`. These are per-mount attributes, not changes to
the runner's underlying filesystem superblocks. No writable-host-tree fallback
is permitted when setup is unavailable or fails.

The launcher then mounts one private `tmpfs` at HOME/TMPDIR with a 32 MiB byte
limit and 1,024-inode limit, plus nosuid, nodev and noexec. Ordinary writes outside
that mount, including `/var/tmp`, `/tmp` and `/dev/shm`, are denied. Existing
per-file, memory, CPU, process, descriptor and lifetime limits remain in force.
The host mountpoint remains root-owned and empty; namespace teardown destroys
the private storage before the launcher removes that mountpoint.

The kernel integration test checks real EROFS failures, a successful private
write/read, an outward symlink, aggregate ENOSPC across several individually
small files, inode ENOSPC, and removal of the home and host-side probe paths.
It runs through both current-suite modes in CI; local systems without the fixed
CI helper skip this integration test, not the application regression tests.

## Governance

Authorize only the reviewed launcher, the baseline-specific CLI reader change,
and the matching read-budget fixture on the external baseline. Do not point the
baseline at the PR head or advance the evaluator, schemas, fixture, golden
hashes, supervisor or workflow. The new tests are proposed coverage, not a silent
promotion of the entire current suite into the frozen floor.

Implementation references: Linux mount_setattr(2),
https://man7.org/linux/man-pages/man2/mount_setattr.2.html ; Linux tmpfs,
https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html .
