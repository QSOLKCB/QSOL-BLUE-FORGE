# OPT v1.0.0 Reuse Record

PR #2 reuses design patterns from the immutable QSOL optimization catalog
without vendoring or executing OPT source.

## Trusted source

Repository:

```text
https://github.com/QSOLKCB/OPT
```

Release:

```text
v1.0.0
```

Release target / merge commit:

```text
41e2fc3677469839fb298dedefd0ce72caebcc68
```

Final reviewed source head recorded by the release:

```text
9fa4164cf1ce8d4be6568db28e33c5242391278b
```

The GitHub release is immutable.

## Patterns adopted in PR #2

### OPT-PY-001 — Deterministic Test Execution

Applied as:

- small deterministic synthetic fixtures;
- standard-library unit tests;
- exact assertions on canonical output and receipt identity;
- no wall-clock or environment-dependent success criteria;
- no external services.

### OPT-INV-001 — Invariant-Driven Computation Reuse

Applied as:

- one canonical scalar reference evaluator;
- derived hardening predicates rather than duplicated ad hoc checks;
- shared deterministic canonicalization/digest path;
- reuse only where the security meaning is identical.

## Explicitly deferred

### OPT-PAR-001 — Bounded Deterministic Parallel Execution

Not activated in PR #2.

BLUE-FORGE first freezes and reviews the scalar reference path. A future
parallel implementation must prove:

```text
canonical_result(workers=N)
==
canonical_result(workers=1)
```

before parallelism can become load-bearing.

### OPT-LEAN-001

Not required by this Python reference-core PR.

### OPT-DSP-001

Not relevant to this defensive evidence evaluator.

## Trust rule

OPT provides optimization lineage, not constitutional authority.

BLUE-FORGE `blue-forge.core-invariants/v1` remains the governing contract.

A reused optimization pattern is rejected if it changes receipt meaning,
authority, provenance, replay, benign-control coverage, failure semantics, or
the proof surface.

**Correctness outranks speed. Proof first. Reuse second.**
