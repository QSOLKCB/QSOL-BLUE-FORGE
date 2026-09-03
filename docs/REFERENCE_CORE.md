# Deterministic Defensive Reference Core

PR #2 introduces the first executable BLUE-FORGE implementation layer while
preserving the immutable `v1.0.0` constitutional contract.

## Scope

The reference core is deliberately small, standard-library only, offline and
non-executing.

It consumes **structured verification receipts**. It does not execute captured
hostile material, discover exploits, scan live hosts, contact external models,
or claim cryptographic attestation.

Its job is narrower:

1. parse a strict hardening-case record;
2. preserve proposer/verifier separation;
3. derive the eight `BLUE_HARDENED` predicates from structured evidence;
4. fail closed on unknown, incomplete or divergent evidence;
5. enforce authority non-expansion and monotonic decisions;
6. emit deterministic verification and regression-memory receipts.

The first reference package lives under:

```text
blue_forge/
```

## Input contract

The input schema identity is:

```text
blue-forge.hardening-case/v1
```

The JSON schema is documented at:

```text
schemas/hardening-case-v1.schema.json
```

The runtime parser is intentionally narrower than general JSON tooling:

- duplicate object keys are rejected;
- floating-point values are rejected;
- non-finite values are rejected;
- case files are bounded to 1 MiB through the CLI;
- JSON nesting is bounded;
- arrays are bounded;
- strings are bounded;
- unknown top-level or nested fields are rejected;
- constitutional invariant identifiers are restricted to `BF-INV-001` through
  `BF-INV-016`.

Canonical JSON uses UTF-8, sorted object keys, no insignificant whitespace and
the narrow supported value domain.

## No self-certification

A hardening case contains two distinct producer identities:

```text
proposal.producer
verification.producer
```

They must differ.

This is a deterministic structural enforcement of `BF-INV-003`. It is not a
cryptographic identity system. Future authenticated verifier adapters may add
stronger provenance without changing this v1 receipt meaning.

## Monotonic decisions

The decision order remains:

```text
ALLOW < REVIEW < DENY
```

The verifier may preserve or tighten the proposal decision. It may not weaken
it inside the same immutable case.

If any mandatory hardening predicate fails while a supplied verification
decision is `ALLOW`, the reference core clamps the emitted result to at least
`REVIEW`.

Unknown or incomplete evidence therefore cannot manufacture an `ALLOW`.

## Authority

The reference evaluator requires:

```text
observed_authority
    SUBSET-OF
requested_authority INTERSECT policy_authority
```

and also requires:

```text
observed_authority
    SUBSET-OF
pre_mitigation_authority
```

This makes authority shrinkage explicit and prevents a mitigation or verifier
from silently expanding capability.

## Derived BLUE_HARDENED predicates

The core does not accept a caller-supplied `BLUE_HARDENED=true` field.

It derives:

### `original_attack_neutralized`

The original hostile evidence must transition from:

```text
VULNERABLE -> BLOCKED|HARMLESS
```

### `attack_class_invariant_holds`

At least one hostile attack-class variant must be present, and every variant
must transition from:

```text
VULNERABLE -> BLOCKED|HARMLESS
```

### `benign_controls_pass`

At least one benign control must be present, and every benign control must
transition from:

```text
ALLOWED -> PRESERVED
```

### `provenance_valid`

Every evidence item must carry a lowercase SHA-256 source identity and the
verification receipt must mark its provenance state as `VERIFIED`.

This is receipt-level provenance validation, not external cryptographic
attestation.

### `verification_complete`

Required hostile variants and benign controls must exist and no evidence
transition may contain fail-closed states such as:

```text
UNKNOWN
MALFORMED
UNSUPPORTED
INCOMPLETE
BUDGET_EXCEEDED
DECODE_ERROR
TIMEOUT
OOM
```

### `replay_exact`

Each evidence record contains a reference-result digest and replay-result
digest. They must match exactly.

### `authority_not_expanded`

The observed authority must remain within both the requested/policy
intersection and the pre-mitigation authority ceiling.

### `reference_equivalence_preserved`

The supplied deterministic reference-result digest and candidate-result digest
must match exactly.

Only when **all eight** predicates pass is the emitted status:

```text
BLUE_HARDENED
```

Otherwise:

```text
NOT_HARDENED
```

## Permanent regression memory

The `regression` command emits a deterministic
`blue-forge.regression-record/v1` object containing:

- the constitutional contract identity;
- case identity and semantic case digest;
- invariant and attack-class identity;
- mitigation identity;
- hardening receipt digest;
- hostile evidence IDs;
- benign-control IDs;
- source evidence digests;
- failed predicates;
- a deterministic record digest.

The record is data. The command does not write into the repository or execute
fixtures automatically.

## CLI

Verify the synthetic reference case:

```sh
python3 -m blue_forge verify fixtures/v1/path-traversal-case.json
```

Generate permanent regression memory:

```sh
python3 -m blue_forge regression fixtures/v1/path-traversal-case.json
```

Exit codes:

```text
0  BLUE_HARDENED
2  malformed/invalid input
3  valid input but NOT_HARDENED
```

Output is canonical single-line JSON.

## Synthetic reference fixture

`fixtures/v1/path-traversal-case.json` is synthetic data. It contains evidence
identities and transition receipts, not executable payload code.

It demonstrates the invariant-level property:

```text
RESOLVED_PATH_MUST_REMAIN_WITHIN_AUTHORISED_ROOT
```

rather than encoding an exploit-string denylist.

The case includes:

- one original hostile observation;
- two hostile attack-class variants;
- two benign controls;
- narrowed authority;
- exact replay receipts;
- exact reference/candidate equivalence.

## Deliberate omissions

PR #2 does **not** add:

- live exploit execution;
- archive extraction;
- autonomous Red activity;
- network access;
- model calls;
- parallel verification;
- optimization caches;
- authenticated/cryptographic verifier identities;
- production adapters.

Those belong in later PRs after the scalar deterministic reference path is
reviewed and frozen.

**Proof first. Reuse second.**
