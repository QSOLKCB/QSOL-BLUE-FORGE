# BLUE-FORGE Core Invariants

**Normative contract:** `blue-forge.core-invariants/v1`  
**Machine registry:** [`contracts/core-invariants-v1.json`](../contracts/core-invariants-v1.json)

These rules are constitutional. They define the minimum security semantics every implementation, adapter, optimization, model integration, verifier, and future contract revision must preserve.

A faster or more capable implementation is a regression if it weakens one of these invariants.

## Decision lattice

Within one immutable run:

```text
ALLOW < REVIEW < DENY
```

Automated stages may preserve or tighten a decision. They may not silently weaken it. A deliberate human or policy override begins a new versioned decision context and preserves the prior result as history.

## BLUE_HARDENED predicate

`BLUE_HARDENED` is an earned state. All of the following must be true:

```text
original_attack_neutralized
AND attack_class_invariant_holds
AND benign_controls_pass
AND provenance_valid
AND verification_complete
AND replay_exact
AND authority_not_expanded
AND reference_equivalence_preserved
```

A missing, unsupported, timed-out, malformed, or otherwise incomplete predicate cannot be treated as true.

## BF-INV-001 - Authority Cannot Silently Expand

Effective authority must remain a subset of the authority both requested and permitted by policy.

```text
effective_authority <= requested_authority INTERSECT policy_authority
```

Models, adapters, geometry, optimizers, capture layers, and verifiers may reduce authority or request review. They may not manufacture authority.

## BF-INV-002 - Defensive Decisions Are Monotonic

Inside one immutable run, automated downstream stages may preserve or tighten `ALLOW < REVIEW < DENY`. They may not weaken a previous decision. Reconsideration requires a new, explicitly versioned decision context.

## BF-INV-003 - No Self-Certification

The component proposing a mitigation cannot be the sole authority declaring that mitigation verified. Proposal and verification identities must remain distinguishable in evidence.

## BF-INV-004 - Provenance Before Interpretation

Unverified material may be inspected as untrusted evidence. It cannot become load-bearing trusted evidence until the required provenance checks succeed.

## BF-INV-005 - Evidence Is Data

Ingestion does not grant execution authority. Hostile or untrusted evidence must not become executable merely because it is imported, parsed, archived, indexed, rendered, or inspected.

Security-sensitive ingestion paths must avoid unsafe deserialization, implicit command execution, arbitrary constructors, uncontrolled includes, and equivalent authority-bearing behavior.

## BF-INV-006 - Replay Failure Is Verification Failure

For a pinned contract:

```text
same captured bytes
+ same policy
+ same engine identity
= same canonical result
```

Unexpected replay divergence invalidates verification until explained under a new contract identity or corrected implementation.

## BF-INV-007 - Benign Behaviour Must Survive

A mitigation is incomplete if it blocks the hostile case only by unnecessarily destroying required legitimate behavior. Appropriate hostile regression vectors require benign controls exercising the preserved contract.

## BF-INV-008 - Unknown Is Not Safe

The following are never equivalent to successful verification:

```text
UNKNOWN
MALFORMED
UNSUPPORTED
INCOMPLETE
TIMEOUT
OOM
RESOURCE_LIMIT
```

A failure to determine safety cannot manufacture `ALLOW` or `VERIFIED`.

## BF-INV-009 - Resource Exhaustion Cannot Produce Verification

CPU, memory, recursion, decompression, worker, fixture, time, output, or evidence limits are security boundaries. Exceeding a configured limit must produce an explicit incomplete or denied outcome, never success.

## BF-INV-010 - Optimisation Cannot Reduce the Proof Surface

Optimization may reduce the cost of proving security. It may not reduce the amount of security being proved.

It must not silently weaken assertions, adversarial-class coverage, benign controls, provenance, isolation, tolerances, deterministic guarantees, boundary tests, or exact replay.

**Proof first. Reuse second.**

## BF-INV-011 - Parallelism Is Semantically Invisible

Worker count, partitioning, and completion order are performance properties. They must not alter canonical security meaning.

Where parallel execution exists, a scalar or otherwise canonical reference path must remain available for equivalence testing.

## BF-INV-012 - Model Agreement Is Not Proof

One model or many models may propose, correlate, classify, or explain. Model consensus does not promote a claim to verified evidence without an independent verification predicate.

## BF-INV-013 - Semantic Changes Require New Contract Identity

Changes to policy meaning, normalization, trust semantics, decision ordering, receipt meaning, invariant semantics, or verification semantics require a new contract identity and new conformance vectors.

Old evidence must not silently acquire new meaning.

## BF-INV-014 - No Silent Degradation

If a required verifier, provenance mechanism, replay capability, or other load-bearing control is unavailable, the system must report that limitation explicitly. It may not silently substitute a weaker mechanism and report success.

## BF-INV-015 - Deception Outward, Truth Inward

Defensive deception may shape hostile behavior toward low-authority, instrumented surfaces. It must never deceive defenders about what was observed, inferred, simulated, verified, incomplete, or decoyed.

The following distinctions are load-bearing:

```text
observed != inferred
inferred != verified
simulated != observed
decoy != production
unknown != safe
```

## BF-INV-016 - Minimum Necessary Intervention

For equivalent verified security outcomes, prefer the mitigation that changes the smallest necessary authority set, resource set, user population, service scope, and time window.

This principle does not forbid broader containment when evidence requires it. It requires broader intervention to be justified rather than automatic.

## Amendment rule

The identifiers `BF-INV-001` through `BF-INV-016` are frozen for contract v1.

A future contract may clarify wording without changing meaning. A semantic change, removal, weakening, renumbering, or incompatible reinterpretation requires a new contract identity and migration notes. CI intentionally checks this rule.
