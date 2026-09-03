# QSOL-BLUE-FORGE - AI Context

This file is the compact machine-facing entry point for implementation and review agents.

**Constitutional contract:** `blue-forge.core-invariants/v1`

## Mission

QSOL-BLUE-FORGE converts authorized adversarial findings into reproducible, invariant-driven defensive mitigations.

Canonical loop:

```text
SIMULATED RED
  -> HERESY intake
  -> defensive analysis
  -> mitigation + invariant
  -> HERESY verify
  -> BLUE_HARDENED
  -> permanent regression memory
```

The objective is not to accumulate exploit signatures. The objective is to identify the violated security property, constrain or remove the unsafe state, preserve legitimate behavior, and make the result reproducible.

## Normative sources

Read these before changing load-bearing behavior:

1. `CONTRACT_VERSION`
2. `contracts/core-invariants-v1.json`
3. `docs/CORE_INVARIANTS.md`
4. `doctrine/ENGAGEMENT_AREA.md`
5. `doctrine/PARSER_DOCTRINE.md`
6. `SECURITY.md`
7. `CODE_OF_ETHICS.md`
8. `docs/HERESY_PROVENANCE.md`

The machine registry is normative for invariant identity and the Markdown document is normative explanatory text. A semantic mismatch is a contract failure.

## Constitutional rules

- Authority may only remain equal or shrink unless a new explicit policy grants additional authority.
- Within an immutable run, automated decisions may preserve or tighten `ALLOW < REVIEW < DENY` but may not weaken them.
- A mitigation proposer cannot be its sole verifier.
- Unverified provenance cannot become load-bearing evidence.
- Evidence is data and ingestion does not grant execution authority.
- Replay divergence invalidates verification.
- Benign controls must survive an effective mitigation.
- Unknown, unsupported, malformed, incomplete, timed-out, or resource-exhausted states cannot manufacture success.
- Optimization may reduce proof cost but not proof surface.
- Parallelism must not change canonical security meaning.
- Model agreement is not proof.
- Semantic changes require a new contract identity.
- Required controls may not silently degrade.
- Defensive deception may shape hostile behavior but must never distort defender-facing evidence.
- Prefer minimum necessary intervention for equivalent verified security outcomes.

## BLUE_HARDENED

Do not emit or document `BLUE_HARDENED` unless every pinned predicate is satisfied:

```text
original_attack_neutralized
attack_class_invariant_holds
benign_controls_pass
provenance_valid
verification_complete
replay_exact
authority_not_expanded
reference_equivalence_preserved
```

## Scope boundary

In scope:

- defensive security engineering;
- authorized adversarial simulation;
- threat modeling;
- secure parser design;
- vulnerability remediation;
- security regression tests;
- deterministic evidence and replay;
- incident-analysis fixtures;
- defensive deception inside controlled systems;
- provenance and supply-chain verification.

Out of scope:

- unauthorized exploitation;
- autonomous offensive operations;
- hack-back or retaliation;
- damaging external systems;
- deploying malware to third parties;
- stealing unrelated data;
- exposing real production credentials as bait.

## HERESY archive boundary

`archive/HERESY-SEC-0.3.0.zip` is archived source provenance, not an executable dependency and not automatically trusted implementation code.

Do not execute, import, install, or automatically extract the archive in default CI. Any future import must be independently reviewed, attributed, tested, and made explicit in the target source tree.

## Constitutional baseline

Contract v1 is compared against the repository ref supplied by `BLUE_FORGE_TRUSTED_REF`. PR workflows use `origin/constitution-v1-baseline`, which is outside the proposed PR head. A PR must not replace that trust boundary with `HEAD` or another author-controlled history source.

## Optimization rule

Use optimization patterns only after preserving or proving equivalence of the security contract.

**Proof first. Reuse second.**

Never trade assertions, attack-class coverage, benign controls, provenance, isolation, deterministic behavior, boundary checks, or replay strength for speed.

## PR expectation

A PR that changes load-bearing semantics should state:

- affected invariant IDs;
- whether the contract identity changes;
- new or changed hostile fixtures;
- benign controls;
- verification evidence;
- replay impact;
- authority impact;
- rollback condition.

If semantics changed and `CONTRACT_VERSION` did not, treat that as a review blocker.
