# Changelog

All notable changes to QSOL-BLUE-FORGE will be documented here.

## Unreleased

### Added

- Deterministic, standard-library defensive reference core under `blue_forge/`.
- Strict `blue-forge.hardening-case/v1` parser and documented JSON schema.
- Derived `BLUE_HARDENED` evaluation with all eight constitutional predicates.
- Deterministic verification receipts and permanent regression-memory records.
- Synthetic path-boundary hardening fixture with hostile variants and benign controls.
- Immutable OPT v1.0.0 reuse record for `OPT-PY-001` and `OPT-INV-001`.
- Split CI materialization for trusted-baseline and proposed reference-core sources.

### Security

- Reference-core evidence is treated strictly as data and is never executed.
- CLI case input is UTF-8-only and bounded to 1 MiB.
- Duplicate keys, floats, excessive JSON nesting, oversized arrays, duplicate capabilities, duplicate evidence IDs, unknown fields, and invalid digests fail closed.
- Proposal and verification producers must differ.
- Verification decisions may not weaken proposal decisions.
- Observed authority must remain within requested/policy and pre-mitigation authority ceilings.
- `UNKNOWN`, incomplete evidence, replay divergence, benign-control regressions, authority expansion, or reference divergence prevent `BLUE_HARDENED`.
- Trusted regression CI now runs trusted tests against trusted reference-core source before the proposed source is imported.

## v1.0.0 - 2026-09-04

### Added

- `blue-forge.core-invariants/v1` with `BF-INV-001` through `BF-INV-016`.
- Machine-readable constitutional registry and normative invariant documentation.
- Defensive engagement-area and parser doctrines.
- HERESY-SEC v0.3.0 source-provenance archive boundary.
- Security, ethics, machine-agent, and AI-facing project guidance.
- Fail-closed constitutional auditor with an external trusted v1 baseline ref.
- Standard-library regression coverage for semantic, provenance, parser, archive, required-file, and forged-history tampering.
- Read-only GitHub Actions constitutional gate with pinned Python and immutable action revisions.

### Security

- Default CI is non-executing for adversarial material; live parser/differential execution requires a separate opt-in `workflow_dispatch` workflow.
- Contract v1 no longer derives its trust anchor from PR-controlled `HEAD` history.
- Load-bearing v1 semantics, machine policy, security/ethics policy, provenance, workflow trust, and regression floors are protected by the external baseline.
