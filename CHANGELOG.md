# Changelog

All notable changes to QSOL-BLUE-FORGE will be documented here.

## Unreleased

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
- Only load-bearing v1 semantic/provenance artifacts are byte-pinned; operational prose remains editable subject to targeted semantic checks.
