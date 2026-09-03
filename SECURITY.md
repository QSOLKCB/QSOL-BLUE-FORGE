# Security Policy

QSOL-BLUE-FORGE is an experimental defensive-security project.

## Reporting vulnerabilities

Please report suspected vulnerabilities privately through the repository owner's preferred GitHub security-reporting channel when available.

Do not place live credentials, private incident material, weaponized payloads, or sensitive exploit details in public issues.

A useful report includes:

- affected commit or release;
- affected invariant IDs if known;
- minimal reproduction in an authorized or synthetic environment;
- expected versus observed behavior;
- whether authority, provenance, replay, benign controls, or failure semantics are affected.

## Trust boundary

The project distinguishes:

```text
captured evidence
interpretation
mitigation proposal
verification evidence
```

These categories are not interchangeable.

Model output, scanner output, or archived source does not become trusted merely because it is present in the repository.

## Archived HERESY source

`archive/HERESY-SEC-0.3.0.zip` is retained for source lineage and design provenance.

Default CI must not execute, import, install, or automatically extract it. Any future code import must be reviewed as new source, attributed, tested, and subjected to the current BLUE-FORGE constitutional contract.

## Adversarial material

Static adversarial fixtures are untrusted defensive regression material.

Default CI inspects them only with bounded, non-executing mechanisms. There is no execution exception on `pull_request` or `push` workflows.

Execution of adversarial material, where live differential or parser testing requires it, happens only in a separate, explicitly opt-in `workflow_dispatch` workflow, never `pull_request`. That workflow must use:

- no production credentials;
- no writable production paths;
- no unintended network access;
- bounded CPU, memory, time, recursion, decompression, and output;
- explicit dependency versions;
- disposable execution state.

## Auditor trust boundary

The constitutional auditor cannot make its own implementation or workflow immutable. Repository governance must protect `scripts/audit_constitution.py`, `.github/workflows/**`, and the trusted constitutional baseline ref from unreviewed changes.

PR-time audit baselines must come from a ref outside the proposed PR head. Contract v1 currently uses the dedicated `constitution-v1-baseline` branch as that bootstrap anchor. A protected signed tag is preferred for a future release boundary when repository governance is configured for it.

## Defensive deception

Decoys, honeytokens, canary identifiers, and instrumented namespaces may be used inside authorized systems to improve detection and containment.

They must not be used as justification for hack-back, remote damage, unrelated data collection, or false attribution.

## Security regressions

Treat the following as security regressions even when functionality or performance improves:

- authority expansion without explicit policy;
- weakening a `DENY` inside the same immutable run;
- self-certifying mitigations;
- treating unverified provenance as trusted;
- executing evidence during ordinary ingestion;
- replay divergence;
- losing benign-control coverage;
- treating unknown or incomplete states as success;
- allowing resource exhaustion to pass verification;
- optimization that reduces proof surface;
- parallel output that changes canonical meaning;
- promoting model consensus to proof;
- changing semantics without changing contract identity;
- silent verifier degradation;
- defender-facing deception about evidence;
- unnecessarily broad intervention when a verified narrower mitigation is equivalent.

See `docs/CORE_INVARIANTS.md` for the normative IDs.
