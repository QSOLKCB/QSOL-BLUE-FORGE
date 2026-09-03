# HERESY-SEC Source Provenance

## Purpose

QSOL-BLUE-FORGE begins with HERESY-SEC as a design and implementation lineage for deterministic security evidence, policy boundaries, replay, and verification concepts.

The archived source is retained so the initial BLUE-FORGE design can be traced to a concrete source bundle rather than a mutable external branch.

## Archived bundle

```text
path: archive/HERESY-SEC-0.3.0.zip
version label: 0.3.0
size: 120145 bytes
GitHub blob object id: 76ad6138023ebe41c6a715980835403b945648f1
source project: https://github.com/QSOLKCB/HERESY-SEC
```

The GitHub blob object ID above is a repository object identity. It is not described here as a SHA-256 digest.

The constitutional audit checks that the checked-out archive still has the expected repository object identity and size.

## Trust status

The archive is:

- source provenance;
- an implementation reference;
- eligible for manual review;
- eligible to inform future BLUE-FORGE code.

The archive is **not**:

- an automatically trusted dependency;
- an executable fixture;
- an installation artifact;
- proof that inherited behavior satisfies the BLUE-FORGE contract;
- permission to bypass current review or tests.

## Import rule

If source is later imported from the archive into active BLUE-FORGE code:

1. identify the imported files and lineage;
2. review them under the current BLUE-FORGE security contract;
3. preserve applicable license and attribution obligations;
4. add tests for the relevant invariant surface;
5. verify benign controls as well as hostile cases;
6. do not execute the archive as part of the import process in default CI;
7. record any intentional semantic divergence from HERESY-SEC.

## Mutation rule

The archived bundle is treated as immutable provenance for contract v1.

Replacing or modifying it requires an explicit provenance update. A future source snapshot should normally receive a new versioned filename rather than silently replacing `HERESY-SEC-0.3.0.zip`.

## Relationship to constitutional invariants

HERESY-SEC is lineage, not constitutional authority.

BLUE-FORGE's load-bearing semantics are defined by:

- `CONTRACT_VERSION`;
- `contracts/core-invariants-v1.json`;
- `docs/CORE_INVARIANTS.md`.

Where archived HERESY behavior and the BLUE-FORGE contract differ, BLUE-FORGE must fail closed until the difference is reviewed and resolved explicitly.
