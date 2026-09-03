# Contract Migration Doctrine

This document defines the trusted handoff from `blue-forge.core-invariants/v1` to any successor constitutional contract.

## Rule

A successor contract is additive. A migration MUST NOT reinterpret, replace, weaken, or delete the frozen v1 semantic, machine-policy, security-policy, ethics, provenance, doctrine, or archive artifacts.

The v1 auditor remains the authority that validates the handoff. A successor PR does not get to replace the trusted v1 auditor in order to authorize itself.

## Trusted authorization

Before a successor-contract PR can pass, the trusted constitutional baseline ref must contain exactly one authorization manifest under:

```text
contracts/migrations/*.json
```

whose `to` value exactly matches the proposed `CONTRACT_VERSION`.

The authorization manifest is a trust decision and therefore belongs on the trusted baseline ref, not solely in the proposed PR. The proposed PR MUST include the identical manifest object for transparency and replay.

The manifest schema is:

```json
{
  "schema": "blue-forge.contract-migration/v1",
  "from": "blue-forge.core-invariants/v1",
  "to": "blue-forge.<successor>/vN",
  "mode": "additive-preserve-v1",
  "successor_contract_files": [
    {
      "path": "contracts/...",
      "git_oid": "0123456789abcdef0123456789abcdef01234567"
    }
  ],
  "conformance_evidence": [
    {
      "path": "conformance/...",
      "git_oid": "89abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

Requirements:

- `from` MUST equal `blue-forge.core-invariants/v1`.
- `to` MUST equal the proposed `CONTRACT_VERSION` and MUST differ from v1.
- `mode` MUST equal `additive-preserve-v1`.
- `successor_contract_files` MUST be non-empty and identify the exact Git blob objects that define the successor contract.
- `conformance_evidence` MUST be non-empty and identify the exact Git blob objects containing migration/conformance evidence.
- every artifact record MUST contain exactly `path` and `git_oid`.
- every `git_oid` MUST be a lowercase 40-hex Git blob object id and the committed object at `path` MUST match it exactly.
- every listed path MUST be repository-relative, normalized, non-escaping, and committed as mode `100644`.
- the checked-out bytes at every listed path MUST match the authorized Git object without Git filters.
- the authorization manifest in the PR MUST be byte-identical to the trusted baseline copy.
- every frozen v1 artifact continues to match the trusted v1 baseline exactly.

Path names alone are not authorization. A successor contract or evidence file whose bytes differ from the trusted `git_oid` is a migration failure even when the path is unchanged.

## Handoff semantics

Changing `CONTRACT_VERSION` alone is a failure.

Changing v1 artifacts while also changing `CONTRACT_VERSION` is a failure.

A valid migration therefore has this shape:

```text
trusted v1 artifacts: preserved exactly
trusted migration authorization: present
CONTRACT_VERSION: successor identity
successor contract blobs: exact authorized Git objects
conformance evidence blobs: exact authorized Git objects
```

Machine-facing successor guidance should be added under new versioned paths rather than rewriting the frozen v1 machine-policy files during the handoff.

After a successor contract is accepted, a later governance change may establish a new trusted baseline/auditor for that successor. That later trust transition is separate from the v1-to-successor migration itself.
