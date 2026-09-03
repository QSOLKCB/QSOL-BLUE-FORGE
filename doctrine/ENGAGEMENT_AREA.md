# Defensive Engagement Area Doctrine

QSOL-BLUE-FORGE uses **engagement area** as a defensive systems metaphor: shape risky behavior toward low-authority, highly observable, strongly bounded surfaces while keeping consequential authority behind independently verified controls.

This document defines the cyber-defensive abstraction only. It is not a guide to physical ambushes, weapons, or military operations.

## Doctrine

Do not attempt to defend every possible route equally.

Design the system so that:

- the safest legitimate route is also the easiest legitimate route;
- suspicious routes naturally lose authority;
- risky transitions become more observable, not less;
- hostile behavior is contained before consequential boundaries;
- every meaningful decision can be attributed and replayed;
- the defender sees truthful evidence even when the hostile observer sees a decoy.

## Terrain model

```text
                 CONSEQUENTIAL AUTHORITY
                         |
                  verified controls
                         |
              +----------+----------+
              |                     |
      safe legitimate path    suspicious behavior
              |                     |
              |                     v
              |             instrumented surface
              |                     |
              |                low authority
              |                     |
              +------------> HERESY evidence
                                    |
                              Blue analysis
                                    |
                             HERESY verify
```

## DISRUPT

Break unsafe assumptions without granting new authority.

Defensive examples include:

- canonicalization before policy;
- re-authentication before sensitive transitions;
- bounded resource budgets;
- capability separation;
- invalidation of stale authority;
- deterministic policy gates.

DISRUPT must not depend on harming a remote system.

## TURN

Redirect risky behavior toward a safer and more observable path.

Examples:

```text
untrusted parser input -> restricted canonical parser
suspicious enumeration -> low-authority instrumented namespace
untrusted operation -> sandboxed capability surface
```

TURN may preserve or reduce authority. It may never silently increase authority.

## FIX

Constrain a suspicious session or action to an explicitly bounded environment so that continued observation cannot become privilege escalation.

Possible defensive constraints include:

- fixed filesystem scope;
- fixed network destination set;
- fixed process capability set;
- bounded CPU, memory, time, and output;
- mandatory evidence capture;
- prevention of persistence.

FIX means containment, not retaliation.

## BLOCK

Hard-deny transitions that cross protected boundaries without sufficient authority and provenance.

Examples include:

- production credential access;
- unauthorized persistence;
- privilege escalation;
- unauthorized process execution;
- unapproved network egress;
- cross-tenant access;
- untrusted provenance entering a trusted decision path.

A hard boundary is not subject to model voting.

## Self-reliance

The deterministic defensive nucleus should remain safe when optional external services disappear.

Loss of an AI provider, external API, network connection, SIEM integration, or remote model must not convert a previous `DENY` into `ALLOW` or fabricate verification.

External systems may improve analysis. They are not the sole basis of safety.

## Truth in reporting

**Deception outward, truth inward.**

Defensive deception may shape a hostile observer's choices through low-authority decoys, honeytokens, canary identifiers, or instrumented namespaces. The defender-facing evidence must remain exact about:

- what was observed;
- what was inferred;
- what was simulated;
- what was verified;
- what was a decoy;
- what remains unknown.

The system must not use deception to exaggerate confidence or attribution.

## Precision and minimum intervention

For equivalent verified security outcomes, prefer the smallest intervention that preserves the invariant.

Examples of the principle include preferring a narrowly scoped capability revocation over disabling unrelated services when both provide equivalent protection.

Broader containment remains legitimate when evidence requires it. The doctrine requires justification, not passivity.

## Path-of-least-resistance rule

The path of least resistance should be intentionally safe for legitimate users and intentionally low-authority for suspicious behavior.

A risky path should become progressively:

```text
less authoritative
more observable
more bounded
more reproducible
```

This transforms path selection from an attacker advantage into a defensive design property.

## Ethical boundary

Defensive engagement areas may observe and contain activity inside systems the operator is authorized to control. They must not cross into hack-back, remote damage, malware deployment to third parties, unrelated data theft, or exposure of real production secrets as bait.
