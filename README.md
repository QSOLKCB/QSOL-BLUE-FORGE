# QSOL-BLUE-FORGE

**Shape the terrain. Prove the defence.**

QSOL-BLUE-FORGE is a defensive cyber-engineering framework for converting authorised adversarial findings into reproducible, invariant-driven mitigations.

The project combines simulated Red activity, deterministic evidence capture, defensive analysis, independent verification and permanent regression memory into a single Blue-Team hardening loop.

The objective is not merely to patch individual exploit payloads.

The objective is to identify the unsafe state or trust-boundary failure that made an exploit possible, encode that condition as a defensive invariant, eliminate or constrain the entire attack class, and prove that the resulting mitigation preserves legitimate behaviour.

```text
SIMULATED RED
      |
      v
HERESY-SEC
capture / canonicalize / provenance
      |
      v
DEFENSIVE ANALYSIS
Daybreak Blue / human / approved defensive tooling
      |
      v
MITIGATION + INVARIANT
      |
      v
HERESY VERIFY
independent deterministic verification
      |
      v
BLUE_HARDENED
      |
      v
PERMANENT REGRESSION MEMORY
      |
      +--------------------> next adversarial cycle
```

---

## Status

**Experimental / defensive research**

QSOL-BLUE-FORGE is being developed as a defensive security engineering and verification framework.

It is not:

* an autonomous offensive system;
* an exploit-development framework;
* a replacement for professional incident response;
* a mechanism for unauthorised testing;
* a hack-back platform;
* a system for retaliating against remote infrastructure.

All adversarial activity used by the project must be authorised, simulated, synthetic, captured from approved testing environments, or derived from legitimate defensive evidence.

---

## Initial repository state

The initial repository contains:

* this architectural and doctrinal specification;
* a bundled HERESY-SEC source archive used as the starting deterministic evidence and replay substrate.

HERESY-SEC provides the initial implementation lineage for:

* canonical security inputs;
* deterministic `ALLOW`, `REVIEW` and `DENY` decisions;
* hard authority boundaries;
* exact replay;
* hash-bound evidence;
* fail-closed behaviour;
* deterministic geometry evidence;
* security-policy verification.

The bundled HERESY-SEC archive is retained as source material and provenance.

BLUE-FORGE may reuse, adapt or extend these mechanisms, but imported behaviour must be independently reviewed before becoming load-bearing BLUE-FORGE policy.

---

# Core Mission

BLUE-FORGE exists to transform:

```text
"Red found a bug."
```

into:

```text
"We identified the violated invariant,
removed or constrained the unsafe state,
proved the original attack class no longer succeeds,
proved legitimate behaviour still works,
and permanently recorded the result."
```

Security progress is therefore measured in **eliminated attack classes and preserved invariants**, not merely closed vulnerability tickets.

---

# Defensive Loop

## 1. Simulated Red

An authorised adversarial system attempts to violate the target's security properties.

Red may:

* generate malicious fixtures;
* exercise sandboxed attack paths;
* test parser boundaries;
* test authentication and authorisation assumptions;
* test privilege separation;
* test supply-chain assumptions;
* test provenance boundaries;
* produce fuzzing or adversarial inputs;
* demonstrate a vulnerability inside an authorised environment.

Red findings are treated as claims until independently captured and verified.

---

## 2. HERESY Intake

HERESY-SEC acts as the evidence boundary.

Its responsibilities include:

* preserving original evidence;
* canonicalising structured inputs;
* binding provenance;
* assigning stable identities;
* recording explicit policy decisions;
* preventing ambiguous evidence from silently becoming trusted evidence;
* generating replayable receipts.

HERESY does not need to agree with Red's interpretation.

It records what happened.

---

## 3. Defensive Analysis

A defensive model, human analyst or approved Blue-Team tool examines the finding.

Potential outputs include:

* root-cause analysis;
* trust-boundary identification;
* mitigation proposals;
* capability reduction;
* parser restriction;
* sandboxing;
* authentication improvements;
* provenance requirements;
* detection rules;
* isolation changes;
* regression fixtures;
* proposed security invariants.

Models may discover, classify, correlate and explain.

**Model agreement is not proof.**

---

## 4. Invariant Derivation

BLUE-FORGE attempts to replace exploit-specific logic with a general security property.

Example:

```text
../../etc/passwd
```

must not become:

```text
DENY_STRING("../../")
```

when the real property is:

```text
RESOLVED_PATH_MUST_REMAIN_WITHIN_AUTHORISED_ROOT
```

Attack payloads become fixtures.

Security invariants become the defence.

---

## 5. Mitigation

The mitigation should make the unsafe state impossible, less authoritative, more observable, or safely contained.

Preferred mitigations include:

* removing unnecessary capabilities;
* validating canonical forms;
* narrowing filesystem authority;
* narrowing process authority;
* narrowing network authority;
* narrowing credential scope;
* enforcing provenance;
* introducing isolation;
* constraining interpreters and parsers;
* eliminating ambiguity;
* applying deterministic policy gates;
* introducing strong authentication;
* separating trusted and untrusted execution.

---

## 6. HERESY Verify

A mitigation is not considered verified merely because the component that proposed it reports success.

HERESY Verify independently evaluates the result.

A verification should establish, where applicable:

```text
original hostile fixture       -> blocked or rendered harmless
attack-class variants          -> blocked or rendered harmless
benign controls                -> expected behaviour preserved
security invariant             -> holds
authority                      -> not expanded
provenance                     -> valid
evidence                       -> complete
replay                         -> exact
reference/optimized result     -> equivalent
```

---

## 7. BLUE_HARDENED

`BLUE_HARDENED` is an earned state.

It must never be inferred merely from:

* absence of alerts;
* model confidence;
* scanner silence;
* a passing patch;
* a timeout;
* incomplete testing;
* Red failing to reproduce something once.

Conceptually:

```text
BLUE_HARDENED :=
    original_attack_neutralized
    AND attack_class_invariant_holds
    AND benign_controls_pass
    AND provenance_valid
    AND verification_complete
    AND replay_exact
    AND authority_not_expanded
    AND reference_equivalence_preserved
```

If a mandatory condition is unknown, the result is not `BLUE_HARDENED`.

---

# Engagement Area Doctrine

BLUE-FORGE does not attempt to defend every possible route equally.

Instead, it shapes system behaviour so that risky or hostile activity is naturally directed toward low-authority, heavily observed and strongly constrained paths.

The defensive analogue of an engagement area is:

```text
            consequential authority
                    |
             heavily protected
                    |
        +-----------+-----------+
        |                       |
        |                       |
 safe legitimate path     suspicious activity
        |                       |
        |                       v
        |              instrumented path
        |                       |
        |                  low authority
        |                       |
        |                       v
        |              HERESY engagement area
        |                       |
        +-----------------------+
```

The safest route should also be the easiest legitimate route.

The riskiest route should be:

* harder to escalate;
* easier to observe;
* lower in authority;
* more deterministic;
* more heavily constrained;
* easier to replay.

---

# Defensive Terrain Effects

BLUE-FORGE borrows the abstract defensive effects:

```text
DISRUPT
TURN
FIX
BLOCK
```

and translates them into safe cyber-defensive mechanisms.

## DISRUPT

Break an attacker's assumed sequence through defensive friction.

Examples:

* canonicalisation;
* re-authentication;
* capability separation;
* resource limits;
* deterministic policy boundaries;
* invalidation of stale authority.

---

## TURN

Redirect risky behaviour toward a safer path.

Examples:

```text
untrusted parser input
        ->
restricted canonical parser

suspicious enumeration
        ->
low-authority instrumented namespace

untrusted operation
        ->
sandboxed capability surface
```

Turning may only reduce or preserve authority.

It must never expand it.

---

## FIX

Restrict freedom of movement after suspicious behaviour has entered a controlled environment.

Examples:

* freeze capability scope;
* freeze filesystem scope;
* freeze permitted destinations;
* bind resource budgets;
* preserve evidence;
* prevent privilege escalation;
* prevent persistence.

Containment may permit continued observation without permitting consequential access.

---

## BLOCK

Hard-deny access to protected boundaries.

Examples:

* production credentials;
* unauthorised persistence;
* privilege escalation;
* unapproved network egress;
* cross-tenant access;
* unauthorised process execution;
* untrusted provenance entering a trusted decision path.

A hard boundary is not subject to model voting.

---

# Core Constitutional Invariants

These invariants are intended to be load-bearing project rules.

## BF-INV-001 — Authority Cannot Silently Expand

```text
effective_authority
    SUBSET-OF
requested_authority INTERSECT policy_authority
```

No model, adapter, geometry result, optimisation or verifier may silently increase authority.

---

## BF-INV-002 — Defensive Decisions Are Monotonic

Within one immutable run:

```text
ALLOW < REVIEW < DENY
```

Automated downstream stages may preserve or tighten a decision.

They may not silently weaken it.

A deliberate policy override starts a new versioned decision context.

---

## BF-INV-003 — No Self-Certification

The component proposing a mitigation cannot be the sole authority declaring that mitigation verified.

```text
proposal != verification evidence
```

---

## BF-INV-004 — Provenance Before Interpretation

Unverified evidence may be inspected.

It may not become load-bearing trusted evidence without the required provenance.

---

## BF-INV-005 — Evidence Is Data

Captured hostile evidence is never automatically executed.

Untrusted evidence must not gain authority through:

* imports;
* shell expansion;
* executable configuration;
* unsafe deserialisation;
* arbitrary constructors;
* symlink traversal;
* implicit command execution.

---

## BF-INV-006 — Replay Failure Is Verification Failure

For a pinned contract:

```text
same captured bytes
+ same policy
+ same engine version
=
same canonical result
```

Unexpected replay divergence invalidates verification.

---

## BF-INV-007 — Benign Behaviour Must Survive

A mitigation is incomplete if it prevents the attack only by unnecessarily destroying required legitimate functionality.

Every appropriate hostile regression should have benign controls.

---

## BF-INV-008 — Unknown Is Not Safe

```text
UNKNOWN      != ALLOW
MALFORMED    != ALLOW
UNSUPPORTED  != ALLOW
INCOMPLETE   != ALLOW
TIMEOUT      != VERIFIED
OOM          != VERIFIED
```

Failure to complete verification cannot manufacture success.

---

## BF-INV-009 — Resource Exhaustion Cannot Produce Verification

Memory, CPU, recursion, decompression, worker, fixture, time or evidence limits must fail explicitly.

Configured safety limits are part of the security boundary.

---

## BF-INV-010 — Optimisation Cannot Reduce the Proof Surface

Performance optimisation may reduce the cost of proving security.

It may not reduce the amount of security being proved.

Optimisation must not silently weaken:

* assertions;
* attack-class coverage;
* provenance checks;
* isolation;
* tolerances;
* deterministic guarantees;
* boundary tests;
* exact replay.

---

## BF-INV-011 — Parallelism Is Semantically Invisible

Worker count and execution order are performance properties.

They must not alter canonical security results.

```text
canonical_result(workers = N)
==
canonical_result(workers = 1)
```

where parallel execution is supported.

---

## BF-INV-012 — Model Agreement Is Not Proof

Multiple models agreeing does not elevate a claim into verified evidence.

```text
model consensus != deterministic verification
```

---

## BF-INV-013 — Semantic Changes Require New Contract Identity

Changes to:

* policy meaning;
* normalisation;
* trust semantics;
* decision ordering;
* receipt meaning;
* invariant semantics;
* verification semantics;

require explicit versioning and new conformance vectors.

Old evidence must never silently acquire new meaning.

---

## BF-INV-014 — No Silent Degradation

If a required verification mechanism is unavailable, BLUE-FORGE records an incomplete verification state.

It does not silently substitute a weaker mechanism and report success.

---

## BF-INV-015 — Deception Outward, Truth Inward

Defensive deception may shape hostile behaviour.

It must never distort evidence presented to defenders.

The system must preserve distinctions such as:

```text
observed   != inferred
inferred   != verified
simulated  != observed
decoy      != production
unknown    != safe
```

---

## BF-INV-016 — Minimum Necessary Intervention

Where multiple mitigations provide equivalent security, prefer the one that alters the smallest necessary:

* authority set;
* resource set;
* user population;
* service scope;
* time window.

Escalation should be evidence-driven.

---

# Self-Reliance

The deterministic defensive nucleus should remain useful when optional external services disappear.

Loss of:

* an AI provider;
* network connectivity;
* an external API;
* a SIEM;
* a remote model;
* an optional integration;

must not convert a security `DENY` into `ALLOW`.

External AI may improve analysis.

It must not be the sole mechanism making the system safe.

---

# Truth in Reporting

BLUE-FORGE treats evidentiary precision as a security property.

Reports should explicitly distinguish:

```text
FACT
OBSERVATION
INFERENCE
MODEL ASSESSMENT
SIMULATION
VERIFIED RESULT
UNRESOLVED CLAIM
```

No presentation layer may silently increase the epistemic strength of evidence.

---

# Precision and Minimum Force

Security response should be proportional to the verified defensive requirement.

Prefer:

```text
revoke one capability
```

over:

```text
disable the entire service
```

when the smaller intervention provides equivalent protection.

Prefer:

```text
isolate one process
```

over:

```text
shutdown every host
```

when containment is sufficient.

Broad containment remains legitimate when evidence supports it.

The principle is not weakness.

It is precision.

---

# Defensive Deception Ethics

BLUE-FORGE may support defensive deception such as:

* decoy services;
* honeypot resources;
* honeytokens;
* canary identifiers;
* synthetic credentials that grant no real authority;
* instrumented namespaces;
* impossible-state tripwires.

These mechanisms must remain defensive.

BLUE-FORGE must not:

* hack back;
* damage remote systems;
* deploy malware to external systems;
* steal unrelated attacker data;
* expose real secrets as bait;
* deliberately endanger unrelated third parties;
* infer real-world identity without sufficient evidence.

The objective is observation, containment and hardening.

Not retaliation.

---

# Parser Doctrine

Security-critical configuration should be intentionally boring.

Expressiveness is an attack surface.

Where possible:

* prefer strict JSON over general-purpose configuration languages;
* reject duplicate keys;
* reject unknown fields;
* reject unsupported encodings;
* reject executable configuration;
* reject recursive structures where recursion is not required;
* reject ambiguous numerical representations;
* reject implicit privilege-bearing defaults.

For YAML/XML compatibility paths, dangerous or unnecessary features should be explicitly disabled or rejected.

Examples include:

```text
YAML aliases / anchors
custom constructors
implicit object tags
duplicate mappings
recursive aliases

XML external entities
DTDs
external references
XInclude
unexpected namespace expansion
```

Canonicalisation must occur before authorisation.

---

# Impossible-State Detection

BLUE-FORGE should increasingly reason about states that should never exist rather than merely recognising known attack strings.

Examples:

```text
unauthenticated identity + administrative capability

read-only worker + process execution

offline worker + unexpected egress

unsigned artifact + trusted provenance status

review-only operation + final ALLOW

parser input without capability X
+ parser output containing capability X
```

An impossible state can be a stronger defensive signal than a signature match.

---

# Security Memory

A successful Red finding should move through:

```text
UNKNOWN
   |
   v
CHARACTERISED
   |
   v
INVARIANT
   |
   v
MITIGATION
   |
   v
VERIFIED
   |
   v
PERMANENT REGRESSION
```

Once an attack class becomes a verified regression, future changes must not silently remove its coverage.

BLUE-FORGE should remember every punch that landed.

---

# Optimisation Doctrine

BLUE-FORGE may incorporate optimisation techniques from the QSOL optimisation programme where they preserve security semantics.

Examples include:

* minimal invariant-preserving fixtures;
* deterministic computation reuse;
* bounded immutable caches;
* elimination of repeated work;
* deterministic early termination;
* bounded deterministic parallelism;
* canonical merge ordering;
* reference-versus-optimised equivalence checks.

The governing rule is:

> **Proof first. Reuse second.**

An optimisation that makes verification faster while weakening a defensive invariant is a regression.

---

# Intended Integration

The long-term architecture may include:

```text
authorised Red systems
        |
        v
capture adapters
        |
        v
HERESY-SEC
        |
        v
QSOL-BLUE-FORGE
        |
        +--> defensive AI analysis
        |
        +--> deterministic policy
        |
        +--> mitigation generation
        |
        +--> regression generation
        |
        v
HERESY VERIFY
        |
        v
BLUE_HARDENED
```

Potential interoperability targets may include:

* SARIF;
* Sigstore;
* in-toto attestations;
* workload identity systems;
* CI systems;
* static-analysis tools;
* fuzzers;
* EDR/SIEM exports;
* agent-harness traces;
* software supply-chain evidence.

No integration may silently grant additional authority.

---

# Proposed Repository Structure

```text
QSOL-BLUE-FORGE/
|
|-- README.md
|-- README4AI.md
|-- AGENTS.md
|-- SECURITY.md
|-- CODE_OF_ETHICS.md
|-- LICENSE
|-- NOTICE.md
|
|-- doctrine/
|   |-- BLUE_TEAM_DOCTRINE.md
|   |-- ENGAGEMENT_AREA.md
|   |-- TRUTH_IN_REPORTING.md
|   `-- MINIMUM_FORCE.md
|
|-- schemas/
|   |-- finding-v1.json
|   |-- invariant-v1.json
|   |-- mitigation-v1.json
|   `-- verification-v1.json
|
|-- blue_forge/
|   |-- intake/
|   |-- invariants/
|   |-- mitigation/
|   |-- verification/
|   `-- replay/
|
|-- fixtures/
|   |-- authentication/
|   |-- filesystem/
|   |-- network/
|   |-- parser/
|   |-- process/
|   |-- provenance/
|   `-- supply_chain/
|
|-- adversarial/
|   `-- simulated/
|
|-- vendor/
|   `-- HERESY-SEC-source.zip
|
`-- tests/
```

The exact layout may evolve while the constitutional invariants remain stable.

---

# AI / Agent Rule

Any implementation agent modifying BLUE-FORGE should treat the following as a hard project rule:

> **A change that makes BLUE-FORGE faster, more capable, more autonomous, more interoperable or more convenient is a regression if it weakens a defensive invariant, expands authority, reduces evidentiary integrity or makes verification less reproducible.**

And:

> **Deception may shape hostile behaviour. It must never distort defensive evidence.**

And:

> **Models may propose. Evidence decides.**

---

# Responsible Use

QSOL-BLUE-FORGE is intended for:

* defensive cybersecurity;
* secure software engineering;
* authorised adversarial simulation;
* vulnerability remediation;
* threat modelling;
* incident analysis;
* security regression testing;
* parser hardening;
* supply-chain verification;
* defensive AI research.

Users are responsible for ensuring that testing is authorised and lawful.

---

# Licence

Recommended licence:

**Mozilla Public License 2.0 (MPL-2.0)**

MPL-2.0 permits commercial and proprietary integration while requiring modifications to MPL-covered source files to remain available under the MPL.

This also aligns with the current HERESY-SEC licensing lineage.

---

# Project Philosophy

```text
SHAPE THE TERRAIN

CONSTRAIN AUTHORITY

MAKE HOSTILE PATHS OBSERVABLE

COLLAPSE AMBIGUITY BEFORE TRUST

DECEPTION OUTWARD

TRUTH INWARD

USE MINIMUM NECESSARY INTERVENTION

NEVER CONFUSE UNKNOWN WITH SAFE

NEVER CONFUSE MODEL CONSENSUS WITH PROOF

NEVER LET OPTIMISATION SHRINK THE PROOF

REPLAY EVERYTHING

REMEMBER EVERY FAILURE

PROVE THE DEFENCE
```

---

## Motto

> **Shape the terrain. Prove the defence.**

QSOL-BLUE-FORGE
