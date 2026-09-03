# Parser Doctrine

Security-critical parsing should be intentionally boring.

Expressiveness is an attack surface. BLUE-FORGE therefore prefers the smallest data language that can represent the required contract and rejects features that create hidden execution, ambiguous interpretation, unbounded expansion, or parser differentials.

## Core rule

**Canonicalize before authorization.**

No authorization decision should depend on a raw representation when multiple equivalent or ambiguous representations can reach the same semantic value.

A security-sensitive path should follow:

```text
raw bytes
  -> encoding validation
  -> bounded parse
  -> structural validation
  -> canonical representation
  -> policy evaluation
```

Policy must not silently depend on parser-specific side effects.

## Preferred configuration format

Prefer strict JSON for load-bearing machine configuration unless another format is required by an external compatibility contract.

Strict JSON handling should reject:

- duplicate object keys;
- unknown fields where schemas are closed;
- unsupported encodings;
- non-finite numeric values;
- values outside pinned integer or size ranges;
- recursive in-memory structures supplied directly by callers;
- implicit privilege-bearing defaults.

## YAML compatibility

YAML must be treated as a compatibility boundary, not as a trusted superset of JSON.

Where YAML support is unavoidable, reject or disable features not explicitly required, including:

- arbitrary object constructors;
- custom tags;
- executable or language-specific tags;
- recursive aliases;
- alias expansion beyond explicit depth/count budgets;
- duplicate mapping keys;
- merge behavior that can obscure the final authority-bearing value;
- implicit coercions that change security meaning.

Parse under bounded CPU, memory, nesting, alias, and output budgets.

If the parser cannot prove that an unsupported feature was absent, the result is incomplete or denied, not trusted.

## XML compatibility

Where XML support is unavoidable, reject or disable features not explicitly required, including:

- DTD processing;
- external general entities;
- external parameter entities;
- external schema or document retrieval;
- XInclude;
- unbounded entity expansion;
- network resolution;
- implicit access to local files.

Namespaces and canonicalization rules that affect security meaning must be pinned by contract.

## Ambiguity collapse

Normalize security-relevant values before policy evaluation, including as applicable:

- path separators and path resolution;
- Unicode normalization;
- case rules;
- percent or escape encoding;
- numeric representation;
- hostname or identifier normalization;
- repeated or aliased fields.

Canonicalization itself must be deterministic, bounded, and versioned when its semantics change.

## Path rule

Authorization applies to the resolved canonical path, not merely to the user-supplied string.

The invariant should express the intended boundary, for example:

```text
RESOLVED_PATH_MUST_REMAIN_WITHIN_AUTHORIZED_ROOT
```

rather than attempting to blacklist individual traversal spellings.

## Archive and compressed-input rule

Untrusted archives are evidence, not containers to extract automatically.

Inspection code must account for both declared and actually consumed resources and must fail explicitly on unsupported compression methods, semantic flags, malformed metadata, traversal names, overlapping entries, expansion-budget breaches, or incomplete decoding.

Default BLUE-FORGE CI must not extract or execute the archived HERESY source bundle.

## Parser differential rule

If two supported parsers can assign different security meaning to the same bytes, those bytes are not eligible for a load-bearing decision until the ambiguity is eliminated by a pinned canonical contract.

## Failure rule

The following conditions cannot become `ALLOW` or `VERIFIED` merely because parsing stopped:

```text
UNKNOWN
MALFORMED
UNSUPPORTED
INCOMPLETE
BUDGET_EXCEEDED
DECODE_ERROR
```

This doctrine implements BF-INV-005, BF-INV-008, BF-INV-009, BF-INV-013, and BF-INV-014.
