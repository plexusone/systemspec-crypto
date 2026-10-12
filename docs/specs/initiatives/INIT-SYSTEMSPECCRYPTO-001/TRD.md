# TRD — systemspec-crypto — Machine-Readable Cryptography Evidence IR (v0.1)

**Initiative:** `INIT-SYSTEMSPECCRYPTO-001`

## Architecture Overview

```text
Source / dependencies / config / SBOM / runtime evidence
      │  discovery & analysis (AI or scanner — out of repo scope)
      ▼
Proposed facts (discovered / inferred)
      │  human review
      ▼
cryptospec JSON IR  ◄── Go structs (source of truth)
      │                   │ invopop/jsonschema
      │                   ▼
      │              JSON Schema — schemakit lint --property-case camelCase — //go:embed
      │
      ├──► validate: referential integrity + semantic rules
      ├──► report: human-readable projections
      └──► later phases: CBOM import/export, posture linter, disclosure views
```

The IR represents facts and evidence; answer generation, linting, and CBOM exchange are consumers. JSON Schema validates the wire contract and stays within the static-type profile: no `oneOf`/`anyOf`/`allOf`/`not`, homogeneous arrays, explicit discriminated fields for polymorphism.

## Core Model

```go
type Spec struct {
    SpecVersion     string           `json:"specVersion"`
    Metadata        Metadata         `json:"metadata,omitempty"`
    System          SystemRef        `json:"system"`
    Scope           Scope            `json:"scope,omitempty"`
    Implementations []Implementation `json:"implementations,omitempty"`
    Algorithms      []Algorithm      `json:"algorithms,omitempty"`
    Uses            []Use            `json:"uses,omitempty"`
    Claims          []Claim          `json:"claims,omitempty"`
    Evidence        []Evidence       `json:"evidence,omitempty"`
}
```

### Spec versioning, metadata, and system identity

`specVersion` carries the semver of the **spec format** (not the described system): v0.1 files carry `"0.1.0"`. Additive format changes bump minor; breaking changes bump major. Tooling accepts any file whose major version it understands.

```go
type Metadata struct {
    Name        string `json:"name,omitempty"`
    Description string `json:"description,omitempty"`
    CreatedAt   string `json:"createdAt,omitempty"` // RFC 3339
    UpdatedAt   string `json:"updatedAt,omitempty"`
}

type SystemRef struct {
    ID   string `json:"id"`
    Name string `json:"name,omitempty"`
}
```

`SystemRef` is deliberately minimal in v0.1 — an opaque system ID plus display name. A structured family-wide identifier scheme is a later shared-primitives decision; adopting one must not break v0.1 files (the ID stays a string).

Every spec states exactly what it describes — which system, release, environment, and components. This matters when a customer asks about a released version while the main branch already contains unreleased crypto changes.

```go
type Scope struct {
    Release     string   `json:"release,omitempty"`
    Environment string   `json:"environment,omitempty"`
    Components  []string `json:"components,omitempty"`
}
```

### ID and reference conventions

Object IDs are lowercase kebab-case strings with a type prefix, unique within the spec:

```text
impl:<slug>        e.g. impl:go-stdlib-crypto
algorithm:<slug>   e.g. algorithm:sha-256
use:<slug>         e.g. use:artifact-integrity
claim:<slug>       e.g. claim:sha256-artifact-integrity
evidence:<slug>    e.g. evidence:update-verify-source
```

Reference fields (`algorithmRef`, `implementationRef`, `evidenceRefs`, `targetRefs`) hold these IDs verbatim. `validate` enforces that each ID carries the prefix matching its object type and that every reference points at an object of the expected type. `roadmapRefs` are the exception: they are opaque external identifiers, never resolved by this module.

### Implementation

Libraries are only one implementation mechanism, so the concept is `Implementation` with a type vocabulary:

```text
library | runtime | operating-system | cloud-provider | kms | hsm | tpm |
database | service | hardware | external
```

```go
type Implementation struct {
    ID               string    `json:"id"`
    Type             string    `json:"type"`
    Name             string    `json:"name"`
    Version          string    `json:"version,omitempty"`
    Provider         string    `json:"provider,omitempty"`
    Capabilities     []string  `json:"capabilities,omitempty"`     // what it CAN do
    UsedCapabilities []string  `json:"usedCapabilities,omitempty"` // what this system DOES with it
    Lifecycle        Lifecycle `json:"lifecycle,omitempty"`
    EvidenceRefs     []string  `json:"evidenceRefs,omitempty"`
}
```

**`Capabilities` ≠ `UsedCapabilities`** is the key anti-hallucination control: a scanner or LLM must never turn "the library supports X" into "the product uses X." `validate` enforces `usedCapabilities ⊆ capabilities` and every entry in `usedCapabilities` should be justified by at least one `Use`.

### Algorithm

A normalized registry describing what each primitive *is* — never how the system uses it (that is `Use`).

```go
type Algorithm struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`      // e.g. "SHA-256", "AES-256-GCM"
    Class     string    `json:"class"`
    Standard  string    `json:"standard,omitempty"` // e.g. "FIPS 180-4"
    KeySize   int       `json:"keySize,omitempty"`
    Lifecycle Lifecycle `json:"lifecycle,omitempty"`
}
```

Class vocabulary:

```text
hash | mac | symmetric-encryption | authenticated-encryption |
asymmetric-encryption | signature | kdf | password-hash |
key-agreement | kem | randomness
```

### Use — the heart of the spec

```go
type Use struct {
    ID                string        `json:"id"`
    Purpose           string        `json:"purpose"`
    Description       string        `json:"description,omitempty"`
    AlgorithmRef      string        `json:"algorithmRef"`
    ImplementationRef string        `json:"implementationRef,omitempty"`
    Component         string        `json:"component,omitempty"`
    Data              *DataContext  `json:"data,omitempty"`          // classification of the protected data
    Configuration     *UseConfig    `json:"configuration,omitempty"` // salted, iterations, parameters
    Locations         []Location    `json:"locations,omitempty"`     // source / config / deployment locators
    Standards         []string      `json:"standards,omitempty"`
    Lifecycle         Lifecycle     `json:"lifecycle,omitempty"`
    RoadmapRefs       []string      `json:"roadmapRefs,omitempty"`
    EvidenceRefs      []string      `json:"evidenceRefs,omitempty"`
}
```

One `Use` record answers many differently-worded questions: *which hashes?* (algorithmRef) — *why?* (purpose) — *where?* (component, locations) — *salted?* (configuration) — *which implementation?* (implementationRef) — *prove it* (evidenceRefs).

**`Purpose` is a closed vocabulary** (enforced by `validate`), with `other` + `description` as the escape hatch so authors never invent near-synonyms:

```text
integrity | confidentiality | authentication | signing | key-derivation |
credential-protection | randomness | other
```

Supporting types:

```go
type UseConfig struct {
    Salted     *bool             `json:"salted,omitempty"`     // nil = not documented, false = explicitly unsalted
    Iterations int               `json:"iterations,omitempty"` // work factor where applicable
    Parameters map[string]string `json:"parameters,omitempty"` // named parameter set, e.g. argon2 memory/threads, AES mode
}

type DataContext struct {
    Classification string `json:"classification"` // e.g. customer-data, credentials, software-artifact, telemetry
    Description    string `json:"description,omitempty"`
}

type Location struct {
    Type       string `json:"type"` // source | config | deployment | runtime
    Repository string `json:"repository,omitempty"`
    Path       string `json:"path,omitempty"`
    Symbol     string `json:"symbol,omitempty"`
}
```

`UseConfig` carries the parameters questionnaires ask about; for password hashing this is where KDF parameters live. Common parameters get explicit fields (`salted`, `iterations`); everything else goes in `parameters`, a homogeneous `map[string]string` — allowed under the static-type profile (fixed value type, no `map[string]any`), following the same precedent as the family's earlier specs. The tri-state `*bool` on `salted` distinguishes "explicitly unsalted" from "not documented," which matters for answer policies.

### Claim, Evidence, Verification

**Verification lives on claims only — deliberately.** Inventory objects (implementations, algorithms, uses) carry `evidenceRefs` but no verification status of their own; the claim is the unit that gets verified, and one claim can cover several objects via `targetRefs`. Implementers must not add per-object verification fields: two verification surfaces would let an object's status and its covering claim's status disagree, and consumers would not know which to trust.

Every significant assertion is a claim supported by evidence and carrying a verification state:

```go
type Claim struct {
    ID           string       `json:"id"`
    Type         string       `json:"type"` // e.g. "crypto-usage"
    Statement    string       `json:"statement"`
    TargetRefs   []string     `json:"targetRefs,omitempty"` // uses/implementations/algorithms this claim covers
    Verification Verification `json:"verification"`
    EvidenceRefs []string     `json:"evidenceRefs,omitempty"`
}

type Evidence struct {
    ID         string     `json:"id"`
    Type       string     `json:"type"`
    Repository string     `json:"repository,omitempty"`
    Path       string     `json:"path,omitempty"`
    Symbol     string     `json:"symbol,omitempty"`
    URI        string     `json:"uri,omitempty"`
    Provenance Provenance `json:"provenance,omitempty"`
}

type Verification struct {
    Status     string `json:"status"`
    Method     string `json:"method,omitempty"`
    VerifiedBy string `json:"verifiedBy,omitempty"`
    VerifiedAt string `json:"verifiedAt,omitempty"` // RFC 3339
}
```

Evidence type vocabulary:

```text
source-code | dependency | configuration | iac | runtime-observation |
tls-scan | sbom | cbom | cloud-configuration | certificate | test |
documentation | human-attestation | vendor-documentation
```

**Verification state machine:**

```text
discovered → inferred → review-required → verified → attested
```

Not every fact must reach `attested`, but downstream consumers can apply policies over the state:

```text
verified / attested  → state as fact
inferred             → qualify or request review
discovered           → supporting evidence only
unknown              → "not currently documented"
conflicting          → block and request review
```

`validate` rejects statuses outside the vocabulary; transition ordering is advisory in v0.1 (any state may be recorded), with transition auditing left to tooling that writes the spec.

### Review, expectation and operating mode (planned, v0.2)

These additions serve producers of **declared** facts: statements about
cryptography that the producer does not itself enforce (an edge TLS
configuration, a database connection policy). They keep a declaration from
being read as current fact after it has stopped being reviewed.

**Review fields.** `Verification` gains three optional fields, still on claims
only (see above):

```go
type Verification struct {
    // ...existing fields...
    ReviewBy   string `json:"reviewBy,omitempty"`   // RFC 3339 full-date: deadline for the next review
    ReviewedAt string `json:"reviewedAt,omitempty"` // RFC 3339 timestamp: when a person last reaffirmed the claim
    ReviewedBy string `json:"reviewedBy,omitempty"` // person or team; defaults to VerifiedBy when absent
}
```

- `verifiedAt` is when the status was reached; `reviewedAt` is when a person
  last looked at it and reaffirmed it without changing the status. A
  reaffirmation does not claim re-verification.
- **Expiry is derived, not stored.** A consumer evaluating at time T treats a
  claim whose `reviewBy` is before T as `review-required`, and the stored
  `status` is unchanged. The file does not change meaning as the clock moves,
  and the diff layer does not report the passage of time as a change.
- `validate` rejects a `reviewBy` earlier than `reviewedAt`, and warns on a
  claim past its `reviewBy` as of the evaluation time (`--as-of`, defaulting to
  now).

**Policy, expectation and actual.** Three things are kept distinct:

| Term | Meaning | Where it lives |
|---|---|---|
| **Policy** | The floor. Generic, applies to every system. | The lint policy (Phase 7), never in the spec |
| **Expectation** | What this boundary is declared to be. Specific, with an owner. At or above the floor. | A spec object |
| **Actual** | What was observed. | Evidence (`tls-scan`, `runtime-observation`) |

```text
policy (floor)  <=  expectation (declared target)  <=  actual (observed)
```

- An **Expectation** is an inventory object with an `owner`, the object it
  applies to (a protocol, protection or external boundary), its attributes,
  and `evidenceRefs` pointing at where the real configuration lives. Its
  review date lives on the claim that covers it, not on the object, so the
  single verification surface rule holds.
- **Attributes take two forms.** Ordered attributes (a TLS version, a key
  size) are minimums; the expectation must be greater than or equal to the
  policy minimum. Set-valued attributes (cipher suites, key-exchange groups)
  are allow-sets; the expectation must be a subset of the policy's set.
- A boundary with **no expectation is held to the policy directly**.
- An expectation **below the floor is a waiver**. It must carry a reason and
  an owner, and its covering claim must carry `reviewBy`. The linter reports it
  as a conditional pass until the review date and as a failure after it.
- The three comparisons give three results: actual below policy is a
  **violation**; actual below expectation but above policy is **drift**; an
  expectation below policy is an **exception**.

**Operating mode.** An implementation records `operatingMode` (for example
approved-algorithms-only versus standard) and, for a cryptographic module, its
name, version and validation reference. A claim that a system runs in an
approved-only mode then points at the implementation that states it.

**Algorithm profile.** A use records the named `algorithmProfile` enforced for
it (for example `fips` or `standard`) and the implementation that defines it.
It is deliberately not called `profile` alone: lint profiles (Phase 7) are
evaluation expectations over a whole spec and are a different concept.

**Key state is a summary, not a record per version.** Key classes carry their
class and policy (algorithm, storage, rotation interval). Current state is
carried as a dated claim ("all versions within policy as of T; current version
N") backed by `verified` evidence. The spec holds no row per key version, which
would change with every rotation and drown the diff layer in noise; live state
belongs to the system that manages the keys.

### Shared primitives (local now, family later)

```go
type Lifecycle struct {
    Status     string `json:"status"` // proposed | planned | in-progress | available | deprecated | retired | cancelled
    Introduced string `json:"introduced,omitempty"`
    Deprecated string `json:"deprecated,omitempty"`
    Removed    string `json:"removed,omitempty"`
}

type Provenance struct {
    Method     string `json:"method"` // static-analyzer | llm-analyzer | sbom-import | scanner | developer | security-review
    Analyzer   string `json:"analyzer,omitempty"`
    AnalyzedAt string `json:"analyzedAt,omitempty"`
}
```

`Lifecycle`, `Evidence`, `Provenance`, `Verification`, and ID/reference conventions are shared-primitive candidates for the whole spec family. **They are defined locally in this module for v0.1**; extraction into a shared family root module is a deliberate later decision, deferred until at least a second family member needs them — small shared schemas, no lockstep versioning.

**Planning stays out of the spec.** Objects may carry `roadmapRefs` (opaque roadmap-item IDs); target dates, dependencies, and status of planned work live in roadmap tooling. This prevents the spec from becoming a project-management format and prevents consumers from converting "planned" into "supported."

**Secrets invariant:** the model describes key classes and management practices (post-v0.1 phases); no field may hold key material, secret values, or operational credentials.

**Post-v0.1 model notes.** The Phase 4 key-management model carries explicit standards-conformance fields on key classes and key-management providers (e.g. NIST SP 800-57, KMIP, PKCS#11, X9 family), so the key-management techniques and standards a system supports are answerable from the IR, not prose. The Phase 8 crypto-RAS model spans reliability, availability, and serviceability as separate categories — including serviceability facts like cryptographic audit logging, crypto health checks, and automated renewal — so each category is answerable independently.

## Validation Rules

Shipped in v0.1 as application-level rules over one schema:

```text
referential integrity   → algorithmRef / implementationRef / evidenceRefs / targetRefs resolve
capability containment  → usedCapabilities ⊆ capabilities per implementation,
                          enforced only when capabilities are enumerated (a
                          managed KMS/HSM may declare usage without listing its
                          full capability set)
usage justification     → each usedCapability referenced by at least one Use (warning)
vocabulary conformance  → lifecycle status, verification status, algorithm class,
                          implementation type, evidence type, use purpose, location
                          type within controlled vocabularies
id conventions          → type-prefixed IDs (impl:/algorithm:/use:/claim:/evidence:);
                          references resolve to objects of the expected type
uniqueness              → object IDs unique within the spec
evidence expectation    → verified/attested claims must carry evidenceRefs
```

## CLI

```text
# v0.1
cryptospec validate <crypto.json>
cryptospec report <crypto.json>          # human-readable internal summary

# later phases
cryptospec cbom import|export ...
cryptospec lint <crypto.json> [--profile ...]
cryptospec report <crypto.json> --view internal|auditor|customer|public
```

Library-first: all capability lives in importable packages; `cmd/cryptospec` is a thin adapter. The `cli` package exposes:

```go
cli.NewRootCommand() // standalone: cryptospec ...
cli.NewCommand()     // mountable:  <family-cli> crypto ...
```

so a future family aggregate CLI mounts this module with one import and one `AddCommand()`.

## Repository Layout

```text
systemspec-crypto/
├── cryptospec/     # core types: spec, implementation, algorithm, use, claim, evidence,
│                   # lifecycle, provenance, verification
├── validate/       # referential integrity + semantic rules
├── schema/         # generated *.schema.json + //go:embed + gen/ (go:build ignore) + tools.go
├── cli/            # cobra command constructors (NewRootCommand / NewCommand)
├── cmd/cryptospec/ # thin main
├── examples/       # fixture corpus (valid/invalid) + dogfood spec
└── docs/specs/initiatives/INIT-SYSTEMSPECCRYPTO-001/
```

Later phases add `cbom/`, `lint/`, `policy/`, `report/`.

## Schema Pipeline, Conformance & Testing

- Go structs → invopop/jsonschema → `schema/*.schema.json`, linted by `schemakit lint --property-case camelCase` in CI, embedded via `//go:embed`.
- `tools.go` with `//go:build tools` blank imports so `go mod tidy` keeps the generator's deps (standard `gen/main.go` pattern).
- Fixture corpus (`examples/fixtures/{valid,invalid}`) exercised by both the Go validator and JSON Schema validation; round-trip test Go → JSON → schema-validate → Go with semantic equality.
- The dogfood spec (a real Go application, modeled end to end) doubles as the authoring-UX test: if modeling a real system feels painful, the schema changes, not the example.

## Dependencies

Cobra (CLI), `invopop/jsonschema` (schema generation), `grokify/schemakit` (lint, dev/CI tool). Verify latest versions before adding. No dependency on CycloneDX tooling until the CBOM bridge phase; no runtime dependency on other family specs — references are by ID/URI.
