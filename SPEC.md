# systemspec-crypto Specification v0.1

This document is the normative specification of the systemspec-crypto data
model, describing what is true of the `cryptospec` package's types and the JSON
documents they marshal to and from.

systemspec-crypto describes the cryptography a system uses as **facts and
evidence**, never prose answers. A **Spec** records the cryptographic
**implementations** a system relies on, the **algorithms** they provide, the
**uses** that tie an algorithm to a purpose and place, and the **claims** —
each backed by **evidence** and carrying a **verification** state — asserted
about them. Questionnaire answers, posture findings, and CycloneDX CBOM
documents are computed from this model; none of them are the model. The primary
responsibility of this specification is the semantic model itself.

Two invariants govern the model:

- **Capabilities are not usage.** An implementation separates what it *can* do
  from what the system *does* with it, so no consumer may infer use of a
  cryptographic capability merely because an implementation supports it.
- **Facts carry verification.** Every claim records how strongly it is known,
  so an AI-inferred fact and a human-attested fact remain distinguishable.

Every type in this specification conforms to the PlexusOne static-type profile:
no `oneOf`, `anyOf`, `allOf`, or other JSON Schema composition, and no untyped
or heterogeneous maps. Controlled vocabularies are expressed as string enums and
optional data as explicit named fields, so the canonical Go model and its
generated JSON Schema remain structurally isomorphic. The generated schema is
`schema/crypto.schema.json`; it passes `schemakit lint --property-case
camelCase` with zero findings.

## 1. Spec Document

A **Spec** is the top-level systemspec-crypto document.

```text
specVersion      the spec FORMAT version, e.g. "0.1.0" (§1.1). Required.
metadata         descriptive facts about the document (name, description, timestamps)
system           the system this spec describes (§1.2). Required.
scope            what release/environment/components the spec covers (§1.3)
implementations  the cryptographic implementations the system relies on (§3)
algorithms       the algorithm registry (§4)
uses             how algorithms are used (§5)
claims           asserted, verifiable statements about the above (§6)
evidence         locators supporting claims (§7)
```

### 1.1 Spec version

`specVersion` is the semantic version of the spec **format**, not of the
described system. Documents conforming to this specification carry `"0.1.0"`.
Additive format changes increment the minor version; breaking changes increment
the major version. Tooling MUST accept any document whose major version it
understands.

### 1.2 System identity

```text
id    an opaque, stable identifier for the described system. Required.
name  human-readable system name
```

`SystemRef` is deliberately minimal in v0.1. A structured, family-wide
identifier scheme is a later decision; `id` remains a string so adopting one
never breaks a v0.1 document.

### 1.3 Scope

```text
release      the released version described, e.g. "1.8.2"
environment  e.g. "production"
components   opaque component identifiers owned by the described system
```

Scope lets one system be described at a specific release while another revision
carries different cryptography.

## 2. Identity and References

Object `id` values are lowercase kebab-case slugs carrying a type prefix and
MUST be unique within a Spec:

```text
impl:<slug>        an implementation
algorithm:<slug>   an algorithm
use:<slug>         a use
claim:<slug>       a claim
evidence:<slug>    an evidence entry
```

Reference fields (`algorithmRef`, `implementationRef`, `evidenceRefs`,
`targetRefs`) hold these IDs verbatim and MUST resolve to an object of the
expected type (§9). `roadmapRefs` are the exception: they are opaque external
roadmap-item identifiers and are never resolved by this specification. Detailed
planning MUST NOT be embedded in the Spec; a Spec references planned work by ID
only.

## 3. Implementations

An **Implementation** is a mechanism that provides cryptography. A library is
only one kind.

```text
id                stable identity (§2). Required.
type              classification from the closed vocabulary (§3.1). Required.
name              human-readable name. Required.
version           implementation version, e.g. "go1.26", "v0.56.0"
provider          the providing vendor or platform, where applicable
capabilities      what this implementation CAN do (§3.2)
usedCapabilities  what this system DOES with it (§3.2)
lifecycle         temporal state (§8)
evidenceRefs      supporting evidence IDs (§7)
```

### 3.1 Type taxonomy

```text
library     runtime     operating-system   cloud-provider   kms
hsm         tpm         database           service          hardware
external
```

### 3.2 Capabilities versus used capabilities

`capabilities` and `usedCapabilities` are free-text capability labels (e.g.
`"SHA-256"`, `"AES-256-GCM"`). `capabilities` records what the implementation is
able to do; `usedCapabilities` records what this system actually uses. This
separation is the model's central anti-hallucination control: a scanner or
language model MUST NOT convert "the implementation supports X" into "the system
uses X".

When `capabilities` is non-empty, every entry of `usedCapabilities` MUST also
appear in `capabilities` (§9). When `capabilities` is empty the containment
check does not apply — an implementation whose full capability set is not
enumerated (for example a managed KMS or HSM) may still declare what it is used
for.

## 4. Algorithms

An **Algorithm** is a normalized registry entry describing what a cryptographic
primitive *is*. It never describes how the system uses the primitive; that is a
Use (§5).

```text
id         stable identity (§2). Required.
name       common name, e.g. "SHA-256", "AES-256-GCM". Required.
class      classification from the closed vocabulary (§4.1). Required.
standard   the defining standard, e.g. "FIPS 180-4", "RFC 9106"
keySize    key size in bits, where applicable
lifecycle  temporal state (§8)
```

### 4.1 Class taxonomy

```text
hash                      mac                    symmetric-encryption
authenticated-encryption  asymmetric-encryption  signature
kdf                       password-hash          key-agreement
kem                       randomness
```

## 5. Uses

A **Use** is the heart of the Spec. A cryptographic inventory can record that an
algorithm exists; a Use records that the algorithm is used for a given purpose,
in a given component, with a given configuration, at given locations, backed by
given evidence. One Use answers many differently-worded questions.

```text
id                 stable identity (§2). Required.
purpose            why the algorithm is used, from the closed vocabulary (§5.1). Required.
description        prose description of the use
algorithmRef       the algorithm used; MUST resolve to an Algorithm (§4). Required.
implementationRef  the implementation providing it; MUST resolve to an Implementation (§3)
component          the component identifier where the use occurs
data               classification of the protected data (§5.2)
configuration      configuration parameters (§5.3)
locations          where the use is realized (§5.4)
standards          applicable standards, e.g. ["RFC 9106"]
lifecycle          temporal state (§8)
roadmapRefs        opaque roadmap-item IDs (§2)
evidenceRefs       supporting evidence IDs (§7)
```

### 5.1 Purpose vocabulary

`purpose` is a closed vocabulary. `other` with a `description` is the escape
hatch, so authors never invent near-synonyms.

```text
integrity        confidentiality   authentication   signing
key-derivation   credential-protection   randomness   other
```

### 5.2 Data context

```text
classification  the class of protected data, e.g. "credentials", "customer-data". Required.
description     prose description
```

### 5.3 Configuration

```text
salted      tri-state: unset = not documented, false = explicitly unsalted, true = salted
iterations  work factor / iteration count, where applicable
parameters  a homogeneous string map of additional named parameters
```

`parameters` carries configuration a questionnaire asks about that has no
explicit field — for example an Argon2 memory/parallelism parameter set. It is
a `map[string]string`: a fixed value type, permitted under the static-type
profile, never a heterogeneous or untyped map.

### 5.4 Locations

A **Location** is a locator for where a use is realized, never the evidence
content itself.

```text
type        one of: source | config | deployment | runtime. Required.
repository  the repository, where applicable
path        file or resource path
symbol      the symbol (function, type) within the path
```

## 6. Claims and Verification

A **Claim** is a stated assertion about the system's cryptography, backed by
evidence and carrying a verification state. **Claims are the verification
surface of the Spec.** Inventory objects (implementations, algorithms, uses)
carry `evidenceRefs` only; they do not carry their own verification status.
Consumers and future implementations MUST NOT add per-object verification: a
single claim, which may cover several objects via `targetRefs`, is the one place
a verification state lives, so a fact and its covering claim can never disagree.

```text
id            stable identity (§2). Required.
type          claim category, e.g. "crypto-usage"
statement     the human-readable assertion. Required.
targetRefs    IDs of the uses/implementations/algorithms this claim covers;
              each MUST resolve to one of those object types (§9)
verification  the verification state (§6.1). Required.
evidenceRefs  supporting evidence IDs (§7)
```

### 6.1 Verification state machine

```text
status      one of the states below. Required.
method      how the state was reached, e.g. "source-analysis"
verifiedBy  the person or team, where applicable
verifiedAt  an RFC 3339 timestamp, where applicable
```

`status` is one of, in increasing strength:

```text
discovered → inferred → review-required → verified → attested
```

A consumer generating an external statement SHOULD gate on the state: a
`verified` or `attested` claim may be stated as current fact; `inferred` or
`review-required` claims must be qualified or held for review; `discovered`
claims are supporting evidence only. A claim whose status is `verified` or
`attested` MUST carry at least one `evidenceRef` (§9). v0.1 records any state;
auditing of transitions between states is the responsibility of tooling that
writes the Spec.

## 7. Evidence and Provenance

An **Evidence** entry is a locator for something that supports a claim. The Spec
stores pointers to evidence, never the evidence content.

```text
id          stable identity (§2). Required.
type        classification from the closed vocabulary (§7.1). Required.
repository  the repository, where applicable
path        file or resource path
symbol      the symbol within the path
uri         a URI locator, where applicable
provenance  how the evidence entered the Spec (§7.2)
```

### 7.1 Evidence type taxonomy

```text
source-code       dependency        configuration      iac
runtime-observation   tls-scan      sbom               cbom
cloud-configuration   certificate   test               documentation
human-attestation     vendor-documentation
```

### 7.2 Provenance

```text
method      how the assertion entered the Spec (§7.2.1)
analyzer    the tool or person identifier
analyzedAt  an RFC 3339 timestamp
```

#### 7.2.1 Provenance method

```text
static-analyzer   llm-analyzer   sbom-import
scanner           developer      security-review
```

Provenance keeps "a static analyzer found this", "a language model inferred
this", "a scanner observed this", and "a reviewer recorded this"
distinguishable, which matters for any customer-facing projection of the facts.

## 8. Lifecycle

**Lifecycle** is a shared temporal-state primitive that lets any object say "I
am not current" without embedding a roadmap.

```text
status      one of: proposed | planned | in-progress | available |
                    deprecated | retired | cancelled
introduced  the release/version an object became current
deprecated  the release/version an object was deprecated
removed     the release/version an object was removed
```

Detailed delivery planning (dates, milestones, dependencies) lives in roadmap
items referenced by `roadmapRefs`, never inline.

## 9. Validation

The `validate` package checks a Spec against these always-on structural rules.
An error-severity finding means the Spec is invalid; a warning is advisory. A
valid Spec produces no findings.

```text
required fields     specVersion, system.id, and each object's required fields present
id conventions      every id carries the prefix matching its object type (§2)
id uniqueness       object ids are unique within the Spec
reference resolves  algorithmRef, implementationRef, evidenceRefs, and targetRefs
                    resolve to objects of the expected type
capability containment
                    when an implementation enumerates capabilities, its
                    usedCapabilities are a subset of them (§3.2)
usage justification (warning)
                    an implementation declaring usedCapabilities is referenced by
                    at least one Use
vocabulary          lifecycle status, provenance method, implementation type,
                    algorithm class, use purpose, location type, evidence type,
                    and verification status are within their controlled vocabularies
evidence required   a claim whose verification status is verified or attested
                    carries at least one evidenceRef (§6.1)
```

Cryptographic posture — whether an algorithm is weak, a library outdated, or a
configuration noncompliant — is out of scope for validation. Posture is the
responsibility of a later, policy-driven linter whose findings are ephemeral and
kept separate from the Spec.

## 10. CycloneDX CBOM Export

The `cbom` package projects a Spec into a CycloneDX 1.6 CBOM: the system as an
`application` component, each implementation as a `library`, and each algorithm
as a `cryptographic-asset` whose primitive is mapped from its class. The Spec's
uses drive a dependency graph in which implementations provide algorithms.

CBOM models cryptographic inventory but not usage purpose, configuration,
locations, claims, evidence, or verification state. Export is therefore a
**lossy projection**, and it MUST report the facts it drops rather than losing
them silently. CBOM is an interchange peer, never a replacement for this model.

## 11. Non-goals (v0.1)

- **Answer generation.** Mapping questionnaire wording onto Spec facts and
  writing prose is a downstream consumer, out of scope for this repository.
- **Key, certificate, protocol, and data-protection detail.** Key classes, PKI,
  protocol cryptography, and at-rest/in-transit protection records are reserved
  for a later revision.
- **CBOM import** and round-trip fixtures. v0.1 exports only.
- **Posture linting and policy profiles** (FIPS, PCI, and similar). Reserved for
  a later, policy-driven linter with ephemeral findings.
- **Crypto agility, PQC assessment, RAS characteristics, and disclosure-policy
  projections.** Reserved.
- **Secrets storage.** The model describes key classes and management practices
  only; no field may ever hold key material, secret values, or operational
  credentials. This is a permanent invariant, not a deferred feature.
- **Threat and risk analysis.** Threats, mitigations, and findings belong to
  tooling that consumes this Spec.

## Prior art

The facts-and-evidence model with a verification state machine draws on the same
claim/evidence philosophy used across the PlexusOne spec family. Cryptographic
inventory interchange is delegated to CycloneDX CBOM
(`github.com/CycloneDX/cyclonedx-go`) rather than reinvented; this
specification's differentiation is the usage, configuration, evidence, and
verification layer that CBOM does not model. The Go-first schema workflow
(`invopop/jsonschema` generation linted by `grokify/schemakit`) and the
composable Cobra CLI follow the conventions established by the sibling
`systems-spec` family specifications.
