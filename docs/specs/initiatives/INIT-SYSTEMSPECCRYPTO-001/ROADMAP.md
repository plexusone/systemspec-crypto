# ROADMAP — systemspec-crypto — Machine-Readable Cryptography Evidence IR (v0.1)

**Initiative:** `INIT-SYSTEMSPECCRYPTO-001`
**Repository:** `github.com/plexusone/systemspec-crypto`

## Phase 1 — Core Inventory Model

**Theme:** Lock the typed core — shared primitives, implementations, algorithms, uses — before any tooling. `capabilities` vs `usedCapabilities` and the `Use` object are the decisions everything downstream depends on.

- [ ] `RMI-SYSTEMSPECCRYPTO-001` Shared primitives: Lifecycle vocabulary (proposed/planned/in-progress/available/deprecated/retired/cancelled), Provenance, ID and reference conventions, roadmapRefs pattern
- [ ] `RMI-SYSTEMSPECCRYPTO-002` Spec envelope: specVersion, metadata, system identity, scope (release, environment, components)
  - Depends on: `RMI-SYSTEMSPECCRYPTO-001`
- [ ] `RMI-SYSTEMSPECCRYPTO-003` Implementations: type vocabulary (library/runtime/os/cloud-provider/kms/hsm/tpm/database/service/hardware/external), capabilities vs usedCapabilities
  - Depends on: `RMI-SYSTEMSPECCRYPTO-001`
- [ ] `RMI-SYSTEMSPECCRYPTO-004` Algorithm registry: class vocabulary (hash/mac/symmetric/authenticated/asymmetric/signature/kdf/password-hash/key-agreement/kem/randomness), standards, parameters
  - Depends on: `RMI-SYSTEMSPECCRYPTO-001`
- [ ] `RMI-SYSTEMSPECCRYPTO-005` Uses: purpose vocabulary, algorithm/implementation refs, component, data classification, configuration (salt/iterations/parameter sets), locations, standards
  - Depends on: `RMI-SYSTEMSPECCRYPTO-003`
  - Depends on: `RMI-SYSTEMSPECCRYPTO-004`

## Phase 2 — Evidence, Verification & Schema Pipeline

**Theme:** Facts without verification states are the hallucination surface this spec exists to eliminate.

- [ ] `RMI-SYSTEMSPECCRYPTO-006` Evidence model: type vocabulary (source-code/dependency/configuration/iac/runtime-observation/tls-scan/sbom/cbom/cloud-configuration/certificate/test/documentation/human-attestation/vendor-documentation), source locators
  - Depends on: `RMI-SYSTEMSPECCRYPTO-001`
- [ ] `RMI-SYSTEMSPECCRYPTO-007` Claims and verification state machine: discovered → inferred → review-required → verified → attested; evidence requirements per state
  - Depends on: `RMI-SYSTEMSPECCRYPTO-006`
- [ ] `RMI-SYSTEMSPECCRYPTO-008` Schema pipeline: generate JSON Schemas from Go types (invopop/jsonschema), schemakit lint camelCase, go:embed, tools.go guard
  - Depends on: `RMI-SYSTEMSPECCRYPTO-002`
  - Depends on: `RMI-SYSTEMSPECCRYPTO-005`
  - Depends on: `RMI-SYSTEMSPECCRYPTO-007`
- [ ] `RMI-SYSTEMSPECCRYPTO-009` Validation rules: referential integrity, usedCapabilities ⊆ capabilities, usage justification, controlled-vocabulary conformance, ID uniqueness, evidence expectations on verified/attested claims
  - Depends on: `RMI-SYSTEMSPECCRYPTO-008`
- [ ] `RMI-SYSTEMSPECCRYPTO-010` Fixture corpus and round-trip tests: valid/invalid examples exercised by Go validator and JSON Schema validation
  - Depends on: `RMI-SYSTEMSPECCRYPTO-008`

## Phase 3 — CLI & Dogfood (closes v0.1)

**Theme:** First payoff — a real application's cryptography fully described, queryable, and evidence-backed.

- [ ] `RMI-SYSTEMSPECCRYPTO-011` CLI foundation: cli package with NewRootCommand/NewCommand constructors, cmd/cryptospec, cryptospec validate with JSON and console output
  - Depends on: `RMI-SYSTEMSPECCRYPTO-009`
- [ ] `RMI-SYSTEMSPECCRYPTO-012` cryptospec report: human-readable internal summary (implementations, algorithms, uses grouped by purpose and component)
  - Depends on: `RMI-SYSTEMSPECCRYPTO-011`
- [ ] `RMI-SYSTEMSPECCRYPTO-013` Dogfood spec: model a real Go application end to end; canonical questionnaire questions answered purely from the IR with evidence traceability
  - Depends on: `RMI-SYSTEMSPECCRYPTO-010`
  - Depends on: `RMI-SYSTEMSPECCRYPTO-011`
- [ ] `RMI-SYSTEMSPECCRYPTO-014` v0.1 release: SPEC.md normative document, README, CI (test/lint/schema-lint/conformance), tag
  - Depends on: `RMI-SYSTEMSPECCRYPTO-012`
  - Depends on: `RMI-SYSTEMSPECCRYPTO-013`

## Phase 4 — Key Management & Protocol Model (v0.2 candidate)

**Theme:** Extend the descriptive model to what enterprise questionnaires ask about constantly — keys, certificates, protocols, protections. Key classes and management practices only; never secret values.

- [ ] `RMI-SYSTEMSPECCRYPTO-015` Key classes: type, algorithm ref, generation, storage, exportability, rotation, access, lifecycle across the key-management lifecycle vocabulary
  - Depends on: `RMI-SYSTEMSPECCRYPTO-014`
- [ ] `RMI-SYSTEMSPECCRYPTO-016` Certificates and PKI classes: purpose, issuer, trust anchors, validity, renewal/rotation/revocation, expiration monitoring
  - Depends on: `RMI-SYSTEMSPECCRYPTO-014`
- [ ] `RMI-SYSTEMSPECCRYPTO-017` Protocol cryptography: TLS and peer protocols with minimum versions, endpoint refs, certificate refs, purposes
  - Depends on: `RMI-SYSTEMSPECCRYPTO-016`
- [ ] `RMI-SYSTEMSPECCRYPTO-018` Protections: data at rest / in transit / in use targets mapped to uses
  - Depends on: `RMI-SYSTEMSPECCRYPTO-015`
- [ ] `RMI-SYSTEMSPECCRYPTO-019` Key-management providers (KMS/HSM/PKI/external) and validation rules for the extended model; dogfood spec extended to full TLS and key-class posture
  - Depends on: `RMI-SYSTEMSPECCRYPTO-017`
  - Depends on: `RMI-SYSTEMSPECCRYPTO-018`

## Phase 5 — CBOM Bridge

**Theme:** CycloneDX CBOM as interchange peer — import/export, never reinvention.

- [ ] `RMI-SYSTEMSPECCRYPTO-020` Artifact references: SBOM/CBOM attachment metadata (type, format, version, URI)
  - Depends on: `RMI-SYSTEMSPECCRYPTO-014`
- [ ] `RMI-SYSTEMSPECCRYPTO-021` CBOM import: CycloneDX cryptographic assets mapped into implementations/algorithms as discovered facts
  - Depends on: `RMI-SYSTEMSPECCRYPTO-020`
- [ ] `RMI-SYSTEMSPECCRYPTO-022` CBOM export: spec inventory projected to CycloneDX CBOM; lossy conversions reported, never silent
  - Depends on: `RMI-SYSTEMSPECCRYPTO-020`
- [ ] `RMI-SYSTEMSPECCRYPTO-023` Mapping fixtures: round-trip corpus against real CycloneDX CBOM examples
  - Depends on: `RMI-SYSTEMSPECCRYPTO-021`
  - Depends on: `RMI-SYSTEMSPECCRYPTO-022`
- [ ] `RMI-SYSTEMSPECCRYPTO-024` cryptospec cbom import/export commands
  - Depends on: `RMI-SYSTEMSPECCRYPTO-023`

## Phase 6 — Posture Linter & Policy

**Theme:** Evaluate the described state against configurable policy; findings are ephemeral artifacts, never spec facts.

- [ ] `RMI-SYSTEMSPECCRYPTO-025` Policy model: prohibited/deprecated algorithms, minimum key sizes, minimum protocol versions, rotation and KDF requirements
  - Depends on: `RMI-SYSTEMSPECCRYPTO-019`
- [ ] `RMI-SYSTEMSPECCRYPTO-026` Findings model: ephemeral finding artifacts with rule ID, target ref, result, severity, observedAt — separate from spec facts
  - Depends on: `RMI-SYSTEMSPECCRYPTO-025`
- [ ] `RMI-SYSTEMSPECCRYPTO-027` Rule engine and core rule classes: capability risk vs configured risk, conditional-pass / secure-configuration-required as first-class results
  - Depends on: `RMI-SYSTEMSPECCRYPTO-026`
- [ ] `RMI-SYSTEMSPECCRYPTO-028` Lint profiles: default-modern plus standards-aligned profiles evaluating the same spec against different expectations
  - Depends on: `RMI-SYSTEMSPECCRYPTO-027`
- [ ] `RMI-SYSTEMSPECCRYPTO-029` cryptospec lint command with profile selection, JSON and console output, CI-gate exit codes
  - Depends on: `RMI-SYSTEMSPECCRYPTO-028`

## Phase 7 — Agility, PQC, RAS & Disclosure (demand-paced)

**Theme:** Grow assessment and projection models from real questionnaire and review needs, not upfront taxonomy.

- [ ] `RMI-SYSTEMSPECCRYPTO-030` Crypto-agility model: algorithm configurability, provider abstraction, rotation-without-redeploy, constraints
  - Depends on: `RMI-SYSTEMSPECCRYPTO-019`
- [ ] `RMI-SYSTEMSPECCRYPTO-031` PQC assessment model: quantum risk per use, migration candidates, standards, roadmap references — assessment over the existing estate, planning stays in roadmap refs
  - Depends on: `RMI-SYSTEMSPECCRYPTO-030`
- [ ] `RMI-SYSTEMSPECCRYPTO-032` Crypto-specific RAS characteristics: KMS/HSM redundancy, key caching and failure behavior, certificate/key rollover, expiry detection, compromise recovery
  - Depends on: `RMI-SYSTEMSPECCRYPTO-019`
- [ ] `RMI-SYSTEMSPECCRYPTO-033` Disclosure-policy model: field-level rules projecting one authoritative spec to internal/auditor/customer/public views
  - Depends on: `RMI-SYSTEMSPECCRYPTO-014`
- [ ] `RMI-SYSTEMSPECCRYPTO-034` cryptospec report --view projections driven by disclosure policy; traceability from projected statements back to claims and evidence
  - Depends on: `RMI-SYSTEMSPECCRYPTO-033`

Out of scope for this initiative: questionnaire answer generation (a downstream consumer of the IR), threat/risk analysis (owned by threat-model tooling that consumes this spec), and secrets storage (permanent invariant, never a phase).
