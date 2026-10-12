# PLAN — systemspec-crypto — Machine-Readable Cryptography Evidence IR (v0.1)

**Initiative:** `INIT-SYSTEMSPECCRYPTO-001`

## Sequencing Rationale

The sequencing optimizes for the first real user — our own Go application portfolio — and its nearest payoff: **a complete, evidence-backed cryptographic description of a real application that can answer questionnaire-style questions purely from the IR.** Everything else (CBOM exchange, posture linting, disclosure views) is a consumer of that description and ships after it exists and has been proven on a real system.

Phase 1 locks the core inventory model (shared primitives, implementations, algorithms, uses) because the IR is the hardest part to retrofit — and because `capabilities` vs `usedCapabilities` and the `Use` object are the design decisions everything downstream depends on. Phase 2 adds the claims/evidence/verification layer and the schema pipeline, then validation, because facts without verification states are exactly the hallucination surface this spec exists to eliminate. Phase 3 delivers the CLI, the dogfood spec, and the v0.1 release.

Post-v0.1: Phase 4 extends the descriptive model to keys, certificates, protocols, and data protections — deliberately deferred because those objects are additive and benefit from authoring experience with the core. Phase 5 adds the review, expectation and operating-mode fields that producers of declared facts need, so a declaration cannot outlive its review. Phase 6 builds the CycloneDX CBOM bridge (interchange, never reinvention). Phase 7 builds the posture linter with configurable policy and ephemeral findings. Phase 8 (crypto agility, PQC assessment, RAS, disclosure views) is demand-paced: each model grows from real questionnaire and review needs rather than an empty taxonomy built upfront. Phase 9 adds semantic diff and change impact.

## Phases

1. **Core Inventory Model** — shared primitives (Lifecycle, Provenance, ID/ref conventions), spec envelope with system identity and scope, implementations with capabilities vs usedCapabilities, algorithm registry, uses. Exit: a hand-authored spec for a small real system parses with all core object types populated.
2. **Evidence, Verification & Schema Pipeline** — evidence model, claims with the verification state machine, generated schemas linted by schemakit, embedded, validation rules, fixture corpus with round-trip tests. Exit: schemas lint clean; the validator rejects a `usedCapabilities ⊄ capabilities` fixture and an unresolved-reference fixture with actionable messages.
3. **CLI & Dogfood (closes v0.1)** — `cli` package with root/subcommand constructors, `cryptospec validate` and `cryptospec report`, dogfood spec for a real Go application, v0.1 release with SPEC.md, README, CI, tag. Exit: canonical questionnaire questions answered purely by querying the dogfood IR, every answer traceable to evidence; v0.1 tagged.
4. **Key Management & Protocol Model (v0.2 candidate)** — key classes (never secret values), certificates/PKI, protocol cryptography, data protections, key-management providers with standards conformance (NIST SP 800-57, KMIP, PKCS#11, X9 family). Exit: the dogfood spec describes its TLS posture, key classes, and supported key-management standards end to end.
5. **Review, Expectation & Operating Mode** — review fields on verification (`reviewBy`, `reviewedAt`, `reviewedBy`) with expiry derived at read time, owned expectations at or above the policy floor with a waiver form, operating mode and module validation on implementations, a per-use algorithm profile, and a dated key-state summary convention. Exit: a declared external boundary is expressed as an owned expectation with a review date, goes `review-required` when the date passes, and a below-floor expectation is representable only as a waiver.
6. **CBOM Bridge** — artifact references, CycloneDX CBOM import and export, mapping fixtures. Exit: round-trip against real CycloneDX CBOM examples with lossy conversions reported, never silent.
7. **Posture Linter & Policy** — policy model, ephemeral findings separate from spec facts, rule engine distinguishing capability risk from configured risk (including conditional-pass / secure-configuration-required), lint profiles, `cryptospec lint`. Exit: the dogfood spec lints against two different profiles producing different findings from the same facts.
8. **Agility, PQC, RAS & Disclosure (demand-paced)** — crypto-agility model, PQC assessments over existing uses with roadmap references, crypto-specific RAS characteristics, disclosure-policy views for `report`. Exit: internal and external reports generated from the same spec with field-level disclosure control.
9. **Semantic Diff & Change Impact** — typed change sets over a spec, framework-neutral impact classification, and a diff command. Exit: two versions of the dogfood spec produce a change set and impacts with CI-gate exit codes.

## Milestones

- **M1 (end Phase 2):** a real spec file round-trips through the full pipeline; schemas lint clean; validator catches the canonical invalid fixtures.
- **M2 (end Phase 3, v0.1):** the dogfood application's cryptography is fully described and queryable; questionnaire-style questions answered from the IR alone; v0.1 tagged.
- **M3 (end Phase 6):** CBOM import/export round-trips against CycloneDX examples.
- **M4 (end Phase 7):** `cryptospec lint` produces a defensible posture report for the dogfood spec under multiple profiles.

## Risks & Mitigations

- **Model bloat / trying to be four specs at once.** The spec answers one question (what crypto exists, why/where/how, how managed, what evidence). Threat analysis, operational RAS beyond crypto-specific characteristics, and planning data are explicitly out of scope; every proposed field must serve description or evidence, not analysis output.
- **`Use` authoring burden kills adoption.** We are the first user; the dogfood spec is the authoring-UX test. If modeling a real application feels painful, the schema changes, not the example.
- **Verification states get ignored and everything becomes "verified."** `validate` requires evidence on verified/attested claims; provenance records who/what asserted each fact, keeping AI-inferred and human-attested distinguishable.
- **Spec drifts into a findings store.** Lint findings are ephemeral artifacts produced by a later-phase consumer; the invariant "a library can gain a CVE tomorrow without the spec changing" is enforced by keeping vulnerability/posture output out of the schema.
- **Premature shared-module extraction across the family.** Shared primitives stay local until a second family member needs them; extraction is a recorded later decision, avoiding lockstep versioning.
- **CBOM bridge scope creep.** The bridge maps, it does not model; anything CycloneDX already represents well is imported/exported, not duplicated in the core.

## Conventions

- Commits carry `Refs: RMI-SYSTEMSPECCRYPTO-NNN` trailers; phases are reviewed and executed as units; phase status derives from member RMIs.
- Go-first schema workflow per org conventions: invopop/jsonschema generation, `schemakit lint --property-case camelCase`, `//go:embed`, `tools.go` guard for generator deps.
- Pre-push: `go test ./...`, `golangci-lint run`, coverage badge per global checklist.
