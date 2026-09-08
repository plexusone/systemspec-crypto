# PRD — systemspec-crypto — Machine-Readable Cryptography Evidence IR (v0.1)

**Initiative:** `INIT-SYSTEMSPECCRYPTO-001`
**Home repo:** `github.com/plexusone/systemspec-crypto`
**Status:** proposed

## Problem

Security questionnaires, DDQs, architecture reviews, procurement requests, and audits ask endless slight variations of the same cryptography questions: which hash algorithms and why, what encrypts data at rest and in transit, which libraries are used and how are they configured, how are keys managed, what is the PQC plan. Today the answers live in spreadsheets and prose documents that go stale the moment the code changes. SBOM/CBOM inventories tell you *that* SHA-256 or AES-256-GCM exists somewhere in the dependency tree, but not *why, where, or how* it is used, how the keys behind it are managed, or what evidence supports any of it. And asking an LLM to answer directly from a codebase invites the most dangerous failure mode in this space: "the library supports algorithm X, therefore the product uses X."

## Vision

**The IR is the source of truth, not the LLM.** systemspec-crypto is a vendor-neutral, Go-first JSON intermediate representation that answers one question about a system:

> What cryptography does this system use, where and why does it use it, how is it configured and managed, what is its lifecycle state, and what evidence supports those claims?

The spec holds **facts and evidence, never prose answers**. Downstream consumers — questionnaire answer generation, posture linting, CBOM exchange, architecture review — are projections over those facts and are explicitly out of scope for this repository. A generated answer must be supportable by claims and evidence in the IR; anything the IR cannot support is "not currently documented," never invented.

**Responsibility hierarchy:** the primary responsibility of this project is the semantic model itself. Consumers (answer generators, linters, CBOM tooling) determine what the model must be able to express and prove it works, but they are consumers of the spec, not the spec. When a use case needs something the model can't express, the model changes; when a use case wants something only it needs, that lives in the consumer — never in the core.

## Users

- **Product builders / security engineers (primary):** maintain one authoritative, machine-readable description of a system's cryptography instead of re-answering the same questionnaire every quarter. The first user is us: the maintainers' own Go application portfolio is the dogfood corpus.
- **Security architects and reviewers:** review cryptographic posture as structured facts with evidence, not tribal knowledge; review *changes* to the cryptographic description instead of re-auditing from scratch.
- **Compliance owners:** trace every external statement back to a claim, its evidence, and its verification state.
- **AI analyzers and agents:** propose spec updates from source, dependency, and configuration analysis — as `discovered`/`inferred` facts that humans verify. AI discovers; humans attest.
- **Downstream tooling:** CycloneDX CBOM ecosystems (via a later import/export bridge), posture linters, and answer-generation systems consume the IR.

## Goals

1. **Facts-and-evidence core:** implementations, algorithms, and uses as typed domain objects, with claims, evidence, and provenance attached to every significant assertion.
2. **Anti-hallucination semantics:** an implementation's `capabilities` (what it can do) and `usedCapabilities` (what this system actually does with it) are separate fields — the single most important control in the model. Verification is a first-class state machine (`discovered → inferred → review-required → verified → attested`), so consumers can apply policies like "state as fact only if verified or attested."
3. **Uses are the heart of the spec:** a CBOM can say SHA-256 exists; a `Use` says SHA-256 is used for artifact integrity, in which component, with what configuration (salt, iterations, parameters), at which locations, backed by which evidence. One `Use` record answers many differently-worded questions.
4. **Statically typed friendly:** Go structs are the source of truth; JSON Schema is generated (invopop/jsonschema, linted by schemakit, camelCase properties) and stays within the static-type profile — no `oneOf`/`anyOf`/`allOf`, explicit discriminated fields.
5. **Shared primitives, family-ready:** lifecycle vocabulary (`proposed/planned/in-progress/available/deprecated/retired/cancelled`), evidence, provenance, and reference conventions are defined locally in this module now, designed for later extraction into a shared family root module.
6. **Composable CLI:** library-first packages with a thin Cobra `cli` package exposing both a standalone root command (`cryptospec`) and a subcommand constructor, so a future family-level aggregate CLI can mount it with one import.

## Non-Goals (v0.1)

- **Answer generation** — mapping questionnaire wording onto IR facts and writing prose is a downstream consumer, permanently out of scope for this repo.
- **Key, certificate, protocol, and data-protection detail** — key classes, PKI, TLS configuration, and at-rest/in-transit protection records are the first post-v0.1 phase, not v0.1.
- **CBOM bridge** — CycloneDX CBOM is an import/export bridge in a later phase; it is never reinvented and never becomes the internal model.
- **Posture linter and policy profiles** (FIPS/PCI/NIST-aligned/etc.) — later phase. Lint findings will be ephemeral artifacts evaluated against configurable policy, never stored as spec facts.
- **Crypto agility, rich PQC assessment, RAS characteristics, disclosure-policy projections** — later phases, driven by real modeling demand.
- **Secrets storage** — the spec describes key *classes* and management practices; it must never contain key material, secret values, or operational credentials. This is a permanent invariant, not a phase.
- **Threat and risk analysis** — threats, mitigations, and findings belong to threat-model tooling that consumes this spec.
- **Roadmap/planning fields** — planned work is referenced by roadmap item ID; the spec never embeds its own project-management format.

## Key Product Decisions

- **`capabilities` ≠ `usedCapabilities`.** Modeling what a library supports separately from what the system actually uses prevents scanners and LLMs from converting library capability into product behavior claims.
- **Verification state machine is first-class.** Every claim carries a verification status; "AI inferred this," "a scanner observed this," "an engineer verified this," and "the security team attested this" are different facts and must remain distinguishable.
- **Uses over inventories.** The algorithm registry says what a primitive *is*; the `Use` object says how the system employs it. Design effort concentrates on `Use`.
- **Findings are not facts.** A library can be secure today and have a CVE tomorrow without the spec changing. Posture evaluation output lives outside the spec and expires; the spec describes the system.
- **Key classes, never secrets.** Descriptive metadata only, from day one.
- **CBOM is an interchange peer, not a foundation.** The differentiation of this spec is usage + configuration + management + evidence + verification; inventory interchange delegates to CycloneDX.
- **Shared lifecycle vocabulary across the family:** `proposed | planned | in-progress | available | deprecated | retired | cancelled`, with detailed planning living in roadmap references (`roadmapRefs`), never inline.
- **Library-first, composable Cobra.** Core packages carry all capability; `cmd/cryptospec` is a thin adapter; the `cli` package exposes `NewRootCommand()` and `NewCommand()` so a family aggregate CLI can mount `crypto` as a subcommand.
- **Go-first schema generation** per org conventions: invopop/jsonschema, `schemakit lint --property-case camelCase`, `//go:embed`, `tools.go` guard.

## Success Criteria

- A complete v0.1 spec file fully describes the cryptography of at least one real Go application: its crypto libraries with capabilities vs used capabilities, its algorithms, and every significant use with purpose, configuration, locations, and evidence.
- Canonical questionnaire questions — "Which hash algorithms are used, for what purpose, with what configuration, and where?", "Which cryptographic libraries does the product employ and which of their capabilities are actually used?" — are answerable *purely by querying the IR* of the dogfood spec, with every answer traceable to evidence.
- `cryptospec validate` enforces referential integrity, `usedCapabilities ⊆ capabilities`, and verification-state validity; invalid fixtures fail with actionable messages.
- Generated JSON Schema passes `schemakit lint --property-case camelCase` with zero violations; Go ↔ JSON round-trip fixtures pass in CI.
- The `cli` package mounts cleanly as both a standalone `cryptospec` binary and a subcommand constructor, verified by a test that builds an aggregate root command.
