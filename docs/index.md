# systemspec-crypto

A Go-first, machine-readable intermediate representation for describing the
cryptography a system uses: **what crypto exists, where and why it is used, how
it is configured and managed, and what evidence supports those claims.**

**The IR is the source of truth, not an LLM.** The spec holds facts and
evidence, never prose answers. Questionnaire responses, posture findings, and
CycloneDX CBOM documents are projections over it; anything the IR cannot support
is "not currently documented," never invented.

## Why systemspec-crypto?

Security questionnaires, audits, and architecture reviews ask endless variations
of the same cryptography questions, and the answers go stale the moment the code
changes. An SBOM/CBOM tells you *that* an algorithm exists somewhere; it does not
tell you *why, where, or how* it is used, or what evidence backs the claim. This
model fills that gap:

- **Capabilities are not usage** — an implementation records what it *can* do
  separately from what the system actually *does* with it, so no consumer can
  infer use of a capability merely because a library supports it.
- **Facts carry verification** — every claim records a state (`discovered →
  inferred → review-required → verified → attested`), so an AI-inferred fact and
  a human-attested one stay distinguishable.
- **Uses are the heart** — one `Use` ties an algorithm to a purpose, component,
  configuration, locations, and evidence, answering many differently-worded
  questions from a single record.
- **Findings are not facts** — cryptographic posture is evaluated by a separate,
  policy-driven linter whose findings are ephemeral; a library can gain a CVE
  tomorrow without the spec changing.

The primary responsibility of this project is the semantic model itself. Answer
generation, posture linting, and CBOM exchange are consumers of the spec, not
the spec. See the [Specification](spec.md) for the full normative model.

## Quick start

```bash
go install github.com/plexusone/systemspec-crypto/cmd/cryptospec@latest

cryptospec validate crypto.json                 # structural validation
cryptospec report   crypto.json                 # human-readable summary
cryptospec cbom export crypto.json -o crypto.cbom.json
```

The same commands mount under a family aggregate CLI as `systemspec crypto …`.
