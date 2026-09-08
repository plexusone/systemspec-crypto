# systemspec-crypto

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/plexusone/systemspec-crypto/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/plexusone/systemspec-crypto/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/plexusone/systemspec-crypto/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/plexusone/systemspec-crypto/actions/workflows/go-lint.yaml
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/plexusone/systemspec-crypto
 [docs-godoc-url]: https://pkg.go.dev/github.com/plexusone/systemspec-crypto
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/plexusone/systemspec-crypto/blob/main/LICENSE

A Go-first, machine-readable intermediate representation (IR) for describing the
cryptography a system uses: **what crypto exists, where and why it is used, how it
is configured and managed, and what evidence supports those claims.**

**The IR is the source of truth, not an LLM.** The spec holds facts and evidence,
never prose answers. Downstream consumers — questionnaire answer generation,
posture linting, CycloneDX CBOM exchange — are projections over these facts. A
generated answer must be supportable by claims and evidence in the IR; anything
the IR cannot support is "not currently documented," never invented.

## Two invariants

- **Capabilities are not usage.** An implementation separates what it *can* do
  (`capabilities`) from what this system actually *does* with it
  (`usedCapabilities`), so a scanner or LLM can never turn "the library supports
  X" into "the product uses X."
- **Facts carry verification.** Every claim records a verification state
  (`discovered → inferred → review-required → verified → attested`), so consumers
  can distinguish an AI-inferred fact from a human-attested one and gate answers
  accordingly.

## Model

A `Spec` describes one system's cryptography with these core objects:

| Object | Answers |
|---|---|
| `implementations` | Which crypto libraries/providers/KMS/HSM are used, and which of their capabilities are actually used |
| `algorithms` | What each primitive *is* (class, standard, key size) |
| `uses` | How a primitive is used — purpose, component, configuration (salt/iterations/parameters), locations, evidence. **The heart of the spec.** |
| `claims` | Stated assertions covering the above, each with a verification state |
| `evidence` | Locators (source, dependency, config, scan, test, attestation) that back claims |

## CLI

```bash
# validate a spec against the structural rules (exits non-zero on errors)
cryptospec validate crypto.json

# print a human-readable internal summary
cryptospec report crypto.json

# project the crypto inventory to a CycloneDX 1.6 CBOM (lossy conversions
# are reported on stderr)
cryptospec cbom export crypto.json --output crypto.cbom.json
```

The same commands mount under a family aggregate CLI as `systemspec crypto ...`.
All capability lives in importable packages (`cryptospec`, `validate`); the CLI is
a thin adapter.

```bash
go install github.com/plexusone/systemspec-crypto/cmd/cryptospec@latest
```

## Go-first schema workflow

Go structs are the source of truth. The JSON Schema is generated from them and
linted for static-type friendliness, guaranteeing the model maps cleanly to Go
and other statically-typed languages:

```bash
go generate ./schema/...                                          # regenerate crypto.schema.json
schemakit lint schema/crypto.schema.json --property-case camelCase
```

## Packages

| Package | Purpose |
|---|---|
| `cryptospec` | Core IR types (source of truth) and the `Parse` loader |
| `validate` | Structural validation rules (referential integrity, capability containment, vocabulary conformance, evidence requirements) |
| `schema` | Generated, embedded JSON Schema |
| `cbom` | CycloneDX CBOM export bridge |
| `cli` | Cobra command constructors (`NewRootCommand`, `NewCommand`) |
| `cmd/cryptospec` | Thin standalone CLI binary |

## Status

v0.1: core inventory model, evidence and verification, schema pipeline,
validation, and CLI, plus early CycloneDX CBOM export. Key management, CBOM
import, and a policy-driven posture linter are planned — see
[`docs/specs/initiatives/INIT-SYSTEMSPECCRYPTO-001`](docs/specs/initiatives/INIT-SYSTEMSPECCRYPTO-001).

## License

MIT — see [LICENSE](LICENSE).
