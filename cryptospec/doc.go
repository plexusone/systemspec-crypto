// Package cryptospec defines the core intermediate representation (IR) for
// systemspec-crypto: a Go-first, machine-readable description of the
// cryptography a system uses — what crypto exists, where and why it is used,
// how it is configured, and what evidence supports those claims.
//
// The Go structs in this package are the source of truth. The JSON Schema in
// the sibling schema package is generated from them, and JSON is the wire
// contract. The model holds facts and evidence, never prose answers:
// downstream consumers (answer generators, posture linters, CBOM tooling) are
// projections over these facts and live outside this package.
//
// Two invariants shape the model:
//
//   - Capabilities are not usage. An [Implementation] separates what it CAN do
//     (Capabilities) from what this system DOES with it (UsedCapabilities), so
//     a scanner or LLM can never turn "the library supports X" into "the
//     product uses X".
//   - Facts carry verification. A [Claim] records a [Verification] state
//     (discovered → inferred → review-required → verified → attested) so
//     consumers can distinguish AI-inferred from human-attested facts.
//
// See docs/specs/initiatives/INIT-SYSTEMSPECCRYPTO-001 for the PRD/TRD.
package cryptospec
