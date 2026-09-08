// Package cbom bridges the cryptospec IR to CycloneDX CBOM (Cryptography Bill
// of Materials). CBOM is an interchange peer, never a replacement: it models
// cryptographic inventory (algorithms, and here the libraries that provide
// them), while the cryptospec IR additionally carries usage purpose,
// configuration, locations, claims, evidence, and verification state.
//
// Because those extra facts have no CBOM representation, [Export] is a lossy
// projection. It returns human-readable notes describing exactly what was
// dropped so the loss is never silent — mirroring the spec's rule that CBOM
// conversions report their lossiness.
package cbom
