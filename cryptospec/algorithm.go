package cryptospec

import "slices"

// Algorithm is a normalized registry entry describing what a cryptographic
// primitive IS — its class, standard, and parameters. It never describes how
// the system uses the primitive; that is the job of [Use].
type Algorithm struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"` // e.g. "SHA-256", "AES-256-GCM"
	Class     AlgorithmClass `json:"class"`
	Standard  string         `json:"standard,omitempty"` // e.g. "FIPS 180-4"
	KeySize   int            `json:"keySize,omitempty"`  // bits, where applicable
	Lifecycle *Lifecycle     `json:"lifecycle,omitempty"`
}

// AlgorithmClass is the controlled vocabulary for [Algorithm.Class].
type AlgorithmClass string

const (
	ClassHash                 AlgorithmClass = "hash"
	ClassMAC                  AlgorithmClass = "mac"
	ClassSymmetricEncryption  AlgorithmClass = "symmetric-encryption"
	ClassAuthenticatedEnc     AlgorithmClass = "authenticated-encryption"
	ClassAsymmetricEncryption AlgorithmClass = "asymmetric-encryption"
	ClassSignature            AlgorithmClass = "signature"
	ClassKDF                  AlgorithmClass = "kdf"
	ClassPasswordHash         AlgorithmClass = "password-hash"
	ClassKeyAgreement         AlgorithmClass = "key-agreement"
	ClassKEM                  AlgorithmClass = "kem"
	ClassRandomness           AlgorithmClass = "randomness"
)

// AlgorithmClasses is the full set of valid algorithm classes.
var AlgorithmClasses = []AlgorithmClass{
	ClassHash,
	ClassMAC,
	ClassSymmetricEncryption,
	ClassAuthenticatedEnc,
	ClassAsymmetricEncryption,
	ClassSignature,
	ClassKDF,
	ClassPasswordHash,
	ClassKeyAgreement,
	ClassKEM,
	ClassRandomness,
}

// Valid reports whether c is a known algorithm class. The empty string is
// treated as valid (unspecified); the validator enforces presence separately.
func (c AlgorithmClass) Valid() bool {
	return c == "" || slices.Contains(AlgorithmClasses, c)
}
