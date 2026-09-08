package cryptospec

import "slices"

// Evidence is a locator for something that supports a claim — a source file, a
// dependency manifest, a config, a scan result, a test, or a human
// attestation. The spec stores pointers to evidence, never the evidence
// content itself.
type Evidence struct {
	ID         string       `json:"id"`
	Type       EvidenceType `json:"type"`
	Repository string       `json:"repository,omitempty"`
	Path       string       `json:"path,omitempty"`
	Symbol     string       `json:"symbol,omitempty"`
	URI        string       `json:"uri,omitempty"`
	Provenance *Provenance  `json:"provenance,omitempty"`
}

// EvidenceType is the controlled vocabulary for [Evidence.Type].
type EvidenceType string

const (
	EvidenceSourceCode         EvidenceType = "source-code"
	EvidenceDependency         EvidenceType = "dependency"
	EvidenceConfiguration      EvidenceType = "configuration"
	EvidenceIaC                EvidenceType = "iac"
	EvidenceRuntimeObservation EvidenceType = "runtime-observation"
	EvidenceTLSScan            EvidenceType = "tls-scan"
	EvidenceSBOM               EvidenceType = "sbom"
	EvidenceCBOM               EvidenceType = "cbom"
	EvidenceCloudConfiguration EvidenceType = "cloud-configuration"
	EvidenceCertificate        EvidenceType = "certificate"
	EvidenceTest               EvidenceType = "test"
	EvidenceDocumentation      EvidenceType = "documentation"
	EvidenceHumanAttestation   EvidenceType = "human-attestation"
	EvidenceVendorDoc          EvidenceType = "vendor-documentation"
)

// EvidenceTypes is the full set of valid evidence types.
var EvidenceTypes = []EvidenceType{
	EvidenceSourceCode,
	EvidenceDependency,
	EvidenceConfiguration,
	EvidenceIaC,
	EvidenceRuntimeObservation,
	EvidenceTLSScan,
	EvidenceSBOM,
	EvidenceCBOM,
	EvidenceCloudConfiguration,
	EvidenceCertificate,
	EvidenceTest,
	EvidenceDocumentation,
	EvidenceHumanAttestation,
	EvidenceVendorDoc,
}

// Valid reports whether t is a known evidence type. The empty string is treated
// as valid (unspecified); the validator enforces presence separately.
func (t EvidenceType) Valid() bool {
	return t == "" || slices.Contains(EvidenceTypes, t)
}
