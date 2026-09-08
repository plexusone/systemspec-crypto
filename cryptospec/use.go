package cryptospec

import "slices"

// Use is the heart of the spec. A CBOM can say SHA-256 exists; a Use says
// SHA-256 is used for artifact integrity, in a given component, with a given
// configuration, at given locations, backed by given evidence. One Use record
// answers many differently-worded questionnaire questions: which algorithm,
// why, where, how it is configured, which implementation, and prove it.
type Use struct {
	ID                string       `json:"id"`
	Purpose           UsePurpose   `json:"purpose"`
	Description       string       `json:"description,omitempty"`
	AlgorithmRef      string       `json:"algorithmRef"`
	ImplementationRef string       `json:"implementationRef,omitempty"`
	Component         string       `json:"component,omitempty"`
	Data              *DataContext `json:"data,omitempty"`
	Configuration     *UseConfig   `json:"configuration,omitempty"`
	Locations         []Location   `json:"locations,omitempty"`
	Standards         []string     `json:"standards,omitempty"`
	Lifecycle         *Lifecycle   `json:"lifecycle,omitempty"`
	RoadmapRefs       []string     `json:"roadmapRefs,omitempty"` // opaque roadmap-item IDs, not resolved here
	EvidenceRefs      []string     `json:"evidenceRefs,omitempty"`
}

// UsePurpose is the closed vocabulary for [Use.Purpose]. PurposeOther plus a
// Description is the escape hatch, so authors never invent near-synonyms.
type UsePurpose string

const (
	PurposeIntegrity            UsePurpose = "integrity"
	PurposeConfidentiality      UsePurpose = "confidentiality"
	PurposeAuthentication       UsePurpose = "authentication"
	PurposeSigning              UsePurpose = "signing"
	PurposeKeyDerivation        UsePurpose = "key-derivation"
	PurposeCredentialProtection UsePurpose = "credential-protection"
	PurposeRandomness           UsePurpose = "randomness"
	PurposeOther                UsePurpose = "other"
)

// UsePurposes is the full set of valid use purposes.
var UsePurposes = []UsePurpose{
	PurposeIntegrity,
	PurposeConfidentiality,
	PurposeAuthentication,
	PurposeSigning,
	PurposeKeyDerivation,
	PurposeCredentialProtection,
	PurposeRandomness,
	PurposeOther,
}

// Valid reports whether p is a known use purpose. The empty string is treated
// as valid (unspecified); the validator enforces presence separately.
func (p UsePurpose) Valid() bool {
	return p == "" || slices.Contains(UsePurposes, p)
}

// UseConfig carries the configuration parameters questionnaires ask about.
// Common parameters get explicit fields; everything else goes in Parameters, a
// homogeneous string map (allowed under the static-type profile). For password
// hashing this is where KDF parameters live.
type UseConfig struct {
	// Salted is tri-state: nil = not documented, false = explicitly unsalted,
	// true = salted. The distinction matters for answer policies.
	Salted     *bool             `json:"salted,omitempty"`
	Iterations int               `json:"iterations,omitempty"` // work factor, where applicable
	Parameters map[string]string `json:"parameters,omitempty"` // e.g. argon2 memory/threads, AES mode
}

// DataContext classifies the data a [Use] protects (e.g. customer-data,
// credentials, software-artifact), so questions about what is encrypted are
// answerable directly.
type DataContext struct {
	Classification string `json:"classification"`
	Description    string `json:"description,omitempty"`
}

// Location points at where a [Use] is realized — source, config, deployment, or
// observed at runtime. It is a locator, never the evidence itself.
type Location struct {
	Type       LocationType `json:"type"`
	Repository string       `json:"repository,omitempty"`
	Path       string       `json:"path,omitempty"`
	Symbol     string       `json:"symbol,omitempty"`
}

// LocationType is the controlled vocabulary for [Location.Type].
type LocationType string

const (
	LocationSource     LocationType = "source"
	LocationConfig     LocationType = "config"
	LocationDeployment LocationType = "deployment"
	LocationRuntime    LocationType = "runtime"
)

// LocationTypes is the full set of valid location types.
var LocationTypes = []LocationType{
	LocationSource,
	LocationConfig,
	LocationDeployment,
	LocationRuntime,
}

// Valid reports whether t is a known location type. The empty string is treated
// as valid (unspecified); the validator enforces presence separately.
func (t LocationType) Valid() bool {
	return t == "" || slices.Contains(LocationTypes, t)
}
