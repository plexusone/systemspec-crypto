package cryptospec

import "slices"

// Implementation is a mechanism that provides cryptography — a library is only
// one kind. The defining anti-hallucination control lives here: Capabilities
// records what the implementation CAN do, while UsedCapabilities records what
// this system actually DOES with it. A scanner or LLM must never turn the
// former into the latter.
type Implementation struct {
	ID               string             `json:"id"`
	Type             ImplementationType `json:"type"`
	Name             string             `json:"name"`
	Version          string             `json:"version,omitempty"`
	Provider         string             `json:"provider,omitempty"`
	Capabilities     []string           `json:"capabilities,omitempty"`     // what it CAN do
	UsedCapabilities []string           `json:"usedCapabilities,omitempty"` // what this system DOES with it
	Lifecycle        *Lifecycle         `json:"lifecycle,omitempty"`
	EvidenceRefs     []string           `json:"evidenceRefs,omitempty"`
}

// ImplementationType is the controlled vocabulary for [Implementation.Type].
type ImplementationType string

const (
	ImplementationLibrary         ImplementationType = "library"
	ImplementationRuntime         ImplementationType = "runtime"
	ImplementationOperatingSystem ImplementationType = "operating-system"
	ImplementationCloudProvider   ImplementationType = "cloud-provider"
	ImplementationKMS             ImplementationType = "kms"
	ImplementationHSM             ImplementationType = "hsm"
	ImplementationTPM             ImplementationType = "tpm"
	ImplementationDatabase        ImplementationType = "database"
	ImplementationService         ImplementationType = "service"
	ImplementationHardware        ImplementationType = "hardware"
	ImplementationExternal        ImplementationType = "external"
)

// ImplementationTypes is the full set of valid implementation types.
var ImplementationTypes = []ImplementationType{
	ImplementationLibrary,
	ImplementationRuntime,
	ImplementationOperatingSystem,
	ImplementationCloudProvider,
	ImplementationKMS,
	ImplementationHSM,
	ImplementationTPM,
	ImplementationDatabase,
	ImplementationService,
	ImplementationHardware,
	ImplementationExternal,
}

// Valid reports whether t is a known implementation type. The empty string is
// treated as valid (unspecified); the validator enforces presence separately.
func (t ImplementationType) Valid() bool {
	return t == "" || slices.Contains(ImplementationTypes, t)
}
