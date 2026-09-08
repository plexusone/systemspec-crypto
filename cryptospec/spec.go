package cryptospec

// SpecVersion is the semantic version of the spec *format* (not the described
// system) emitted by this package. Additive format changes bump the minor
// version; breaking changes bump the major. Tooling accepts any file whose
// major version it understands.
const SpecVersion = "0.1.0"

// Spec is the root document: a facts-and-evidence description of a system's
// cryptography. The Go structs are the source of truth; the JSON encoding is
// the wire contract.
type Spec struct {
	SpecVersion     string           `json:"specVersion"`
	Metadata        *Metadata        `json:"metadata,omitempty"`
	System          SystemRef        `json:"system"`
	Scope           *Scope           `json:"scope,omitempty"`
	Implementations []Implementation `json:"implementations,omitempty"`
	Algorithms      []Algorithm      `json:"algorithms,omitempty"`
	Uses            []Use            `json:"uses,omitempty"`
	Claims          []Claim          `json:"claims,omitempty"`
	Evidence        []Evidence       `json:"evidence,omitempty"`
}

// Metadata is descriptive, non-identifying information about the spec document.
type Metadata struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"` // RFC 3339
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

// SystemRef identifies the system this spec describes. It is deliberately
// minimal in v0.1 — an opaque ID plus display name. A structured family-wide
// identifier scheme is a later shared-primitives decision; the ID stays a
// string so adopting one never breaks v0.1 files.
type SystemRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Scope states exactly what the spec covers — which release, environment, and
// components. This matters when a released version is described while the main
// branch already contains unreleased crypto changes. Components are opaque
// component identifiers owned by the describing system.
type Scope struct {
	Release     string   `json:"release,omitempty"`
	Environment string   `json:"environment,omitempty"`
	Components  []string `json:"components,omitempty"`
}
