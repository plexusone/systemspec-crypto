package cryptospec

import "slices"

// Provenance records how an assertion entered the spec — the mechanism and,
// optionally, which analyzer and when. It keeps "AI inferred this", "a scanner
// observed this", and "an engineer recorded this" distinguishable, which
// matters for any customer-facing projection of the facts.
type Provenance struct {
	Method     ProvenanceMethod `json:"method,omitempty"`
	Analyzer   string           `json:"analyzer,omitempty"`   // tool or person identifier
	AnalyzedAt string           `json:"analyzedAt,omitempty"` // RFC 3339
}

// ProvenanceMethod is the controlled vocabulary for [Provenance.Method].
type ProvenanceMethod string

const (
	ProvenanceStaticAnalyzer ProvenanceMethod = "static-analyzer"
	ProvenanceLLMAnalyzer    ProvenanceMethod = "llm-analyzer"
	ProvenanceSBOMImport     ProvenanceMethod = "sbom-import"
	ProvenanceScanner        ProvenanceMethod = "scanner"
	ProvenanceDeveloper      ProvenanceMethod = "developer"
	ProvenanceSecurityReview ProvenanceMethod = "security-review"
)

// ProvenanceMethods is the full set of valid provenance methods.
var ProvenanceMethods = []ProvenanceMethod{
	ProvenanceStaticAnalyzer,
	ProvenanceLLMAnalyzer,
	ProvenanceSBOMImport,
	ProvenanceScanner,
	ProvenanceDeveloper,
	ProvenanceSecurityReview,
}

// Valid reports whether m is a known provenance method. The empty string is
// treated as valid (unspecified).
func (m ProvenanceMethod) Valid() bool {
	return m == "" || slices.Contains(ProvenanceMethods, m)
}
