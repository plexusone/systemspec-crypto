package cryptospec

// Claim is a stated assertion about the system's cryptography, backed by
// evidence and carrying a [Verification] state. Claims are the verification
// surface of the spec: one claim can cover several inventory objects via
// TargetRefs, and inventory objects themselves carry only evidence references,
// never their own verification status.
type Claim struct {
	ID           string       `json:"id"`
	Type         string       `json:"type,omitempty"` // e.g. "crypto-usage"
	Statement    string       `json:"statement"`
	TargetRefs   []string     `json:"targetRefs,omitempty"` // uses/implementations/algorithms covered
	Verification Verification `json:"verification"`
	EvidenceRefs []string     `json:"evidenceRefs,omitempty"`
}
