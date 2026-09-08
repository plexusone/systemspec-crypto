// Package validate checks a cryptospec.Spec against the always-on structural
// rules: referential integrity, capability containment, controlled-vocabulary
// conformance, ID conventions, uniqueness, and evidence expectations. It
// reports facts about the document's structure — not cryptographic posture,
// which is the job of a later, policy-driven linter whose findings are
// ephemeral and separate from the spec.
package validate

// Severity classifies how serious a Finding is.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Finding is a single validation result: which rule was checked, where it
// applies, and what went wrong. Only failures are returned by Validate — a
// clean run produces a zero-length slice.
type Finding struct {
	// RuleID identifies the rule that produced this finding, e.g.
	// "core.reference-resolves".
	RuleID string `json:"ruleId"`

	// Severity classifies how serious this finding is.
	Severity Severity `json:"severity"`

	// Message is a human-readable explanation.
	Message string `json:"message"`

	// Path locates the offending element, e.g. "uses[2].algorithmRef".
	Path string `json:"path"`
}

// HasErrors reports whether any finding has error severity.
func HasErrors(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}
