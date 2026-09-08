package cryptospec

import "slices"

// Verification records the confidence state of a [Claim] and how it was
// reached. It is the surface that keeps AI-inferred facts distinguishable from
// human-attested ones, and it is attached to claims only — never to inventory
// objects — so a fact and its covering claim can never carry disagreeing
// statuses.
type Verification struct {
	Status     VerificationStatus `json:"status"`
	Method     string             `json:"method,omitempty"`     // e.g. "source-analysis"
	VerifiedBy string             `json:"verifiedBy,omitempty"` // person or team
	VerifiedAt string             `json:"verifiedAt,omitempty"` // RFC 3339
}

// VerificationStatus is the state machine controlling how strongly a claim may
// be stated by downstream consumers:
//
//	discovered → inferred → review-required → verified → attested
//
// Not every fact must reach attested. Consumers apply policy over the state
// (e.g. state as fact only when verified or attested). v0.1 records any state;
// transition auditing is left to tooling that writes the spec.
type VerificationStatus string

const (
	VerificationDiscovered     VerificationStatus = "discovered"
	VerificationInferred       VerificationStatus = "inferred"
	VerificationReviewRequired VerificationStatus = "review-required"
	VerificationVerified       VerificationStatus = "verified"
	VerificationAttested       VerificationStatus = "attested"
)

// VerificationStatuses is the full set of valid verification statuses, in
// state-machine order.
var VerificationStatuses = []VerificationStatus{
	VerificationDiscovered,
	VerificationInferred,
	VerificationReviewRequired,
	VerificationVerified,
	VerificationAttested,
}

// Valid reports whether s is a known verification status. Unlike the other
// vocabularies the empty string is NOT valid: every claim must carry a status.
func (s VerificationStatus) Valid() bool {
	return slices.Contains(VerificationStatuses, s)
}

// IsSupported reports whether the status lets a consumer state the claim as a
// current fact (verified or attested). Consumers use this to gate answer
// generation; discovered/inferred/review-required claims must be qualified or
// held for review.
func (s VerificationStatus) IsSupported() bool {
	return s == VerificationVerified || s == VerificationAttested
}
