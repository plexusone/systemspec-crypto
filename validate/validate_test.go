package validate

import (
	"testing"

	"github.com/plexusone/systemspec-crypto/cryptospec"
)

// goodSpec returns a structurally valid spec. Tests mutate a copy to trigger
// individual rules.
func goodSpec() *cryptospec.Spec {
	return &cryptospec.Spec{
		SpecVersion: cryptospec.SpecVersion,
		System:      cryptospec.SystemRef{ID: "example-service", Name: "Example Service"},
		Implementations: []cryptospec.Implementation{{
			ID:               "impl:go-stdlib",
			Type:             cryptospec.ImplementationLibrary,
			Name:             "Go standard crypto",
			Capabilities:     []string{"SHA-256", "AES-256-GCM"},
			UsedCapabilities: []string{"SHA-256"},
			EvidenceRefs:     []string{"evidence:go-mod"},
		}},
		Algorithms: []cryptospec.Algorithm{{
			ID: "algorithm:sha-256", Name: "SHA-256", Class: cryptospec.ClassHash,
		}},
		Uses: []cryptospec.Use{{
			ID: "use:artifact-integrity", Purpose: cryptospec.PurposeIntegrity,
			AlgorithmRef: "algorithm:sha-256", ImplementationRef: "impl:go-stdlib",
			Locations:    []cryptospec.Location{{Type: cryptospec.LocationSource, Path: "verify.go"}},
			EvidenceRefs: []string{"evidence:verify-src"},
		}},
		Claims: []cryptospec.Claim{{
			ID: "claim:sha256-integrity", Statement: "SHA-256 verifies artifact integrity.",
			TargetRefs:   []string{"use:artifact-integrity"},
			EvidenceRefs: []string{"evidence:verify-src"},
			Verification: cryptospec.Verification{Status: cryptospec.VerificationVerified},
		}},
		Evidence: []cryptospec.Evidence{
			{ID: "evidence:verify-src", Type: cryptospec.EvidenceSourceCode, Path: "verify.go"},
			{ID: "evidence:go-mod", Type: cryptospec.EvidenceDependency, Path: "go.mod"},
		},
	}
}

func TestValidate_Good(t *testing.T) {
	if findings := Validate(goodSpec()); len(findings) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
	}
}

// hasRule reports whether findings contain a finding with the given rule ID.
func hasRule(findings []Finding, rule string) bool {
	for _, f := range findings {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func TestValidate_Rules(t *testing.T) {
	cases := []struct {
		name    string
		rule    string
		mutate  func(s *cryptospec.Spec)
		wantErr bool // whether HasErrors should be true
	}{
		{"missing-specVersion", "core.required-field", func(s *cryptospec.Spec) {
			s.SpecVersion = ""
		}, true},
		{"missing-system-id", "core.required-field", func(s *cryptospec.Spec) {
			s.System.ID = ""
		}, true},
		{"capability-containment", "core.capability-containment", func(s *cryptospec.Spec) {
			s.Implementations[0].UsedCapabilities = []string{"RSA-4096"} // not in capabilities
		}, true},
		{"unresolved-algorithmRef", "core.reference-resolves", func(s *cryptospec.Spec) {
			s.Uses[0].AlgorithmRef = "algorithm:nope"
		}, true},
		{"unresolved-implementationRef", "core.reference-resolves", func(s *cryptospec.Spec) {
			s.Uses[0].ImplementationRef = "impl:nope"
		}, true},
		{"unresolved-evidenceRef", "core.reference-resolves", func(s *cryptospec.Spec) {
			s.Claims[0].EvidenceRefs = []string{"evidence:nope"}
		}, true},
		{"unresolved-targetRef", "core.reference-resolves", func(s *cryptospec.Spec) {
			s.Claims[0].TargetRefs = []string{"use:nope"}
		}, true},
		{"bad-id-prefix", "core.id-convention", func(s *cryptospec.Spec) {
			s.Algorithms[0].ID = "sha-256" // missing algorithm: prefix
			s.Uses[0].AlgorithmRef = "sha-256"
		}, true},
		{"duplicate-id", "core.id-unique", func(s *cryptospec.Spec) {
			s.Algorithms = append(s.Algorithms, s.Algorithms[0])
		}, true},
		{"unknown-purpose", "core.vocabulary", func(s *cryptospec.Spec) {
			s.Uses[0].Purpose = "encrypt-everything"
		}, true},
		{"unknown-verification", "core.vocabulary", func(s *cryptospec.Spec) {
			s.Claims[0].Verification.Status = "trust-me"
		}, true},
		{"verified-without-evidence", "core.evidence-required", func(s *cryptospec.Spec) {
			s.Claims[0].EvidenceRefs = nil
		}, true},
		{"used-capability-unjustified", "core.used-capability-justified", func(s *cryptospec.Spec) {
			s.Uses[0].ImplementationRef = "" // impl now referenced by no Use
		}, false}, // warning only
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := goodSpec()
			tc.mutate(s)
			findings := Validate(s)
			if !hasRule(findings, tc.rule) {
				t.Errorf("expected rule %q, got findings: %+v", tc.rule, findings)
			}
			if got := HasErrors(findings); got != tc.wantErr {
				t.Errorf("HasErrors() = %v, want %v (findings: %+v)", got, tc.wantErr, findings)
			}
		})
	}
}
