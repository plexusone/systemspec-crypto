package cryptospec

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestVocabularies_Valid(t *testing.T) {
	// Empty is valid (unspecified) for every vocabulary except verification.
	cases := []struct {
		name  string
		valid bool
		call  func() bool
	}{
		{"lifecycle-known", true, func() bool { return LifecycleAvailable.Valid() }},
		{"lifecycle-empty", true, func() bool { return LifecycleStatus("").Valid() }},
		{"lifecycle-bogus", false, func() bool { return LifecycleStatus("nope").Valid() }},
		{"provenance-known", true, func() bool { return ProvenanceDeveloper.Valid() }},
		{"provenance-bogus", false, func() bool { return ProvenanceMethod("nope").Valid() }},
		{"impl-known", true, func() bool { return ImplementationKMS.Valid() }},
		{"impl-bogus", false, func() bool { return ImplementationType("nope").Valid() }},
		{"class-known", true, func() bool { return ClassAuthenticatedEnc.Valid() }},
		{"class-bogus", false, func() bool { return AlgorithmClass("nope").Valid() }},
		{"purpose-known", true, func() bool { return PurposeIntegrity.Valid() }},
		{"purpose-bogus", false, func() bool { return UsePurpose("nope").Valid() }},
		{"location-known", true, func() bool { return LocationSource.Valid() }},
		{"location-bogus", false, func() bool { return LocationType("nope").Valid() }},
		{"evidence-known", true, func() bool { return EvidenceSourceCode.Valid() }},
		{"evidence-bogus", false, func() bool { return EvidenceType("nope").Valid() }},
		{"verify-known", true, func() bool { return VerificationVerified.Valid() }},
		{"verify-empty", false, func() bool { return VerificationStatus("").Valid() }},
		{"verify-bogus", false, func() bool { return VerificationStatus("nope").Valid() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.call(); got != tc.valid {
				t.Errorf("Valid() = %v, want %v", got, tc.valid)
			}
		})
	}
}

func TestVerificationStatus_IsSupported(t *testing.T) {
	supported := map[VerificationStatus]bool{
		VerificationDiscovered:     false,
		VerificationInferred:       false,
		VerificationReviewRequired: false,
		VerificationVerified:       true,
		VerificationAttested:       true,
	}
	for status, want := range supported {
		if got := status.IsSupported(); got != want {
			t.Errorf("%s.IsSupported() = %v, want %v", status, got, want)
		}
	}
}

func TestHasPrefix(t *testing.T) {
	if !HasPrefix("impl:go-stdlib", IDPrefixImplementation) {
		t.Error("expected impl:go-stdlib to match implementation prefix")
	}
	if HasPrefix("impl:", IDPrefixImplementation) {
		t.Error("bare prefix with empty slug must not match")
	}
	if HasPrefix("use:x", IDPrefixImplementation) {
		t.Error("wrong prefix must not match")
	}
}

func TestSpec_JSONRoundTrip(t *testing.T) {
	salted := true
	in := Spec{
		SpecVersion: SpecVersion,
		System:      SystemRef{ID: "example-service", Name: "Example Service"},
		Implementations: []Implementation{{
			ID:               "impl:go-stdlib",
			Type:             ImplementationLibrary,
			Name:             "Go standard crypto",
			Capabilities:     []string{"SHA-256", "AES-256-GCM"},
			UsedCapabilities: []string{"SHA-256"},
		}},
		Algorithms: []Algorithm{{
			ID: "algorithm:sha-256", Name: "SHA-256", Class: ClassHash, Standard: "FIPS 180-4",
		}},
		Uses: []Use{{
			ID: "use:artifact-integrity", Purpose: PurposeIntegrity, AlgorithmRef: "algorithm:sha-256",
			ImplementationRef: "impl:go-stdlib",
			Configuration:     &UseConfig{Salted: &salted, Iterations: 1},
			Locations:         []Location{{Type: LocationSource, Path: "internal/verify.go"}},
			EvidenceRefs:      []string{"evidence:verify-src"},
		}},
		Claims: []Claim{{
			ID: "claim:sha256-integrity", Statement: "SHA-256 verifies artifact integrity.",
			TargetRefs: []string{"use:artifact-integrity"}, EvidenceRefs: []string{"evidence:verify-src"},
			Verification: Verification{Status: VerificationVerified, Method: "source-analysis"},
		}},
		Evidence: []Evidence{{
			ID: "evidence:verify-src", Type: EvidenceSourceCode, Path: "internal/verify.go",
		}},
	}

	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Spec
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round-trip mismatch:\n in = %+v\nout = %+v", in, out)
	}
}
