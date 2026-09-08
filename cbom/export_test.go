package cbom

import (
	"bytes"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/plexusone/systemspec-crypto/cryptospec"
)

func sampleSpec() *cryptospec.Spec {
	return &cryptospec.Spec{
		SpecVersion: cryptospec.SpecVersion,
		System:      cryptospec.SystemRef{ID: "svc", Name: "Service"},
		Implementations: []cryptospec.Implementation{
			{ID: "impl:go", Type: cryptospec.ImplementationLibrary, Name: "Go crypto", Version: "go1.27"},
		},
		Algorithms: []cryptospec.Algorithm{
			{ID: "algorithm:sha-256", Name: "SHA-256", Class: cryptospec.ClassHash, Standard: "FIPS 180-4"},
			{ID: "algorithm:argon2id", Name: "Argon2id", Class: cryptospec.ClassPasswordHash},
			{ID: "algorithm:ecdsa", Name: "ECDSA", Class: cryptospec.ClassSignature},
		},
		Uses: []cryptospec.Use{
			{ID: "use:tokens", Purpose: cryptospec.PurposeCredentialProtection, AlgorithmRef: "algorithm:sha-256", ImplementationRef: "impl:go"},
		},
		Claims: []cryptospec.Claim{
			{ID: "claim:x", Statement: "s", Verification: cryptospec.Verification{Status: cryptospec.VerificationVerified}, EvidenceRefs: []string{"evidence:e"}},
		},
		Evidence: []cryptospec.Evidence{{ID: "evidence:e", Type: cryptospec.EvidenceSourceCode}},
	}
}

func TestExport_Structure(t *testing.T) {
	bom, notes := Export(sampleSpec())

	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("expected metadata component")
	}
	if bom.Metadata.Component.Type != cdx.ComponentTypeApplication {
		t.Errorf("metadata component type = %q, want application", bom.Metadata.Component.Type)
	}

	var libs, assets int
	primitives := map[string]cdx.CryptoPrimitive{}
	for _, c := range *bom.Components {
		switch c.Type {
		case cdx.ComponentTypeLibrary:
			libs++
		case cdx.ComponentTypeCryptographicAsset:
			assets++
			if c.CryptoProperties == nil || c.CryptoProperties.AlgorithmProperties == nil {
				t.Errorf("crypto asset %q missing algorithm properties", c.BOMRef)
				continue
			}
			primitives[c.BOMRef] = c.CryptoProperties.AlgorithmProperties.Primitive
		}
	}
	if libs != 1 || assets != 3 {
		t.Errorf("components: libs=%d assets=%d, want 1 and 3", libs, assets)
	}
	if primitives["algorithm:sha-256"] != cdx.CryptoPrimitiveHash {
		t.Errorf("sha-256 primitive = %q, want hash", primitives["algorithm:sha-256"])
	}
	if primitives["algorithm:argon2id"] != cdx.CryptoPrimitiveKDF {
		t.Errorf("argon2id primitive = %q, want kdf", primitives["algorithm:argon2id"])
	}
	if primitives["algorithm:ecdsa"] != cdx.CryptoPrimitiveSignature {
		t.Errorf("ecdsa primitive = %q, want signature", primitives["algorithm:ecdsa"])
	}

	// Lossy notes must be surfaced (uses, claims, evidence all present).
	if len(notes) != 3 {
		t.Errorf("expected 3 loss notes, got %d: %v", len(notes), notes)
	}
}

func TestExport_Dependencies(t *testing.T) {
	bom, _ := Export(sampleSpec())
	if bom.Dependencies == nil {
		t.Fatal("expected dependencies")
	}
	var appDeps, implProvides bool
	for _, d := range *bom.Dependencies {
		if d.Ref == "svc" && d.Dependencies != nil {
			appDeps = true
		}
		if d.Ref == "impl:go" && d.Provides != nil {
			for _, p := range *d.Provides {
				if p == "algorithm:sha-256" {
					implProvides = true
				}
			}
		}
	}
	if !appDeps {
		t.Error("expected app to depend on implementations")
	}
	if !implProvides {
		t.Error("expected impl:go to provide algorithm:sha-256")
	}
}

// TestExport_EncodeRoundTrip proves the emitted JSON is a well-formed CycloneDX
// document that decodes back into the library's model with the crypto-asset
// types preserved (the reason Encode bypasses the buggy BOMEncoder converter).
func TestExport_EncodeRoundTrip(t *testing.T) {
	bom, _ := Export(sampleSpec())

	var buf bytes.Buffer
	if err := Encode(&buf, bom); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var got cdx.BOM
	dec := cdx.NewBOMDecoder(&buf, cdx.BOMFileFormatJSON)
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", got.BOMFormat)
	}
	if got.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("specVersion = %v, want 1.6", got.SpecVersion)
	}
	var assets int
	for _, c := range *got.Components {
		if c.Type == cdx.ComponentTypeCryptographicAsset {
			assets++
		}
	}
	if assets != 3 {
		t.Errorf("crypto-asset components after round-trip = %d, want 3", assets)
	}
}
