package cbom

import (
	"encoding/json"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/plexusone/systemspec-crypto/cryptospec"
)

const (
	// cbomSpecVersion is the CycloneDX version this bridge targets. 1.6 is the
	// widely-adopted CBOM version and the earliest with cryptographic-asset
	// components.
	cbomSpecVersion = cdx.SpecVersion1_6
	cbomJSONSchema  = "http://cyclonedx.org/schema/bom-1.6.schema.json"
)

// Export projects spec into a CycloneDX 1.6 CBOM: the system as an application
// component, each implementation as a library, and each algorithm as a
// cryptographic-asset. It also returns notes describing the facts that CBOM
// cannot represent (usage purpose, configuration, locations, claims, evidence,
// verification state), so the lossy conversion is explicit.
func Export(spec *cryptospec.Spec) (*cdx.BOM, []string) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cbomSpecVersion
	bom.JSONSchema = cbomJSONSchema
	bom.Version = 1

	appRef := spec.System.ID
	appName := spec.System.Name
	if appName == "" {
		appName = spec.System.ID
	}
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			Type:   cdx.ComponentTypeApplication,
			BOMRef: appRef,
			Name:   appName,
		},
	}

	components := make([]cdx.Component, 0, len(spec.Implementations)+len(spec.Algorithms))
	for _, impl := range spec.Implementations {
		components = append(components, cdx.Component{
			Type:    cdx.ComponentTypeLibrary,
			BOMRef:  impl.ID,
			Name:    impl.Name,
			Version: impl.Version,
		})
	}
	for _, a := range spec.Algorithms {
		comp := cdx.Component{
			Type:        cdx.ComponentTypeCryptographicAsset,
			BOMRef:      a.ID,
			Name:        a.Name,
			Description: a.Standard,
			CryptoProperties: &cdx.CryptoProperties{
				AssetType:           cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: algorithmProperties(a),
			},
		}
		components = append(components, comp)
	}
	bom.Components = &components

	if deps := buildDependencies(spec, appRef); len(deps) > 0 {
		bom.Dependencies = &deps
	}

	return bom, lossNotes(spec)
}

// Encode writes bom as pretty-printed CycloneDX JSON.
//
// It marshals the struct directly rather than using cyclonedx-go's BOMEncoder.
// That encoder runs a version converter whose supportsComponentType table (as
// of v0.12.0) omits ComponentTypeCryptographicAsset, so it silently rewrites
// every cryptographic-asset component to "application" — corrupting the CBOM —
// even though the library fully models CryptoProperties. Marshalling directly
// preserves the crypto-asset types; SpecVersion and JSONSchema are set by
// Export. Do not switch this back to BOMEncoder until that table is fixed
// upstream.
func Encode(w io.Writer, bom *cdx.BOM) error {
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal CBOM: %w", err)
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write CBOM: %w", err)
	}
	return nil
}

// algorithmProperties maps a cryptospec algorithm to CycloneDX algorithm
// properties: primitive, representative crypto functions, and — for ECDSA — the
// curve names carried in the algorithm name.
func algorithmProperties(a cryptospec.Algorithm) *cdx.CryptoAlgorithmProperties {
	primitive, fns := primitiveForClass(a.Class)
	props := &cdx.CryptoAlgorithmProperties{Primitive: primitive}
	if len(fns) > 0 {
		props.CryptoFunctions = &fns
	}
	return props
}

func primitiveForClass(class cryptospec.AlgorithmClass) (cdx.CryptoPrimitive, []cdx.CryptoFunction) {
	switch class {
	case cryptospec.ClassHash:
		return cdx.CryptoPrimitiveHash, []cdx.CryptoFunction{cdx.CryptoFunctionDigest}
	case cryptospec.ClassMAC:
		return cdx.CryptoPrimitiveMAC, []cdx.CryptoFunction{cdx.CryptoFunctionTag}
	case cryptospec.ClassSymmetricEncryption:
		return cdx.CryptoPrimitiveBlockCipher, []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt}
	case cryptospec.ClassAuthenticatedEnc:
		return cdx.CryptoPrimitiveAE, []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt}
	case cryptospec.ClassAsymmetricEncryption:
		return cdx.CryptoPrimitivePKE, []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt}
	case cryptospec.ClassSignature:
		return cdx.CryptoPrimitiveSignature, []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify}
	case cryptospec.ClassKDF, cryptospec.ClassPasswordHash:
		return cdx.CryptoPrimitiveKDF, []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive}
	case cryptospec.ClassKeyAgreement:
		return cdx.CryptoPrimitiveKeyAgree, nil
	case cryptospec.ClassKEM:
		return cdx.CryptoPrimitiveKEM, []cdx.CryptoFunction{cdx.CryptoFunctionEncapsulate, cdx.CryptoFunctionDecapsulate}
	case cryptospec.ClassRandomness:
		return cdx.CryptoPrimitiveDRBG, []cdx.CryptoFunction{cdx.CryptoFunctionGenerate}
	default:
		return cdx.CryptoPrimitiveOther, nil
	}
}

// buildDependencies expresses the app's dependency on each implementation and,
// via the spec's uses, which algorithms each implementation provides.
func buildDependencies(spec *cryptospec.Spec, appRef string) []cdx.Dependency {
	provides := map[string]map[string]bool{}
	for _, u := range spec.Uses {
		if u.ImplementationRef == "" || u.AlgorithmRef == "" {
			continue
		}
		if provides[u.ImplementationRef] == nil {
			provides[u.ImplementationRef] = map[string]bool{}
		}
		provides[u.ImplementationRef][u.AlgorithmRef] = true
	}

	var deps []cdx.Dependency
	if len(spec.Implementations) > 0 {
		implRefs := make([]string, 0, len(spec.Implementations))
		for _, impl := range spec.Implementations {
			implRefs = append(implRefs, impl.ID)
		}
		deps = append(deps, cdx.Dependency{Ref: appRef, Dependencies: &implRefs})
	}
	for _, impl := range spec.Implementations {
		algs := provides[impl.ID]
		if len(algs) == 0 {
			continue
		}
		// Preserve algorithm order as declared in the spec for stable output.
		var algRefs []string
		for _, a := range spec.Algorithms {
			if algs[a.ID] {
				algRefs = append(algRefs, a.ID)
			}
		}
		deps = append(deps, cdx.Dependency{Ref: impl.ID, Provides: &algRefs})
	}
	return deps
}

// lossNotes enumerates the cryptospec facts that a CBOM cannot carry.
func lossNotes(spec *cryptospec.Spec) []string {
	var notes []string
	if n := len(spec.Uses); n > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d use(s): purpose, component, configuration (salt/iterations/parameters), and source locations are not represented in CBOM", n))
	}
	if n := len(spec.Claims); n > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d claim(s) and their verification state (discovered/inferred/verified/attested) are not represented in CBOM", n))
	}
	if n := len(spec.Evidence); n > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d evidence record(s) are not represented in CBOM", n))
	}
	return notes
}
