package validate

import (
	"fmt"
	"slices"

	"github.com/plexusone/systemspec-crypto/cryptospec"
)

// Validate checks spec against every always-on structural rule and returns all
// findings, most-specific first in document order. A structurally sound spec
// returns a zero-length slice. Use [HasErrors] to gate on error-severity
// findings.
func Validate(spec *cryptospec.Spec) []Finding {
	v := &validator{index: newIndex(spec)}
	v.checkEnvelope(spec)
	v.checkImplementations(spec)
	v.checkAlgorithms(spec)
	v.checkUses(spec)
	v.checkClaims(spec)
	v.checkEvidence(spec)
	return v.findings
}

type validator struct {
	findings []Finding
	index    *index
}

func (v *validator) errorf(rule, path, format string, args ...any) {
	v.findings = append(v.findings, Finding{
		RuleID: rule, Severity: SeverityError, Path: path,
		Message: fmt.Sprintf(format, args...),
	})
}

func (v *validator) warnf(rule, path, format string, args ...any) {
	v.findings = append(v.findings, Finding{
		RuleID: rule, Severity: SeverityWarning, Path: path,
		Message: fmt.Sprintf(format, args...),
	})
}

// index holds the set of IDs by object kind, plus a count of every ID across
// the whole spec for duplicate detection.
type index struct {
	impls  map[string]bool
	algos  map[string]bool
	uses   map[string]bool
	claims map[string]bool
	evid   map[string]bool
	counts map[string]int
}

func newIndex(spec *cryptospec.Spec) *index {
	ix := &index{
		impls:  map[string]bool{},
		algos:  map[string]bool{},
		uses:   map[string]bool{},
		claims: map[string]bool{},
		evid:   map[string]bool{},
		counts: map[string]int{},
	}
	for _, x := range spec.Implementations {
		ix.impls[x.ID] = true
		ix.counts[x.ID]++
	}
	for _, x := range spec.Algorithms {
		ix.algos[x.ID] = true
		ix.counts[x.ID]++
	}
	for _, x := range spec.Uses {
		ix.uses[x.ID] = true
		ix.counts[x.ID]++
	}
	for _, x := range spec.Claims {
		ix.claims[x.ID] = true
		ix.counts[x.ID]++
	}
	for _, x := range spec.Evidence {
		ix.evid[x.ID] = true
		ix.counts[x.ID]++
	}
	return ix
}

func (v *validator) checkEnvelope(spec *cryptospec.Spec) {
	if spec.SpecVersion == "" {
		v.errorf("core.required-field", "specVersion", "specVersion is required")
	}
	if spec.System.ID == "" {
		v.errorf("core.required-field", "system.id", "system.id is required")
	}
}

func (v *validator) checkImplementations(spec *cryptospec.Spec) {
	for i, impl := range spec.Implementations {
		p := fmt.Sprintf("implementations[%d]", i)
		v.requireID(impl.ID, cryptospec.IDPrefixImplementation, p)
		if impl.Name == "" {
			v.errorf("core.required-field", p+".name", "implementation name is required")
		}
		if impl.Type == "" {
			v.errorf("core.required-field", p+".type", "implementation type is required")
		} else if !impl.Type.Valid() {
			v.errorf("core.vocabulary", p+".type", "unknown implementation type %q", impl.Type)
		}
		v.checkLifecycle(impl.Lifecycle, p)
		v.checkEvidenceRefs(impl.EvidenceRefs, p)

		// Capability containment: usedCapabilities must be a subset of
		// capabilities — the core anti-hallucination control. Only enforced
		// when capabilities are enumerated; an implementation whose full
		// capability set is unlisted (e.g. a managed KMS) may still declare
		// what it is used for.
		if len(impl.Capabilities) > 0 {
			for j, uc := range impl.UsedCapabilities {
				if !slices.Contains(impl.Capabilities, uc) {
					v.errorf("core.capability-containment",
						fmt.Sprintf("%s.usedCapabilities[%d]", p, j),
						"usedCapability %q is not declared in capabilities", uc)
				}
			}
		}
		// Usage justification: an implementation that claims used capabilities
		// should be referenced by at least one Use.
		if len(impl.UsedCapabilities) > 0 && !v.implReferencedByUse(spec, impl.ID) {
			v.warnf("core.used-capability-justified", p,
				"implementation %q declares usedCapabilities but no Use references it", impl.ID)
		}
	}
}

func (v *validator) checkAlgorithms(spec *cryptospec.Spec) {
	for i, a := range spec.Algorithms {
		p := fmt.Sprintf("algorithms[%d]", i)
		v.requireID(a.ID, cryptospec.IDPrefixAlgorithm, p)
		if a.Name == "" {
			v.errorf("core.required-field", p+".name", "algorithm name is required")
		}
		if a.Class == "" {
			v.errorf("core.required-field", p+".class", "algorithm class is required")
		} else if !a.Class.Valid() {
			v.errorf("core.vocabulary", p+".class", "unknown algorithm class %q", a.Class)
		}
		v.checkLifecycle(a.Lifecycle, p)
	}
}

func (v *validator) checkUses(spec *cryptospec.Spec) {
	for i, u := range spec.Uses {
		p := fmt.Sprintf("uses[%d]", i)
		v.requireID(u.ID, cryptospec.IDPrefixUse, p)
		if u.Purpose == "" {
			v.errorf("core.required-field", p+".purpose", "use purpose is required")
		} else if !u.Purpose.Valid() {
			v.errorf("core.vocabulary", p+".purpose", "unknown use purpose %q", u.Purpose)
		}
		if u.AlgorithmRef == "" {
			v.errorf("core.required-field", p+".algorithmRef", "use algorithmRef is required")
		} else if !v.index.algos[u.AlgorithmRef] {
			v.errorf("core.reference-resolves", p+".algorithmRef",
				"algorithmRef %q does not resolve to an algorithm", u.AlgorithmRef)
		}
		if u.ImplementationRef != "" && !v.index.impls[u.ImplementationRef] {
			v.errorf("core.reference-resolves", p+".implementationRef",
				"implementationRef %q does not resolve to an implementation", u.ImplementationRef)
		}
		for j, loc := range u.Locations {
			if loc.Type != "" && !loc.Type.Valid() {
				v.errorf("core.vocabulary", fmt.Sprintf("%s.locations[%d].type", p, j),
					"unknown location type %q", loc.Type)
			}
		}
		v.checkLifecycle(u.Lifecycle, p)
		v.checkEvidenceRefs(u.EvidenceRefs, p)
	}
}

func (v *validator) checkClaims(spec *cryptospec.Spec) {
	for i, c := range spec.Claims {
		p := fmt.Sprintf("claims[%d]", i)
		v.requireID(c.ID, cryptospec.IDPrefixClaim, p)
		if c.Statement == "" {
			v.errorf("core.required-field", p+".statement", "claim statement is required")
		}
		if c.Verification.Status == "" {
			v.errorf("core.required-field", p+".verification.status", "verification status is required")
		} else if !c.Verification.Status.Valid() {
			v.errorf("core.vocabulary", p+".verification.status",
				"unknown verification status %q", c.Verification.Status)
		}
		// Evidence expectation: a claim stated as fact must carry evidence.
		if c.Verification.Status.IsSupported() && len(c.EvidenceRefs) == 0 {
			v.errorf("core.evidence-required", p+".evidenceRefs",
				"claim with status %q must carry evidenceRefs", c.Verification.Status)
		}
		for j, ref := range c.TargetRefs {
			if !v.targetResolves(ref) {
				v.errorf("core.reference-resolves", fmt.Sprintf("%s.targetRefs[%d]", p, j),
					"targetRef %q does not resolve to a use, implementation, or algorithm", ref)
			}
		}
		v.checkEvidenceRefs(c.EvidenceRefs, p)
	}
}

func (v *validator) checkEvidence(spec *cryptospec.Spec) {
	for i, e := range spec.Evidence {
		p := fmt.Sprintf("evidence[%d]", i)
		v.requireID(e.ID, cryptospec.IDPrefixEvidence, p)
		if e.Type == "" {
			v.errorf("core.required-field", p+".type", "evidence type is required")
		} else if !e.Type.Valid() {
			v.errorf("core.vocabulary", p+".type", "unknown evidence type %q", e.Type)
		}
		if e.Provenance != nil && !e.Provenance.Method.Valid() {
			v.errorf("core.vocabulary", p+".provenance.method",
				"unknown provenance method %q", e.Provenance.Method)
		}
	}
}

func (v *validator) checkLifecycle(lc *cryptospec.Lifecycle, path string) {
	if lc != nil && !lc.Status.Valid() {
		v.errorf("core.vocabulary", path+".lifecycle.status",
			"unknown lifecycle status %q", lc.Status)
	}
}

func (v *validator) checkEvidenceRefs(refs []string, path string) {
	for j, ref := range refs {
		if !v.index.evid[ref] {
			v.errorf("core.reference-resolves", fmt.Sprintf("%s.evidenceRefs[%d]", path, j),
				"evidenceRef %q does not resolve to an evidence entry", ref)
		}
	}
}

// requireID enforces presence, the type prefix, and uniqueness of an object ID.
func (v *validator) requireID(id, prefix, path string) {
	if id == "" {
		v.errorf("core.required-field", path+".id", "id is required")
		return
	}
	if !cryptospec.HasPrefix(id, prefix) {
		v.errorf("core.id-convention", path+".id",
			"id %q must use the %q prefix", id, prefix)
	}
	if v.index.counts[id] > 1 {
		v.errorf("core.id-unique", path+".id", "id %q is not unique", id)
	}
}

// targetResolves reports whether a claim targetRef points at an existing use,
// implementation, or algorithm.
func (v *validator) targetResolves(ref string) bool {
	return v.index.uses[ref] || v.index.impls[ref] || v.index.algos[ref]
}

func (v *validator) implReferencedByUse(spec *cryptospec.Spec, implID string) bool {
	for _, u := range spec.Uses {
		if u.ImplementationRef == implID {
			return true
		}
	}
	return false
}
