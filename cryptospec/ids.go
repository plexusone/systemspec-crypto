package cryptospec

import "strings"

// Object IDs are lowercase kebab-case slugs with a type prefix, unique within a
// [Spec]. Reference fields hold these IDs verbatim; the validator checks that
// every ID carries the prefix matching its object type and that references
// resolve to an object of the expected type.
const (
	IDPrefixImplementation = "impl:"
	IDPrefixAlgorithm      = "algorithm:"
	IDPrefixUse            = "use:"
	IDPrefixClaim          = "claim:"
	IDPrefixEvidence       = "evidence:"
)

// HasPrefix reports whether id starts with the given type prefix and has a
// non-empty slug after it.
func HasPrefix(id, prefix string) bool {
	return strings.HasPrefix(id, prefix) && len(id) > len(prefix)
}
