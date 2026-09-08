package cryptospec

import "slices"

// Lifecycle is the shared temporal-state primitive used across the spec family.
// It lets any object say "this is not current" without every object embedding a
// roadmap system. Detailed planning (dates, milestones, dependencies) lives in
// roadmap items referenced by ID, never inline here.
type Lifecycle struct {
	Status     LifecycleStatus `json:"status,omitempty"`
	Introduced string          `json:"introduced,omitempty"` // release/version an object became current
	Deprecated string          `json:"deprecated,omitempty"`
	Removed    string          `json:"removed,omitempty"`
}

// LifecycleStatus is the controlled vocabulary for [Lifecycle.Status], shared
// across the systemspec family.
type LifecycleStatus string

const (
	LifecycleProposed   LifecycleStatus = "proposed"
	LifecyclePlanned    LifecycleStatus = "planned"
	LifecycleInProgress LifecycleStatus = "in-progress"
	LifecycleAvailable  LifecycleStatus = "available"
	LifecycleDeprecated LifecycleStatus = "deprecated"
	LifecycleRetired    LifecycleStatus = "retired"
	LifecycleCancelled  LifecycleStatus = "cancelled"
)

// LifecycleStatuses is the full set of valid lifecycle statuses.
var LifecycleStatuses = []LifecycleStatus{
	LifecycleProposed,
	LifecyclePlanned,
	LifecycleInProgress,
	LifecycleAvailable,
	LifecycleDeprecated,
	LifecycleRetired,
	LifecycleCancelled,
}

// Valid reports whether s is a known lifecycle status. The empty string is
// treated as valid (unspecified); callers requiring a status enforce it
// separately.
func (s LifecycleStatus) Valid() bool {
	return s == "" || slices.Contains(LifecycleStatuses, s)
}
