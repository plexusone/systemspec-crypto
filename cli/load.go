package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/plexusone/systemspec-crypto/cryptospec"
)

// errValidationFailed is returned by commands when a spec has error-severity
// findings. The root command silences it; callers map a non-nil Execute error
// to a non-zero exit code.
var errValidationFailed = errors.New("validation failed")

// loadSpec reads and parses a crypto spec from a file path.
func loadSpec(path string) (*cryptospec.Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	spec, err := cryptospec.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return spec, nil
}
