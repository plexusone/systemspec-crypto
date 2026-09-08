package cryptospec

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Parse decodes a Spec from its JSON encoding. Unknown fields are rejected so
// typos and stale fields surface as errors rather than being silently dropped,
// matching the generated schema's additionalProperties:false stance.
func Parse(data []byte) (*Spec, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Spec
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode crypto spec: %w", err)
	}
	return &s, nil
}
