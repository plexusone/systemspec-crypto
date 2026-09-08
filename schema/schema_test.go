package schema

import (
	"encoding/json"
	"testing"
)

func TestSpecJSON_IsValidJSONSchema(t *testing.T) {
	if len(SpecJSON) == 0 {
		t.Fatal("SpecJSON is empty; run `go generate ./schema/...`")
	}
	var doc map[string]any
	if err := json.Unmarshal(SpecJSON, &doc); err != nil {
		t.Fatalf("SpecJSON is not valid JSON: %v", err)
	}
	if doc["$schema"] == nil {
		t.Error("SpecJSON missing $schema")
	}
	required, _ := doc["required"].([]any)
	if !containsString(required, "specVersion") || !containsString(required, "system") {
		t.Errorf("SpecJSON required = %v, want specVersion and system", required)
	}
}

func containsString(items []any, want string) bool {
	for _, item := range items {
		if s, ok := item.(string); ok && s == want {
			return true
		}
	}
	return false
}
