package cryptospec

import "testing"

func TestParse_Valid(t *testing.T) {
	data := []byte(`{"specVersion":"0.1.0","system":{"id":"svc"}}`)
	spec, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.System.ID != "svc" {
		t.Errorf("system.id = %q, want svc", spec.System.ID)
	}
}

func TestParse_RejectsUnknownField(t *testing.T) {
	data := []byte(`{"specVersion":"0.1.0","system":{"id":"svc"},"bogus":true}`)
	if _, err := Parse(data); err == nil {
		t.Error("expected error for unknown field, got nil")
	}
}

func TestParse_RejectsMalformed(t *testing.T) {
	if _, err := Parse([]byte(`{not json`)); err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}
