package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func fixture(name string) string {
	return filepath.Join("..", "examples", "fixtures", name)
}

// runRoot executes the standalone root with args and captures combined output.
func runRoot(args ...string) (string, error) {
	root := NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestValidate_ValidFixture(t *testing.T) {
	out, err := runRoot("validate", fixture("valid/full.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v (out: %s)", err, out)
	}
	if !strings.Contains(out, "ok: no findings") {
		t.Errorf("expected ok message, got: %s", out)
	}
}

func TestValidate_InvalidFixture(t *testing.T) {
	out, err := runRoot("validate", fixture("invalid/capability-leak.json"))
	if !errors.Is(err, errValidationFailed) {
		t.Fatalf("expected errValidationFailed, got %v", err)
	}
	if !strings.Contains(out, "core.capability-containment") {
		t.Errorf("expected containment finding, got: %s", out)
	}
}

func TestValidate_JSONFormat(t *testing.T) {
	out, err := runRoot("validate", "--format", "json", fixture("valid/full.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var findings []map[string]any
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatalf("output is not valid JSON array: %v (out: %s)", err, out)
	}
	if len(findings) != 0 {
		t.Errorf("expected empty findings array, got %d", len(findings))
	}
}

func TestValidate_LoadError(t *testing.T) {
	if _, err := runRoot("validate", fixture("does-not-exist.json")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestReport_ValidFixture(t *testing.T) {
	out, err := runRoot("report", fixture("valid/full.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"System: Example Service", "Implementations (2)", "Uses (2)", "integrity:", "[verified]"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q; got:\n%s", want, out)
		}
	}
}

// TestFamilyMount proves NewCommand mounts under an aggregate root so
// `systemspec crypto validate ...` runs the same code as the standalone CLI.
func TestFamilyMount(t *testing.T) {
	aggregate := &cobra.Command{Use: "systemspec"}
	aggregate.AddCommand(NewCommand())

	var buf bytes.Buffer
	aggregate.SetOut(&buf)
	aggregate.SetErr(&buf)
	aggregate.SetArgs([]string{"crypto", "validate", fixture("valid/full.json")})
	if err := aggregate.Execute(); err != nil {
		t.Fatalf("mounted command failed: %v (out: %s)", err, buf.String())
	}
	if !strings.Contains(buf.String(), "ok: no findings") {
		t.Errorf("expected ok from mounted command, got: %s", buf.String())
	}
}
