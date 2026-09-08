package schema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/plexusone/systemspec-crypto/cryptospec"
	"github.com/plexusone/systemspec-crypto/validate"
)

func compileSpecSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	var schemaDoc any
	if err := json.Unmarshal(SpecJSON, &schemaDoc); err != nil {
		t.Fatalf("unmarshal embedded schema: %v", err)
	}
	if err := compiler.AddResource("crypto.schema.json", schemaDoc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	compiled, err := compiler.Compile("crypto.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return compiled
}

func globFixtures(t *testing.T, dir string) []string {
	t.Helper()
	fixtures, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures found under %s", dir)
	}
	return fixtures
}

// TestValidFixtures proves every file under examples/fixtures/valid passes the
// full conformance chain: it validates against the generated JSON Schema,
// unmarshals cleanly into cryptospec.Spec, produces no error-severity findings
// from the Go validator, and round-trips Go -> JSON -> schema without loss.
func TestValidFixtures(t *testing.T) {
	compiled := compileSpecSchema(t)
	for _, path := range globFixtures(t, filepath.Join("..", "examples", "fixtures", "valid")) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			var doc any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("fixture is not valid JSON: %v", err)
			}
			if err := compiled.Validate(doc); err != nil {
				t.Fatalf("fixture does not validate against crypto.schema.json: %v", err)
			}

			var spec cryptospec.Spec
			if err := json.Unmarshal(data, &spec); err != nil {
				t.Fatalf("fixture does not unmarshal into cryptospec.Spec: %v", err)
			}
			if spec.SpecVersion == "" {
				t.Error("expected non-empty specVersion after unmarshal")
			}
			for _, f := range validate.Validate(&spec) {
				if f.Severity == validate.SeverityError {
					t.Errorf("unexpected validation error: %s %s: %s", f.RuleID, f.Path, f.Message)
				}
			}

			// Round-trip: re-marshal the decoded Spec and re-validate against
			// the schema, proving the Go model emits schema-conformant JSON.
			out, err := json.Marshal(&spec)
			if err != nil {
				t.Fatalf("re-marshal spec: %v", err)
			}
			var rt any
			if err := json.Unmarshal(out, &rt); err != nil {
				t.Fatalf("re-unmarshal: %v", err)
			}
			if err := compiled.Validate(rt); err != nil {
				t.Fatalf("round-tripped spec does not validate against schema: %v", err)
			}
		})
	}
}

// TestDogfoodSpecs proves the real dogfood specs under examples/dogfood
// validate against the JSON Schema, unmarshal cleanly, and produce no
// error-severity findings — the bar any real, hand-authored spec must meet.
func TestDogfoodSpecs(t *testing.T) {
	compiled := compileSpecSchema(t)
	for _, path := range globFixtures(t, filepath.Join("..", "examples", "dogfood")) {
		// Dogfood directories also hold generated CBOM artifacts, which are
		// CycloneDX documents, not cryptospec.Spec files — skip them.
		if strings.HasSuffix(path, ".cbom.json") {
			continue
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read dogfood spec: %v", err)
			}

			var doc any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("dogfood spec is not valid JSON: %v", err)
			}
			if err := compiled.Validate(doc); err != nil {
				t.Fatalf("dogfood spec does not validate against crypto.schema.json: %v", err)
			}

			spec, err := cryptospec.Parse(data)
			if err != nil {
				t.Fatalf("dogfood spec does not parse: %v", err)
			}
			if len(spec.Uses) == 0 {
				t.Error("expected at least one use in a dogfood spec")
			}
			for _, f := range validate.Validate(spec) {
				if f.Severity == validate.SeverityError {
					t.Errorf("validation error: %s %s: %s", f.RuleID, f.Path, f.Message)
				}
			}
		})
	}
}

// TestInvalidFixtures proves every file under examples/fixtures/invalid is
// rejected by at least one layer: JSON Schema catches structural violations
// (missing required fields, wrong types), and the Go validator catches
// semantic ones (unresolved references, capability leaks, missing evidence)
// that JSON Schema cannot express.
func TestInvalidFixtures(t *testing.T) {
	compiled := compileSpecSchema(t)
	for _, path := range globFixtures(t, filepath.Join("..", "examples", "fixtures", "invalid")) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			var doc any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("fixture is not valid JSON: %v", err)
			}
			schemaRejected := compiled.Validate(doc) != nil

			var spec cryptospec.Spec
			validatorRejected := false
			if err := json.Unmarshal(data, &spec); err == nil {
				validatorRejected = validate.HasErrors(validate.Validate(&spec))
			}

			if !schemaRejected && !validatorRejected {
				t.Fatal("expected fixture to be rejected by schema or validator, but both accepted it")
			}
		})
	}
}
