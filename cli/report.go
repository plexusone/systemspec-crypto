package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemspec-crypto/cryptospec"
)

func newReportCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "report <crypto.json>",
		Short: "Print a human-readable summary of a crypto spec",
		Long: `Report summarizes a crypto spec: implementations (capabilities vs used),
algorithms, uses grouped by purpose, and claims with their verification state.
This is the internal view; disclosure-controlled external views are a later
phase.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := loadSpec(args[0])
			if err != nil {
				return err
			}
			switch format {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(spec)
			case "text", "":
				return renderReport(cmd.OutOrStdout(), spec)
			default:
				return fmt.Errorf("unknown format %q (want text or json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func renderReport(w io.Writer, spec *cryptospec.Spec) error {
	ew := &errWriter{w: w}

	name := spec.System.Name
	if name == "" {
		name = spec.System.ID
	}
	ew.printf("System: %s (%s)\n", name, spec.System.ID)
	if spec.Scope != nil {
		var parts []string
		if spec.Scope.Release != "" {
			parts = append(parts, "release "+spec.Scope.Release)
		}
		if spec.Scope.Environment != "" {
			parts = append(parts, "environment "+spec.Scope.Environment)
		}
		if len(parts) > 0 {
			ew.printf("Scope: %s\n", strings.Join(parts, ", "))
		}
	}

	algoName := make(map[string]string, len(spec.Algorithms))
	for _, a := range spec.Algorithms {
		algoName[a.ID] = a.Name
	}

	ew.printf("\nImplementations (%d):\n", len(spec.Implementations))
	for _, impl := range spec.Implementations {
		desc := string(impl.Type)
		if impl.Provider != "" {
			desc += ", " + impl.Provider
		}
		ew.printf("  %s  %s (%s)\n", impl.ID, impl.Name, desc)
		if len(impl.Capabilities) > 0 {
			ew.printf("    capabilities: %s\n", strings.Join(impl.Capabilities, ", "))
		}
		if len(impl.UsedCapabilities) > 0 {
			ew.printf("    used:         %s\n", strings.Join(impl.UsedCapabilities, ", "))
		}
	}

	ew.printf("\nAlgorithms (%d):\n", len(spec.Algorithms))
	for _, a := range spec.Algorithms {
		line := fmt.Sprintf("  %s  %s  %s", a.ID, a.Name, a.Class)
		if a.Standard != "" {
			line += "  " + a.Standard
		}
		ew.println(line)
	}

	ew.printf("\nUses (%d):\n", len(spec.Uses))
	for _, purpose := range usePurposesInOrder(spec.Uses) {
		ew.printf("  %s:\n", purpose)
		for _, u := range spec.Uses {
			if string(u.Purpose) != purpose {
				continue
			}
			alg := algoName[u.AlgorithmRef]
			if alg == "" {
				alg = u.AlgorithmRef
			}
			line := fmt.Sprintf("    %s  %s", u.ID, alg)
			if u.ImplementationRef != "" {
				line += " via " + u.ImplementationRef
			}
			if u.Component != "" {
				line += "  [" + u.Component + "]"
			}
			ew.println(line)
			if u.Description != "" {
				ew.printf("      %s\n", u.Description)
			}
		}
	}

	ew.printf("\nClaims (%d):\n", len(spec.Claims))
	for _, c := range spec.Claims {
		ew.printf("  [%s]  %s  %s\n", c.Verification.Status, c.ID, c.Statement)
	}
	return ew.Err()
}

// usePurposesInOrder returns the distinct purposes present in uses, sorted for
// stable output.
func usePurposesInOrder(uses []cryptospec.Use) []string {
	seen := map[string]bool{}
	var purposes []string
	for _, u := range uses {
		p := string(u.Purpose)
		if !seen[p] {
			seen[p] = true
			purposes = append(purposes, p)
		}
	}
	sort.Strings(purposes)
	return purposes
}
