package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemspec-crypto/validate"
)

func newValidateCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "validate <crypto.json>",
		Short: "Check a crypto spec against the structural validation rules",
		Long: `Validate checks referential integrity, capability containment,
controlled-vocabulary conformance, ID conventions, uniqueness, and evidence
requirements. It exits non-zero when any error-severity finding is present.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := loadSpec(args[0])
			if err != nil {
				return err
			}
			findings := validate.Validate(spec)
			if err := writeFindings(cmd.OutOrStdout(), findings, format); err != nil {
				return err
			}
			if validate.HasErrors(findings) {
				return errValidationFailed
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func writeFindings(w io.Writer, findings []validate.Finding, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		// Encode a non-nil slice so empty results render as [], not null.
		if findings == nil {
			findings = []validate.Finding{}
		}
		return enc.Encode(findings)
	case "text", "":
		ew := &errWriter{w: w}
		if len(findings) == 0 {
			ew.println("ok: no findings")
			return ew.Err()
		}
		for _, f := range findings {
			ew.printf("%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, f.Path, f.Message)
		}
		return ew.Err()
	default:
		return fmt.Errorf("unknown format %q (want text or json)", format)
	}
}
