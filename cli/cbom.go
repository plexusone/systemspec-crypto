package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemspec-crypto/cbom"
)

func newCBOMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cbom",
		Short: "Bridge crypto specs to and from CycloneDX CBOM",
	}
	cmd.AddCommand(newCBOMExportCommand())
	return cmd
}

func newCBOMExportCommand() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export <crypto.json>",
		Short: "Project a crypto spec into a CycloneDX 1.6 CBOM",
		Long: `Export writes a CycloneDX 1.6 CBOM (cryptographic inventory) derived from a
crypto spec. The projection is lossy — usage purpose, configuration, evidence,
and verification state have no CBOM representation — so the dropped facts are
reported on stderr.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := loadSpec(args[0])
			if err != nil {
				return err
			}
			bom, notes := cbom.Export(spec)

			out := cmd.OutOrStdout()
			var f *os.File
			if output != "" {
				f, err = os.Create(output)
				if err != nil {
					return fmt.Errorf("create %s: %w", output, err)
				}
				out = f
			}
			encErr := cbom.Encode(out, bom)
			if f != nil {
				if cerr := f.Close(); cerr != nil && encErr == nil {
					encErr = fmt.Errorf("close %s: %w", output, cerr)
				}
			}
			if encErr != nil {
				return encErr
			}

			// Report lossy conversions to stderr so they never pass silently.
			ew := &errWriter{w: cmd.ErrOrStderr()}
			for _, n := range notes {
				ew.printf("note: %s\n", n)
			}
			return ew.Err()
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "write CBOM to a file instead of stdout")
	return cmd
}
