package cli

import "github.com/spf13/cobra"

const longDescription = `cryptospec works with systemspec-crypto documents: a Go-first, machine-readable
description of the cryptography a system uses — what crypto exists, where and
why it is used, how it is configured, and what evidence supports those claims.`

// NewRootCommand returns the standalone cryptospec root command.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "cryptospec",
		Short: "Validate and report on systemspec-crypto documents",
		Long:  longDescription,
		// Findings and load errors are printed by the subcommands themselves;
		// don't let Cobra echo the returned error or usage on failure.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(subcommands()...)
	return root
}

// NewCommand returns a `crypto` command suitable for mounting under a family
// aggregate CLI, so `systemspec crypto validate ...` and `cryptospec validate
// ...` run the same code.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "Validate and report on systemspec-crypto documents",
		Long:  longDescription,
	}
	cmd.AddCommand(subcommands()...)
	return cmd
}

func subcommands() []*cobra.Command {
	return []*cobra.Command{
		newValidateCommand(),
		newReportCommand(),
		newCBOMCommand(),
	}
}
