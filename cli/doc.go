// Package cli builds the cryptospec Cobra commands. It exposes two entry
// points so the same subcommands serve a focused tool and the wider spec
// family:
//
//   - [NewRootCommand] returns the standalone `cryptospec` root command.
//   - [NewCommand] returns a `crypto` command that a family aggregate CLI can
//     mount with one AddCommand call (e.g. `systemspec crypto validate ...`).
//
// The package is a thin adapter: all real work lives in the cryptospec and
// validate packages, so the same capability is callable from services, CI, and
// other tooling without shelling out.
package cli
