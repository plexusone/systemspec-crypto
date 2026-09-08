// Command cryptospec is the standalone CLI for systemspec-crypto documents.
// It is a thin adapter over the cli package; all capability lives in importable
// packages so the same functionality is callable from services and CI.
package main

import (
	"os"

	"github.com/plexusone/systemspec-crypto/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
