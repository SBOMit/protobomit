package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "protobomit",
	Short: "Generate SBOMs from witness attestations",
	Long: `protobomit is a tool for generating Software Bill of Materials (SBOMs) 
from witness attestations. It parses attestations, resolves file paths to 
packages (Python, Node.js, etc.), and outputs SBOMs in SPDX or CycloneDX formats.

Examples:
  # Generate an SBOM from a witness attestation file
  protobomit generate --attestation attestation.json

  # Generate with specific output format
  protobomit generate --attestation attestation.json --format cdx14

  # Generate and write to a file
  protobomit generate --attestation attestation.json --output sbom.json`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
