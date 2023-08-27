package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sbom",
	Short: "A tool for managing SBOM",
	Long:  `A tool for managing Software Bill of Materials (SBOM) by adding in-toto attestations as an external references.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
