package cmd

import (
	"github.com/spf13/cobra"
	"github.com/testifysec/protobomit/pkg"
)

var (
	sbomFile         string
	attestationFiles []string
	policyFile       string
	publicKeyFile    string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new SBOM",
	Long:  `Generate a new SBOM by adding in-toto attestations as an external references.`,
	Run: func(cmd *cobra.Command, args []string) {
		pkg.GenerateSBOM(sbomFile, attestationFiles, policyFile, publicKeyFile)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVarP(&sbomFile, "sbom", "s", "", "Path to the SBOM file (required)")
	generateCmd.Flags().StringSliceVarP(&attestationFiles, "attestation", "a", []string{}, "Path to the attestation file (required)")
	generateCmd.Flags().StringVarP(&policyFile, "policy", "p", "", "Path to the policy file (required)")
	generateCmd.Flags().StringVarP(&publicKeyFile, "publicKey", "k", "", "Path to the public key file (required)")
	generateCmd.MarkFlagRequired("sbom")
	generateCmd.MarkFlagRequired("attestation")
	generateCmd.MarkFlagRequired("policy")
	generateCmd.MarkFlagRequired("publicKey")
}
