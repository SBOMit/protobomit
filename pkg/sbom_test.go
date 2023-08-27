package pkg

import (
	"testing"
)

func TestGenerateSBOM(t *testing.T) {
	sbomFile := "../test/galadriel_Linux_x86_64.tar.gz.spdx.sbom"

	attestationFiles := []string{"../test/3f9855594d691b35095c35e5f7d64d37ad314d51368678582c719c34aa072afa.json"}
	policyFile := "../test/policy-signed.json"
	publicKeyFile := "../test/policy.pub"

	err := GenerateSBOM(sbomFile, attestationFiles, policyFile, publicKeyFile)

	if err != nil {
		t.Errorf("GenerateSBOM() failed, expected %v, got %v", nil, err)
	}
}
