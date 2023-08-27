package pkg

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
)

func GenerateSBOM(sbomFile string, attestationFiles []string, policyFile string, publicKeyFile string) error {
	hasher := sha256.New()
	sbomContents, err := ioutil.ReadFile(sbomFile)
	if err != nil {
		log.Fatalf("Failed reading file: %s", err)
	}
	hasher.Write(sbomContents)
	sbomHash := hasher.Sum(nil)

	fmt.Printf("Hash of SBOM: %x\n", sbomHash)

	if err := verifyWitness(sbomHash, policyFile, attestationFiles, publicKeyFile); err != nil {
		log.Fatalf("Verification failed: %s", err)
	}

	stepName, oid, err := locator(attestationFiles, sbomHash)
	if err != nil {
		log.Fatalf("Failed to locate hash in attestation: %s", err)
	}

	fmt.Printf("Step name: %s\n", stepName)
	fmt.Printf("OID: %s\n", oid)

	r := reader.New()
	doc, err := r.ParseFile(sbomFile)
	if err != nil {
		log.Fatalf("Failed reading SBOM file: %s", err)
	}

	hashType := strings.Join(strings.Split(oid, ":")[:3], ":")
	hashValue := strings.Split(oid, ":")[3]

	url := "https://archivista.testifysec.io/download/" + hashValue

	hashes := map[string]string{
		hashType: hashValue,
	}

	doc.NodeList.Nodes[0].ExternalReferences = append(doc.NodeList.Nodes[0].ExternalReferences, &sbom.ExternalReference{
		Type:      "https://witness.testifysec.com/attestation-collection/v0.1",
		Authority: "testifysec.com",
		Url:       url,
		Hashes:    hashes,
		Comment:   "in-toto attestation for the SBOM Step",
	})

	newFile, err := os.Create("new_sbom_file.sbom")
	if err != nil {
		log.Fatalf("Failed creating new SBOM file: %s", err)
	}
	defer newFile.Close()

	w := writer.New()
	if err := w.WriteStream(doc, newFile); err != nil {
		log.Fatalf("Failed writing to new SBOM file: %s", err)
	}

	return nil
}
