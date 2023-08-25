package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/edwarnicke/gitoid"

	_ "github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/attestation"
	_ "github.com/testifysec/go-witness/attestation/file"
	_ "github.com/testifysec/go-witness/attestation/material"
	_ "github.com/testifysec/go-witness/attestation/product"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/intoto"
)

func main() {

	sbomFile := "test/galadriel_Linux_x86_64.tar.gz.spdx.sbom"
	attestationFile := "test/4940f9f4f29f9531a9068ede8ce01b98ffc9302dc3ef4db916cd837c637bd9a3.json"
	// policyFile := "test/policy.json"
	// pubkeyFile := "test/pubkey.pem"

	// NOTE: The verification with go-witness is still missing.

	// Calculate the hash of the sbom
	hasher := sha256.New()
	sbomContents, err := ioutil.ReadFile(sbomFile)
	if err != nil {
		log.Fatalf("Failed reading file: %s", err)
	}
	hasher.Write(sbomContents)
	sbomHash := hasher.Sum(nil)

	fmt.Printf("Hash of SBOM: %x\n", sbomHash)

	//find the hash in the attestation
	stepName, oid, err := locator([]string{attestationFile}, sbomHash)
	if err != nil {
		log.Fatalf("Failed to locate hash in attestation: %s", err)
	}

	fmt.Printf("Step name: %s\n", stepName)
	fmt.Printf("OID: %s\n", oid)

}

// verify the hash of the sbom against the output hash of the attestation

// Read SBOM to protobom

// add external references to the protobom
func locator(attestionFiles []string, sbomHash []byte) (stepName string, oid string, err error) {
	hashStr := fmt.Sprintf("%x", sbomHash)

	for _, f := range attestionFiles {
		// Read the content of the attestation file
		data, err := ioutil.ReadFile(f)
		if err != nil {
			return "", "", fmt.Errorf("failed reading file %s: %w", f, err)
		}

		// Unmarshal the content into dsse.Envelope type
		var envelope dsse.Envelope
		if err = json.Unmarshal(data, &envelope); err != nil {
			return "", "", fmt.Errorf("failed to unmarshal data from file %s: %w", f, err)
		}

		// Unmarshal the decoded payload into in-toto.Statement type
		var statement intoto.Statement
		if err = json.Unmarshal(envelope.Payload, &statement); err != nil {
			return "", "", fmt.Errorf("failed to unmarshal in-toto statement from file %s: %w", f, err)
		}

		// Unmarshal the predicate into attestation.Collection type
		var attCollection attestation.Collection
		if err = json.Unmarshal(statement.Predicate, &attCollection); err != nil {
			return "", "", fmt.Errorf("failed to unmarshal attestation collection from file %s: %w", f, err)
		}
		fmt.Printf("Attestation Collection Name: %s\n", attCollection.Name)

		// Create a reader for the attestation data using io package
		reader := bytes.NewReader(data)

		gitoid, err := gitoid.New(reader, gitoid.WithSha256())
		if err != nil {
			return "", "", fmt.Errorf("failed to create gitoid from file %s: %w", f, err)
		}

		// Now you have the statement which includes the subject that we are interested in
		for _, subj := range statement.Subject {
			for _, digest := range subj.Digest {
				if digest == hashStr {
					// If the hash matches, return the step name and OID
					fmt.Printf("Found hash %s in attestation %s\n", hashStr, f)
					return attCollection.Name, gitoid.URI(), nil
				}
			}
		}
	}

	return "", "", nil // Could replace this with a specific error if no matching hash was found
}
