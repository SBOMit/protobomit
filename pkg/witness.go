package pkg

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/edwarnicke/gitoid"
	"github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/attestation"
	_ "github.com/testifysec/go-witness/attestation/file"
	_ "github.com/testifysec/go-witness/attestation/material"
	_ "github.com/testifysec/go-witness/attestation/product"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/intoto"
	"github.com/testifysec/go-witness/source"
)

func locator(attestationFiles []string, sbomHash []byte) (stepName string, oid string, err error) {
	hashStr := fmt.Sprintf("%x", sbomHash)

	for _, attestationFile := range attestationFiles {

		data, err := ioutil.ReadFile(attestationFile)
		if err != nil {
			log.Fatalf("Failed reading file: %s", err)
		}

		var envelope dsse.Envelope
		if err = json.Unmarshal(data, &envelope); err != nil {
			log.Fatalf("Failed to unmarshal data from file: %s", err)
		}

		var statement intoto.Statement
		if err = json.Unmarshal(envelope.Payload, &statement); err != nil {
			log.Fatalf("Failed to unmarshal in-toto statement from file: %s", err)
		}

		var attCollection attestation.Collection
		if err = json.Unmarshal(statement.Predicate, &attCollection); err != nil {
			log.Fatalf("Failed to unmarshal attestation collection from file: %s", err)
		}
		log.Printf("Attestation Collection Name: %s\n", attCollection.Name)

		reader := bytes.NewReader(data)

		gitoid, err := gitoid.New(reader, gitoid.WithSha256())
		if err != nil {
			log.Fatalf("Failed to create gitoid from file: %s", err)
		}

		for _, subj := range statement.Subject {
			for _, digest := range subj.Digest {
				if digest == hashStr {
					log.Printf("Found hash %s in attestation\n", hashStr)
					return attCollection.Name, gitoid.URI(), nil
				}
			}
		}
	}
	return "", "", nil
}

func verifyWitness(sbomHash []byte, policyFile string, attestationFiles []string, publicKeyFile string) error {
	policyData, err := ioutil.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}
	policyEnvelope := dsse.Envelope{}
	if err := json.Unmarshal(policyData, &policyEnvelope); err != nil {
		return fmt.Errorf("failed to unmarshal policy envelope: %w", err)
	}

	pubKeyData, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	verifier, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(pubKeyData))
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	subjects := []cryptoutil.DigestSet{
		{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: fmt.Sprintf("%x", sbomHash)},
	}

	memSource := source.NewMemorySource()
	for _, attestationFile := range attestationFiles {

		if err := memSource.LoadFile(attestationFile); err != nil {
			return fmt.Errorf("failed to load attestation file: %w", err)
		}
	}

	_, err = witness.Verify(
		context.Background(),
		policyEnvelope,
		[]cryptoutil.Verifier{verifier},
		witness.VerifyWithSubjectDigests(subjects),
		witness.VerifyWithCollectionSource(memSource),
	)

	if err != nil {
		return fmt.Errorf("failed to verify policy: %w", err)
	}

	log.Println("Verification succeeded")
	return nil
}
