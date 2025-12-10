package attestation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func ParseWitnessFile(path string) ([]TypedAttestation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read witness file: %w", err)
	}

	return ParseWitnessData(data)
}

func ParseWitnessData(data []byte) ([]TypedAttestation, error) {
	var envelope WitnessEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal envelope: %w", err)
	}

	// Decode b64 payload
	payload := envelope.Payload
	if len(payload) == 0 {
		var rawEnvelope struct {
			PayloadType string      `json:"payloadType"`
			Payload     string      `json:"payload"`
			Signatures  []Signature `json:"signatures"`
		}
		if err := json.Unmarshal(data, &rawEnvelope); err != nil {
			return nil, fmt.Errorf("failed to unmarshal raw envelope: %w", err)
		}

		decoded, err := base64.StdEncoding.DecodeString(rawEnvelope.Payload)

		if err != nil {
			return nil, fmt.Errorf("failed to decode payload: %w", err)
		}
		payload = decoded
	}

	var statement InTotoStatement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}

	return extractAttestations(statement.Predicate)
}

func extractAttestations(predicate map[string]interface{}) ([]TypedAttestation, error) {
	var result []TypedAttestation

	attestationsRaw, ok := predicate["attestations"]
	if !ok {
		return result, nil
	}

	attestations, ok := attestationsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("attestations is not an array")
	}

	for _, att := range attestations {
		attMap, ok := att.(map[string]interface{})
		if !ok {
			continue
		}

		typed := TypedAttestation{
			Data: make(map[string]interface{}),
		}

		if typeVal, ok := attMap["type"].(string); ok {
			typed.Type = extractShortType(typeVal)
		}

		if attData, ok := attMap["attestation"].(map[string]interface{}); ok {
			typed.Data = attData
		}

		result = append(result, typed)
	}

	return result, nil
}

// "https://witness.testifysec.com/attestation/material/v0.1" -> "material"
func extractShortType(fullType string) string {
	typeMap := map[string]string{
		"material":    "material",
		"product":     "product",
		"command-run": "command-run",
		"commandrun":  "command-run",
		"environment": "environment",
		"git":         "git",
		"network":     "network",
		"file":        "file",
	}

	fullTypeLower := strings.ToLower(fullType)
	for pattern, shortType := range typeMap {
		if strings.Contains(fullTypeLower, pattern) {
			return shortType
		}
	}

	// Return the last path segment if no match
	parts := strings.Split(fullType, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" && !strings.HasPrefix(parts[i], "v") {
			return parts[i]
		}
	}

	return fullType
}

// ExtractorChain to delegate extraction to type-specific extractors
func ExtractFilesFromAttestations(attestations []TypedAttestation, types []string) []FileInfo {
	chain := NewExtractorChain()
	return chain.ExtractAll(attestations, types)
}
