package attestation

// MaterialExtractor extracts files from material attestations
// Material attestations typically contain source files and their hashes
type MaterialExtractor struct{}

func NewMaterialExtractor() *MaterialExtractor {
	return &MaterialExtractor{}
}

func (e *MaterialExtractor) Name() string {
	return "material"
}

func (e *MaterialExtractor) Extract(data map[string]interface{}) []FileInfo {
	var files []FileInfo

	materials, ok := data["materials"].(map[string]interface{})
	if !ok {
		materials = make(map[string]interface{})
		for k, v := range data {
			// Skip non-file entries for now
			if k != "materials" && k != "command" && k != "environ" && k != "environment" {
				materials[k] = v
			}
		}
		if len(materials) == 0 {
			return files
		}
	}

	for path, hashData := range materials {
		fi := FileInfo{
			Path:   path,
			Hashes: make(map[string]string),
		}

		if hashes, ok := hashData.(map[string]interface{}); ok {
			for algo, hash := range hashes {
				if hashStr, ok := hash.(string); ok {
					fi.Hashes[algo] = hashStr
				}
			}
		}

		if len(fi.Hashes) > 0 {
			files = append(files, fi)
		}
	}

	return files
}
