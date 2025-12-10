package attestation

// CommandRunExtractor extracts files from command-run attestations
// Command-run attestations contain files that were opened/accessed during command execution
type CommandRunExtractor struct{}

func NewCommandRunExtractor() *CommandRunExtractor {
	return &CommandRunExtractor{}
}

func (e *CommandRunExtractor) Name() string {
	return "command-run"
}

func (e *CommandRunExtractor) Extract(data map[string]interface{}) []FileInfo {
	var files []FileInfo
	var openedFiles map[string]interface{}

	processesRaw, ok := data["processes"].([]interface{})

	if ok && len(processesRaw) > 0 {
		// Unique files from all processes
		allOpenedFiles := make(map[string]interface{})
		for _, procRaw := range processesRaw {
			if proc, ok := procRaw.(map[string]interface{}); ok {
				if procOpened, ok := proc["openedfiles"].(map[string]interface{}); ok {
					for path, hashData := range procOpened {
						if _, exists := allOpenedFiles[path]; !exists {
							allOpenedFiles[path] = hashData
						}
					}
				}
			}
		}
		if len(allOpenedFiles) > 0 {
			openedFiles = allOpenedFiles
		}
	}
	if openedFiles == nil {
		return files
	}

	for path, hashData := range openedFiles {
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
