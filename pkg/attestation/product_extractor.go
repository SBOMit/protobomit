package attestation

// ProductExtractor extracts files from product attestations
// Product attestations typically contain output/build artifacts and their hashes
type ProductExtractor struct{}

func NewProductExtractor() *ProductExtractor {
	return &ProductExtractor{}
}

func (e *ProductExtractor) Name() string {
	return "product"
}

func (e *ProductExtractor) Extract(data map[string]interface{}) []FileInfo {
	var files []FileInfo

	products, ok := data["products"].(map[string]interface{})
	if !ok {
		products = make(map[string]interface{})
		for k, v := range data {
			if k != "command" && k != "environ" && k != "environment" {
				products[k] = v
			}
		}
		if len(products) == 0 {
			return files
		}
	}

	for path, hashData := range products {
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
