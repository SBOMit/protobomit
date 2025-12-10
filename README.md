# Protobomit

Generate Software Bill of Materials (SBOMs) from Witness attestations.

## Overview

`protobomit` parses witness attestation files and generates SBOMs in SPDX or CycloneDX format. It:
- Extracts files from attestation types
- Resolves files to packages using ecosystem-specific resolvers (Python, Go, Rust, etc.)
- Filters out package files already listed as packages
- Supports multiple SBOM output formats

## Installation

```bash
git clone https://github.com/testifysec/protobomit.git
cd protobomit
go build -o protobomit ./cmd/root.go ./cmd/generate.go
```

## Usage

```bash
./protobomit generate --attestation attestation.json

--attestation string    Path to witness attestation file (required)
--output string         Output file path (default: stdout)
--format string         Output format: spdx22, spdx23, cdx14, cdx15 (default: "spdx23")
--name string           Application name (default: "protobomit-sbom")
--version string        Application version (default: "1.0.0")
--author strings        Author(s) - can be repeated
--types strings         Attestation types to process (default: material,command-run,product)
```

## Development

### Attestation Extractors

Modular extractors for different attestation types:
- `MaterialExtractor` - Build Input materials
- `CommandRunExtractor` - Opened files from processes
- `ProductExtractor` - Built artifacts

Implement `Extractor` interface to add new types.

### Resolvers

Ecosystem-specific package resolvers that extract packages from file paths:
- `PythonResolver` - Resolves from `site-packages/`, `dist-packages/`, `.dist-info`

Each resolver implements `Resolver` and optionally `PackageFileFilterer` to filter its own package files.

### Processing Pipeline

```
Attestation → Extract Files → Filter Cache Files → 
Run Resolvers → Filter Package Files → Generate SBOM
```

## Testing

```bash
go run . generate --attestation test/sample-attestation.json
``` 
   
## License  
   
Protobomit is licensed under [Apache 2.0]](LICENSE).  
   
## Contributing  
   
Contributions are welcome.
   
## Contact  
   
For any inquiries or issues, please open an issue on the [Protobomit GitHub repository](https://github.com/sbomit/protobomit/issues).
