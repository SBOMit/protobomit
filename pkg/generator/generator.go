package generator

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/testifysec/protobomit/pkg/attestation"
	"github.com/testifysec/protobomit/pkg/resolver"
)

type Options struct {
	DocumentName     string
	DocumentVersion  string
	Authors          []string
	AttestationTypes []string
	OutputFormat     string
	OutputPath       string
}

// DefaultOptions returns default generator options
func DefaultOptions() *Options {
	return &Options{
		DocumentName:     "protobomit-generated-sbom",
		DocumentVersion:  "1.0.0",
		Authors:          []string{},
		AttestationTypes: []string{"material", "command-run", "product"},
		OutputFormat:     "spdx23",
	}
}

type Generator struct {
	opts          *Options
	resolverChain *resolver.ResolverChain
}

func New(opts *Options) *Generator {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Generator{
		opts:          opts,
		resolverChain: resolver.NewResolverChain(),
	}
}

func (g *Generator) GenerateFromFile(attestationPath string) error {
	attestations, err := attestation.ParseWitnessFile(attestationPath)
	if err != nil {
		return fmt.Errorf("failed to parse attestation file: %w", err)
	}
	return g.GenerateFromAttestations(attestations)
}

func (g *Generator) GenerateFromAttestations(attestations []attestation.TypedAttestation) error {
	attFiles := attestation.ExtractFilesFromAttestations(attestations, g.opts.AttestationTypes)

	// Convert to resolver.FileInfo format
	var files []resolver.FileInfo
	for _, f := range attFiles {
		files = append(files, resolver.FileInfo{
			Path:   f.Path,
			Hashes: f.Hashes,
		})
	}

	// Run through resolver chain (filtering + resolution)
	result := g.resolverChain.ResolveAll(files)

	doc := g.createDocument(result)

	return g.writeOutput(doc)
}

func (g *Generator) createDocument(result resolver.ResolverResult) *sbom.Document {
	doc := sbom.NewDocument()

	doc.Metadata.Id = fmt.Sprintf("urn:uuid:%s", generateUUID())
	doc.Metadata.Name = g.opts.DocumentName
	doc.Metadata.Version = g.opts.DocumentVersion
	doc.Metadata.Date = timestamppb.New(time.Now())

	for _, author := range g.opts.Authors {
		doc.Metadata.Authors = append(doc.Metadata.Authors, &sbom.Person{Name: author})
	}

	doc.Metadata.Tools = append(doc.Metadata.Tools, &sbom.Tool{
		Name:    "protobomit",
		Version: "1.0.0",
		Vendor:  "SBOMit",
	})

	appNode := &sbom.Node{
		Id:             fmt.Sprintf("pkg:generic/%s@%s", sanitizeID(g.opts.DocumentName), g.opts.DocumentVersion),
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_APPLICATION},
		Name:           g.opts.DocumentName,
		Version:        g.opts.DocumentVersion,
	}

	doc.NodeList.AddRootNode(appNode)

	// Add resolved packages
	for _, pkg := range result.Packages {
		node := g.createPackageNode(pkg)
		doc.NodeList.AddNode(node)
		doc.NodeList.RelateNodeAtID(node, appNode.Id, sbom.Edge_contains)
	}

	// Add unresolved files
	for _, file := range result.Files {
		node := g.createFileNode(file)
		doc.NodeList.AddNode(node)
		doc.NodeList.RelateNodeAtID(node, appNode.Id, sbom.Edge_contains)
	}

	return doc
}

func (g *Generator) createPackageNode(pkg resolver.PackageInfo) *sbom.Node {
	node := &sbom.Node{
		Id:             pkg.PURL,
		Type:           sbom.Node_PACKAGE,
		Name:           pkg.Name,
		Version:        pkg.Version,
		PrimaryPurpose: []sbom.Purpose{sbom.Purpose_LIBRARY},
		Licenses:       pkg.Licenses,
		Identifiers:    make(map[int32]string),
		Hashes:         make(map[int32]string),
	}

	node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = pkg.PURL

	for algo, hash := range pkg.Hashes {
		hashAlgo := mapHashAlgorithm(algo)
		if hashAlgo != sbom.HashAlgorithm_UNKNOWN {
			node.Hashes[int32(hashAlgo)] = hash
		}
	}

	return node
}

func (g *Generator) createFileNode(file resolver.FileInfo) *sbom.Node {
	node := &sbom.Node{
		Id:     fmt.Sprintf("File-%s", sanitizeID(file.Path)),
		Type:   sbom.Node_FILE,
		Name:   file.Path,
		Hashes: make(map[int32]string),
	}

	for algo, hash := range file.Hashes {
		hashAlgo := mapHashAlgorithm(algo)
		if hashAlgo != sbom.HashAlgorithm_UNKNOWN {
			node.Hashes[int32(hashAlgo)] = hash
		}
	}

	return node
}

// nopWriteCloser wraps os.File to implement io.WriteCloser
type nopWriteCloser struct {
	w *os.File
}

func (n *nopWriteCloser) Write(p []byte) (int, error) {
	return n.w.Write(p)
}

func (n *nopWriteCloser) Close() error {
	if n.w == os.Stdout {
		return nil
	}
	return n.w.Close()
}

func (g *Generator) writeOutput(doc *sbom.Document) error {
	w := writer.New()
	format := g.getOutputFormat()

	if g.opts.OutputPath == "" || g.opts.OutputPath == "-" {
		return w.WriteStreamWithOptions(doc, &nopWriteCloser{w: os.Stdout}, &writer.Options{Format: format})
	}

	return w.WriteFileWithOptions(doc, g.opts.OutputPath, &writer.Options{Format: format})
}

func (g *Generator) getOutputFormat() formats.Format {
	switch strings.ToLower(g.opts.OutputFormat) {
	case "spdx23", "spdx-2.3", "spdx23json":
		return formats.SPDX23JSON
	case "spdx22", "spdx-2.2", "spdx22json":
		return formats.SPDX22JSON
	case "cdx14", "cdx-1.4", "cdx14json", "cyclonedx14":
		return formats.CDX14JSON
	case "cdx15", "cdx-1.5", "cdx15json", "cyclonedx15":
		return formats.CDX15JSON
	default:
		return formats.SPDX23JSON
	}
}

func mapHashAlgorithm(algo string) sbom.HashAlgorithm {
	switch strings.ToLower(algo) {
	case "sha256", "sha-256":
		return sbom.HashAlgorithm_SHA256
	case "sha1", "sha-1":
		return sbom.HashAlgorithm_SHA1
	case "sha512", "sha-512":
		return sbom.HashAlgorithm_SHA512
	case "md5":
		return sbom.HashAlgorithm_MD5
	case "sha384", "sha-384":
		return sbom.HashAlgorithm_SHA384
	default:
		return sbom.HashAlgorithm_UNKNOWN
	}
}

func sanitizeID(s string) string {
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		" ", "-",
		":", "-",
		"@", "-at-",
	)
	result := replacer.Replace(s)
	result = strings.Trim(result, "-")
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	return result
}

func generateUUID() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		now&0xFFFFFFFF,
		(now>>32)&0xFFFF,
		(now>>48)&0xFFFF,
		(now>>16)&0xFFFF,
		now&0xFFFFFFFFFFFF,
	)
}
