package resolver

import (
	"regexp"
	"strings"
)

type FileFilter struct {
	excludePatterns []*regexp.Regexp
	excludePrefixes []string
	excludeSuffixes []string
}

func NewFileFilter() *FileFilter {
	return &FileFilter{
		excludePatterns: []*regexp.Regexp{
			// Python cache
			regexp.MustCompile(`__pycache__`),
			regexp.MustCompile(`\.pyc$`),
			regexp.MustCompile(`\.pyo$`),

			// Node.js cache
			regexp.MustCompile(`/node_modules/\.cache/`),
			regexp.MustCompile(`/\.npm/`),

			// General cache directories
			regexp.MustCompile(`/\.cache/`),

			// Build artifacts
			regexp.MustCompile(`/\.git/`),
			regexp.MustCompile(`/\.svn/`),
			regexp.MustCompile(`/\.hg/`),

			// Temp files
			regexp.MustCompile(`\.tmp$`),
			regexp.MustCompile(`\.temp$`),
			regexp.MustCompile(`~$`),

			// Log files
			regexp.MustCompile(`\.log$`),

			// OS-specific
			regexp.MustCompile(`\.DS_Store$`),
			regexp.MustCompile(`Thumbs\.db$`),

			// IDE/Editor files
			regexp.MustCompile(`/\.idea/`),
			regexp.MustCompile(`/\.vscode/`),
			regexp.MustCompile(`\.swp$`),
			regexp.MustCompile(`\.swo$`),
		},
		excludePrefixes: []string{
			"/proc/",
			"/sys/",
			"/dev/",
			"/run/",
		},
		excludeSuffixes: []string{
			".pyc",
			".pyo",
			".tmp",
			".temp",
			".log",
			".swp",
			".swo",
			"~",
		},
	}
}

func (f *FileFilter) ShouldInclude(path string) bool {
	for _, prefix := range f.excludePrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}

	for _, suffix := range f.excludeSuffixes {
		if strings.HasSuffix(path, suffix) {
			return false
		}
	}

	for _, pattern := range f.excludePatterns {
		if pattern.MatchString(path) {
			return false
		}
	}

	return true
}
