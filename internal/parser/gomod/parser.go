package gomod

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// Parser handles Go module manifest files.
type Parser struct{}

// New creates a new Go module parser.
func New() *Parser {
	return &Parser{}
}

// Name returns the parser identifier.
func (p *Parser) Name() string {
	return "go-mod"
}

// Supported returns the file names this parser handles.
func (p *Parser) Supported() []string {
	return []string{"go.mod"}
}

// Detect checks if a go.mod file exists in the given path.
func (p *Parser) Detect(path string) (bool, string) {
	manifest := filepath.Join(path, "go.mod")
	if _, err := os.Stat(manifest); err == nil {
		return true, manifest
	}
	return false, ""
}

// Parse extracts dependencies from go.mod and resolves exact versions
// from go.sum when available.
//
// Uses go.mod as the source of truth for declared dependencies,
// and go.sum for resolved exact versions and tamper detection.
func (p *Parser) Parse(path string) ([]dependency.Dependency, error) {
	manifest := filepath.Join(path, "go.mod")
	data, err := os.ReadFile(manifest)
	if err != nil {
		return nil, fmt.Errorf("opening go.mod: %w", err)
	}

	var deps []dependency.Dependency
	scanner := bufio.NewScanner(bytes.NewReader(data))

	// State machine: we only care about require blocks.
	inRequire := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip blank lines and comments.
		if trimmed == "" || strings.TrimPrefix(trimmed, "//") == "" {
			continue
		}

		// Detect require directive with inline syntax:
		//   require pkg v1.0.0
		if strings.HasPrefix(trimmed, "require ") && !strings.Contains(trimmed, "(") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				dep := buildDep(parts[1], parts[2], manifest, true)
				deps = append(deps, dep)
			}
			continue
		}

		// Detect require block start:
		//   require (
		if strings.HasPrefix(trimmed, "require (") {
			inRequire = true
			continue
		}

		// Detect require block end.
		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}

		// Inside a require block, parse each line:
		//   pkg v1.0.0
		//   pkg v1.0.0 // indirect
		if inRequire {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				direct := true
				// The version is the second field; anything after may include comments.
				version := parts[1]
				// Check for indirect comment in remaining fields.
				comment := strings.Join(parts[2:], " ")
				if strings.Contains(comment, "indirect") {
					direct = false
				}
				dep := buildDep(parts[0], version, manifest, direct)
				deps = append(deps, dep)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	// Resolve to exact versions from go.sum if available.
	resolved, err := ResolveVersionsWithGoSum(deps, path)
	if err != nil {
		// Log but continue with go.mod versions.
		return deps, nil
	}

	return resolved, nil
}
func buildDep(name, version, path string, direct bool) dependency.Dependency {
	// Strip Go module version prefix (v4.0.0 -> 4.0.0) for OSV compatibility.
	cleanVersion := strings.TrimPrefix(version, "v")

	return dependency.Dependency{
		ID:        fmt.Sprintf("go:%s@%s", name, cleanVersion),
		Name:      name,
		Version:   cleanVersion,
		Ecosystem: "go",
		Path:      path,
		Direct:    direct,
	}
}
