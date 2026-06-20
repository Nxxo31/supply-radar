// Package npm implements a parser for Node.js packages (package.json + lockfiles).
package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// Parser handles Node.js/JavaScript project manifests.
type Parser struct{}

// New creates a new npm parser.
func New() *Parser {
	return &Parser{}
}

// Name returns the parser identifier.
func (p *Parser) Name() string {
	return "npm"
}

// Supported returns the file names this parser handles.
func (p *Parser) Supported() []string {
	return []string{"package.json", "package-lock.json", "yarn.lock"}
}

// Detect checks if a package.json file exists in the given path.
func (p *Parser) Detect(path string) (bool, string) {
	manifest := filepath.Join(path, "package.json")
	if _, err := os.Stat(manifest); err == nil {
		return true, manifest
	}
	return false, ""
}

// npmPackage represents the relevant fields of package.json.
type npmPackage struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// Parse extracts dependencies from package.json and resolves exact versions
// from package-lock.json when available.
//
// Uses package.json as the source of truth for declared dependencies,
// and package-lock.json for resolved exact versions.
func (p *Parser) Parse(path string) ([]dependency.Dependency, error) {
	manifest := filepath.Join(path, "package.json")
	data, err := os.ReadFile(manifest)
	if err != nil {
		return nil, fmt.Errorf("reading package.json: %w", err)
	}

	var pkg npmPackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	var deps []dependency.Dependency

	// Process dependencies.
	for name, version := range pkg.Dependencies {
		dep := buildDep(name, version, manifest, true)
		deps = append(deps, dep)
	}

	// Process devDependencies (marked as direct but distinguished by scope).
	for name, version := range pkg.DevDependencies {
		dep := buildDep(name, version, manifest, true)
		dep.ID = fmt.Sprintf("npm:dev:%s@%s", name, version)
		deps = append(deps, dep)
	}

	// Resolve to exact versions from lockfile if available.
	resolved, err := ResolveVersions(deps, path)
	if err != nil {
		// Log but continue with package.json versions.
		return deps, nil
	}

	return resolved, nil
}

func buildDep(name, version, path string, direct bool) dependency.Dependency {
	// Clean version: strip ^ ~ >= <= prefixes for matching purposes.
	cleanVersion := strings.TrimLeft(version, "^~>=< ")

	return dependency.Dependency{
		ID:        fmt.Sprintf("npm:%s@%s", name, cleanVersion),
		Name:      name,
		Version:   cleanVersion,
		Ecosystem: "npm",
		Path:      path,
		Direct:    direct,
	}
}
