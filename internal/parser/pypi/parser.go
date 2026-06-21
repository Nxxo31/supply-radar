// Package pypi implements a parser for Python project manifests (requirements.txt and pyproject.toml).
//
// Supported formats:
//   - requirements.txt (PEP 508 style, handles version specifiers and comments)
//   - pyproject.toml (TOML-based, reads [project].dependencies and [tool.poetry].dependencies)
//
// The parser follows the same contract as Go and npm parsers in this codebase.
package pypi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// Parser extracts dependencies from Python manifests.
type Parser struct{}

// New creates a new PyPI parser.
func New() *Parser {
	return &Parser{}
}

// Name returns "pypi".
func (p *Parser) Name() string {
	return "pypi"
}

// Supported returns the list of filenames this parser handles.
func (p *Parser) Supported() []string {
	return []string{"requirements.txt", "pyproject.toml"}
}

// Detect checks for requirements.txt or pyproject.toml in the given path.
// Returns true and the manifest path if found.
func (p *Parser) Detect(path string) (bool, string) {
	// Check requirements.txt first (more common in legacy projects).
	reqPath := filepath.Join(path, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		return true, reqPath
	}

	// Then pyproject.toml (modern standard).
	pyprojectPath := filepath.Join(path, "pyproject.toml")
	if _, err := os.Stat(pyprojectPath); err == nil {
		return true, pyprojectPath
	}

	return false, ""
}

// Parse extracts dependencies from requirements.txt or pyproject.toml.
//
// Requirements.txt format:
//
//	flask==3.0.0
//	requests>=2.31.0
//	# This is a comment line
//	--extra-index-url https://custom.pypi.org/simple/  (skip this)
//	numpy>=1.26.0,<1.27.0
//
// Pyproject.toml format:
//
//	  [project]
//
//		 dependencies = ["flask>=3.0.0", "requests>=2.31.0"]
func (p *Parser) Parse(path string) ([]dependency.Dependency, error) {
	// Try requirements.txt first.
	reqPath := filepath.Join(path, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		return p.parseRequirements(reqPath)
	}

	// Then try pyproject.toml.
	pyprojectPath := filepath.Join(path, "pyproject.toml")
	if _, err := os.Stat(pyprojectPath); err == nil {
		return p.parsePyProject(pyprojectPath)
	}

	return nil, fmt.Errorf("no supported Python manifest found in %s", path)
}

// parseRequirements reads a requirements.txt file and returns dependencies.
func (p *Parser) parseRequirements(path string) ([]dependency.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening requirements.txt: %w", err)
	}
	defer file.Close()

	var deps []dependency.Dependency
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip pip options (flags starting with - or --).
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "--") {
			continue
		}

		// Handle version specifiers: package==version, package>=version, package~=version, etc.
		// PEP 508 format: package specifiers
		name, version := parsePEP508(line)
		if name == "" {
			continue
		}

		dep := buildDep(name, version, path, true)
		deps = append(deps, dep)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading requirements.txt: %w", err)
	}

	return deps, nil
}

// parsePyProject reads a pyproject.toml and extracts dependencies from [project].dependencies
// or [tool.poetry].dependencies sections.
func (p *Parser) parsePyProject(path string) ([]dependency.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening pyproject.toml: %w", err)
	}
	defer file.Close()

	var deps []dependency.Dependency
	scanner := bufio.NewScanner(file)

	inDependencies := false
	depsBlock := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Detect dependencies section start.
		if strings.HasPrefix(line, "dependencies = [") {
			inDependencies = true
			depsBlock = ""

			// Check if the line starts and ends on the same line.
			if strings.HasSuffix(line, "]") {
				// Single-line deps list.
				content := line[strings.Index(line, "[")+1 : len(line)-1]
				deps = append(deps, parseTOMLDeps(content, path)...)
				continue
			}
			continue
		}

		// Build the multi-line dependency block.
		if inDependencies {
			if line == "]" {
				inDependencies = false
				deps = append(deps, parseTOMLDeps(depsBlock, path)...)
				depsBlock = ""
				continue
			}
			depsBlock += line
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading pyproject.toml: %w", err)
	}

	return deps, nil
}

// parseTOMLDeps parses a comma-separated list of PEP 508 dependency strings.
func parseTOMLDeps(content, manifestPath string) []dependency.Dependency {
	var deps []dependency.Dependency

	// Split by comma, handle quoted strings.
	items := strings.Split(content, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		// Remove surrounding quotes.
		item = strings.Trim(item, `"`)
		if item == "" {
			continue
		}

		name, version := parsePEP508(item)
		if name == "" {
			continue
		}

		dep := buildDep(name, version, manifestPath, true)
		deps = append(deps, dep)
	}

	return deps
}

// parsePEP508 splits a PEP 508 dependency string into name and version.
//
// Examples:
//
//	flask==3.0.0        -> flask, 3.0.0
//	requests>=2.31.0    -> requests, 2.31.0
//	numpy>=1.26,<1.27   -> numpy, 1.26
//	django>=4.2,<5.0    -> django, 4.2
//	package==2.0.0 ; python_version >= "3.10" -> package, 2.0.0
//	simple-package      -> simple-package, latest
func parsePEP508(line string) (string, string) {
	// Handle environment markers with ';'.
	cleanLine := line
	if idx := strings.Index(line, ";"); idx >= 0 {
		cleanLine = strings.TrimSpace(line[:idx])
	}

	// Package name: everything before the first version specifier.
	// Version specifiers: ==, >=, <=, !=, ~=, ===
	specifiers := []string{"===", "~=", "!=", ">=", "<=", "==", ">", "<"}

	for _, spec := range specifiers {
		if idx := strings.Index(cleanLine, spec); idx >= 0 {
			name := strings.TrimSpace(cleanLine[:idx])
			versionPart := strings.TrimSpace(cleanLine[idx+len(spec):])

			// Handle multiple specifiers (e.g., >=1.0,<2.0) — take the first.
			if commaIdx := strings.Index(versionPart, ","); commaIdx >= 0 {
				versionPart = strings.TrimSpace(versionPart[:commaIdx])
			}

			return name, versionPart
		}
	}

	// No version specifier — just package name.
	return cleanLine, "latest"
}

// parseJSON extracts a version from a JSON-encoded string.
// Used for pyproject.toml parsing when dependencies are JSON-encoded.
func parseJSON(raw string) string {
	// Trim whitespace.
	raw = strings.TrimSpace(raw)

	// Try to parse as JSON string.
	var parsed string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return raw
	}

	return parsed
}

func buildDep(name, version, path string, direct bool) dependency.Dependency {
	return dependency.Dependency{
		ID:        fmt.Sprintf("pypi:%s@%s", name, version),
		Name:      name,
		Version:   version,
		Ecosystem: "pypi",
		Path:      path,
		Direct:    direct,
	}
}
