package gomod

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// ParseGoSum reads the go.sum file and returns a map of module -> exact version.
// It only considers the main module lines (not the .go.mod lines) for version resolution.
// Returns a map where key is module path and value is the exact version string.
// Note: version strings in go.sum include the 'v' prefix.
func ParseGoSum(path string) (map[string]string, error) {
	sumPath := filepath.Join(path, "go.sum")
	file, err := os.Open(sumPath)
	if err != nil {
		// If no go.sum file, return empty map (not an error)
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, fmt.Errorf("opening go.sum: %w", err)
	}
	defer file.Close()

	versions := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		// Format: module version checksum
		parts := strings.Fields(line)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid go.sum line %d: %q", lineNum, line)
		}

		modulePath := parts[0]
		version := parts[1]

		// Skip .go.mod lines for version resolution (we only want the main module versions)
		// In go.sum, .go.mod variants have the format: module version/go.mod checksum
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}

		// Store the version (we keep the full version string including 'v' prefix)
		versions[modulePath] = version
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading go.sum: %w", err)
	}

	return versions, nil
}

// GoSumExists checks if a go.sum file exists in the given path.
func GoSumExists(path string) bool {
	_, err := os.Stat(filepath.Join(path, "go.sum"))
	return err == nil
}

// ResolveVersionsWithGoSum takes a list of dependencies from go.mod and resolves them to exact
// versions using go.sum if available. If a dependency is not found in go.sum, it keeps
// the original version from go.mod.
func ResolveVersionsWithGoSum(goModDeps []dependency.Dependency, path string) ([]dependency.Dependency, error) {
	// First, try to get versions from go.sum
	goSumVersions, err := ParseGoSum(path)
	if err != nil {
		// If we can't read go.sum, fall back to go.mod versions
		return goModDeps, nil
	}

	// If go.sum is empty or doesn't contain any versions, fall back to go.mod
	if len(goSumVersions) == 0 {
		return goModDeps, nil
	}

	resolved := make([]dependency.Dependency, 0, len(goModDeps))
	for _, dep := range goModDeps {
		if exactVersion, ok := goSumVersions[dep.Name]; ok {
			// Use the exact version from go.sum
			dep.Version = exactVersion
			// Note: we keep the 'v' prefix in the version for now, but the OSV client
			// will strip it when making requests (as it does for go.mod versions)
			dep.ID = fmt.Sprintf("go:%s@%s", dep.Name, exactVersion)
		}
		// Otherwise keep the original version from go.mod
		resolved = append(resolved, dep)
	}

	return resolved, nil
}
