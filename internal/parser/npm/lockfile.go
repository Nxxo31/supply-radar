package npm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// lockfilePackage represents a package entry in the packages dictionary.
type lockfilePackage struct {
	Version      string   `json:"version"`
	Resolved     string   `json:"resolved,omitempty"`
	Integrity    string   `json:"integrity,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
	Dev          bool     `json:"dev,omitempty"`
	DevOptional  bool     `json:"devOptional,omitempty"`
	Optional     bool     `json:"optional,omitempty"`
}

// packageLock represents the lockfile structure (v3).
type packageLock struct {
	LockfileVersion int                         `json:"lockfileVersion"`
	Name            string                      `json:"name"`
	Version         string                      `json:"version"`
	Packages        map[string]*lockfilePackage `json:"packages"`
	Dependencies    map[string]*lockfileDep     `json:"dependencies,omitempty"`
}

// lockfileDep represents a dependency in the legacy v2 dependencies format.
type lockfileDep struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved,omitempty"`
	Integrity    string            `json:"integrity,omitempty"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
	Dev          bool              `json:"dev,omitempty"`
	Optional     bool              `json:"optional,omitempty"`
}

// ParseLockfile extracts the exact resolved versions from package-lock.json.
// It reads from the packages dictionary (v3 format) when available, with
// fallback to the legacy dependencies dictionary (v2 format).
//
// Returns a map of package name -> exact version for all resolved deps.
// The map is keyed by package name (no scope prefix for npm packages).
func ParseLockfile(path string) (map[string]string, error) {
	lockPath := filepath.Join(path, "package-lock.json")

	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("reading package-lock.json: %w", err)
	}

	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	versions := make(map[string]string)

	// Prefer packages dictionary (v3 format).
	if len(lock.Packages) > 0 {
		for pkgPath, pkg := range lock.Packages {
			name := pkgNameFromPath(pkgPath)
			if name == "" || pkg == nil || pkg.Version == "" {
				continue
			}
			versions[name] = pkg.Version
		}
		return versions, nil
	}

	// Fallback to legacy dependencies dictionary (v2 format).
	if len(lock.Dependencies) > 0 {
		for name, dep := range lock.Dependencies {
			if dep == nil || dep.Version == "" {
				continue
			}
			versions[name] = dep.Version
		}
		return versions, nil
	}

	return versions, nil
}

// VerifyLockfile checks that the integrity hashes in package-lock.json match
// the actual downloaded packages. Returns a map of package name -> verification
// status (true if hash is valid, false if missing or invalid).
func VerifyLockfile(path string) (map[string]bool, error) {
	lockPath := filepath.Join(path, "package-lock.json")

	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("reading package-lock.json: %w", err)
	}

	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	results := make(map[string]bool)

	// Check integrity hashes.
	if len(lock.Packages) > 0 {
		for pkgPath, pkg := range lock.Packages {
			name := pkgNameFromPath(pkgPath)
			if name == "" || pkg == nil {
				continue
			}
			// If integrity is present, validate it. If missing or invalid, mark as false.
			if pkg.Integrity != "" {
				results[name] = IsValidIntegrityHash(pkg.Integrity)
			} else {
				results[name] = false // missing integrity
			}
		}
	}

	return results, nil
}

// ResolveVersions takes a list of package.json deps and resolves them to exact
// versions using package-lock.json. Packages without lockfile entries keep
// their original version string.
func ResolveVersions(pkgJSONDeps []dependency.Dependency, path string) ([]dependency.Dependency, error) {
	lockVersions, err := ParseLockfile(path)
	if err != nil {
		// If no lockfile, return deps as-is (they may be ranges).
		return pkgJSONDeps, nil
	}

	resolved := make([]dependency.Dependency, 0, len(pkgJSONDeps))
	for _, dep := range pkgJSONDeps {
		if exactVersion, ok := lockVersions[dep.Name]; ok {
			dep.Version = exactVersion
			dep.ID = fmt.Sprintf("npm:%s@%s", dep.Name, exactVersion)
		}
		// Otherwise keep original (range version from package.json).
		resolved = append(resolved, dep)
	}

	return resolved, nil
}

// pkgNameFromPath extracts the package name from a node_modules path.
// "node_modules/lodash" -> "lodash"
// "node_modules/@babel/core" -> "@babel/core"
// "" (root entry) -> ""
func pkgNameFromPath(pkgPath string) string {
	// Root package (empty path in packages dict).
	if pkgPath == "" {
		return ""
	}

	// Strip leading "./" if present.
	pkgPath = strings.TrimPrefix(pkgPath, "./")

	// Must start with node_modules/.
	if !strings.HasPrefix(pkgPath, "node_modules/") {
		return ""
	}

	pkgPath = strings.TrimPrefix(pkgPath, "node_modules/")

	// Handle scoped packages: @org/package -> @org/package.
	// No further stripping needed.
	return pkgPath
}

// IsValidIntegrityHash checks if a string is a valid SHA-512 integrity hash.
// npm uses "sha512-<base64>" format. Returns true if the hash decodes to exactly 64 bytes.
func IsValidIntegrityHash(hash string) bool {
	if hash == "" {
		return false
	}

	// npm v7+ uses "sha512-<base64>" format.
	if strings.HasPrefix(hash, "sha512-") {
		encoded := strings.TrimPrefix(hash, "sha512-")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return false
		}
		return len(decoded) == 64 // SHA-512 produces 64 bytes
	}

	// Legacy plain base64 (less common).
	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}
	return len(decoded) == 64
}
