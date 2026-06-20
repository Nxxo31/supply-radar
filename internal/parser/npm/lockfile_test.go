package npm

import (
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

func testdata(t *testing.T) string {
	// testdata/ is next to the parser source files.
	_, thisFile, _, _ := runtime.Caller(0)
	// internal/parser/npm/ -> internal/parser/npm/
	pkgDir := filepath.Dir(thisFile)
	return filepath.Join(pkgDir, "testdata")
}

func TestParseLockfile_Basic(t *testing.T) {
	// Temp dir with package-lock.json v3.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
  "name": "test-pkg",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-pkg",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTutaDI8BGTYmkkmC9Q7S2RoasjsM/A9nHJPXFT8dzC7p4860jxU9umQ4PyRn9Rb+9Acvwoc8g=="
    },
    "node_modules/axios": {
      "version": "1.6.2",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.6.2.tgz",
      "integrity": "sha512-7lDpHy4d6wW5l5XZ8I7E1KE+ZGIuGd3iKyltX1gTFXd4umY8oviQ4X5gehaTJH6eMXMfUkwIJ4V50PNUVGw=="
    }
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	versions, err := ParseLockfile(dir)
	if err != nil {
		t.Fatalf("ParseLockfile failed: %v", err)
	}

	if len(versions) != 2 {
		t.Fatalf("Expected 2 versions from lockfile, got %d", len(versions))
	}

	if versions["lodash"] != "4.17.21" {
		t.Errorf("Expected lodash 4.17.21, got %s", versions["lodash"])
	}
	if versions["axios"] != "1.6.2" {
		t.Errorf("Expected axios 1.6.2, got %s", versions["axios"])
	}
}

func TestParseLockfile_V2Legacy(t *testing.T) {
	// Temp dir with package-lock.json v2 (legacy).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
  "name": "test-pkg",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTutaDI8BGTYmkkmC9Q7S2RoasjsM/A9nHJPXFT8dzC7p4860jxU9umQ4PyRn9Rb+9Acvwoc8g=="
    }
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	versions, err := ParseLockfile(dir)
	if err != nil {
		t.Fatalf("ParseLockfile failed: %v", err)
	}

	if len(versions) != 1 {
		t.Fatalf("Expected 1 version from lockfile (v2), got %d", len(versions))
	}
	if versions["lodash"] != "4.17.21" {
		t.Errorf("Expected lodash 4.17.21, got %s", versions["lodash"])
	}
}

func TestResolveVersions_Basic(t *testing.T) {
	// Setup package.json deps with versions.
	deps := []dependency.Dependency{
		{
			Name:      "lodash",
			Version:   "^4.17.20", // range
			Ecosystem: "npm",
			Path:      "/tmp/test",
			Direct:    true,
			ID:        "npm:lodash@^4.17.20",
		},
		{
			Name:      "axios",
			Version:   "~0.27.2", // range
			Ecosystem: "npm",
			Path:      "/tmp/test",
			Direct:    true,
			ID:        "npm:axios@~0.27.2",
		},
	}

	// Temp dir with package-lock.json.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
  "name": "test-pkg",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-pkg",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    },
    "node_modules/axios": {
      "version": "1.6.2",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.6.2.tgz"
    }
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolveVersions(deps, dir)
	if err != nil {
		t.Fatalf("ResolveVersions failed: %v", err)
	}

	if len(resolved) != 2 {
		t.Fatalf("Expected 2 resolved deps, got %d", len(resolved))
	}

	// Check lodash: ^4.17.20 -> 4.17.21 (exact)
	for _, dep := range resolved {
		if dep.Name == "lodash" {
			if dep.Version != "4.17.21" {
				t.Errorf("Expected lodash 4.17.21, got %s", dep.Version)
			}
			if dep.ID != "npm:lodash@4.17.21" {
				t.Errorf("Expected lodash ID npm:lodash@4.17.21, got %s", dep.ID)
			}
		}
		if dep.Name == "axios" {
			if dep.Version != "1.6.2" {
				t.Errorf("Expected axios 1.6.2, got %s", dep.Version)
			}
			if dep.ID != "npm:axios@1.6.2" {
				t.Errorf("Expected axios ID npm:axios@1.6.2, got %s", dep.ID)
			}
		}
	}
}

func TestResolveVersions_NoLockfile(t *testing.T) {
	deps := []dependency.Dependency{
		{
			Name:      "lodash",
			Version:   "4.17.20",
			Ecosystem: "npm",
			Path:      "/tmp/test",
			Direct:    true,
			ID:        "npm:lodash@4.17.20",
		},
	}

	// No lockfile present.
	dir := t.TempDir()
	// Ensure no package-lock.json exists.

	resolved, err := ResolveVersions(deps, dir)
	if err != nil {
		t.Fatalf("ResolveVersions failed: %v", err)
	}

	if len(resolved) != 1 {
		t.Fatalf("Expected 1 dep, got %d", len(resolved))
	}
	if resolved[0].Version != "4.17.20" {
		t.Errorf("Expected version unchanged 4.17.20, got %s", resolved[0].Version)
	}
}

func TestVerifyLockfile_HashValidation(t *testing.T) {
	// Create a valid SHA-512 hash for a known string
	data := []byte("test-string-for-hash")
	hashBytes := sha512.Sum512(data)
	validB64 := base64.StdEncoding.EncodeToString(hashBytes[:])
	validHash := "sha512-" + validB64

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
  "name": "test-pkg",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-pkg",
      "volume": "1.0.0"
    },
    "node_modules/good": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/good/-/good-1.0.0.tgz",
      "integrity": "` + validHash + `"
    },
    "node_modules/bad": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/bad/-/bad-1.0.0.tgz",
      "integrity": "sha512-invalid-base64-here!!!"
    }
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := VerifyLockfile(dir)
	if err != nil {
		t.Fatalf("VerifyLockfile failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}
	
	if results["good"] != true {
		t.Error("Expected good hash to be valid")
	}
	if results["bad"] != false {
		t.Error("Expected bad hash to be invalid")
	}
}

func TestVerifyLockfile_NoIntegrity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
  "name": "test-pkg",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-pkg",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := VerifyLockfile(dir)
	if err != nil {
		t.Fatalf("VerifyLockfile failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if results["lodash"] != false {
		t.Error("Expected lodash without integrity to be false (not verified)")
	}
}

func TestIsValidIntegrityHash_KnownGood(t *testing.T) {
	// Test with a known string
	data := []byte("hello")
	hashBytes := sha512.Sum512(data)
	b64 := base64.StdEncoding.EncodeToString(hashBytes[:])
	integrity := "sha512-" + b64

	if !IsValidIntegrityHash(integrity) {
		t.Errorf("Expected valid hash for %q, got false", integrity)
	}

	// Test with empty string
	data = []byte{}
	hashBytes = sha512.Sum512(data)
	b64 = base64.StdEncoding.EncodeToString(hashBytes[:])
	integrity = "sha512-" + b64

	if !IsValidIntegrityHash(integrity) {
		t.Errorf("Expected valid hash for empty string, got false")
	}

	// Test with invalid hash
	if IsValidIntegrityHash("sha512-invalid") {
		t.Error("Expected invalid hash to return false")
	}
	if IsValidIntegrityHash("sha512-") {
		t.Error("Expected empty hash to return false")
	}
	if IsValidIntegrityHash("") {
		t.Error("Expected empty string to return false")
	}
}