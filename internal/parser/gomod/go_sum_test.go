package gomod

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

func TestParseGoSum_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	// Use valid base64 SHA-256 hashes (44 base64 chars for 32 bytes)
	goSumContent := `github.com/foo/bar v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
github.com/foo/bar v1.0.0/go.mod h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
github.com/baz/qux v2.0.0 h1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
`

	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(goSumContent), 0644); err != nil {
		t.Fatal(err)
	}

	versions, err := ParseGoSum(tmpDir)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(versions) != 2 {
		t.Fatalf("Expected 2 versions from go.sum, got %d", len(versions))
	}

	if versions["github.com/foo/bar"] != "v1.0.0" {
		t.Errorf("Expected github.com/foo/bar v1.0.0, got %s", versions["github.com/foo/bar"])
	}

	if versions["github.com/baz/qux"] != "v2.0.0" {
		t.Errorf("Expected github.com/baz/qux v2.0.0, got %s", versions["github.com/baz/qux"])
	}
}

func TestParseGoSum_NoGoSum(t *testing.T) {
	tmpDir := t.TempDir()

	versions, err := ParseGoSum(tmpDir)
	if err != nil {
		t.Fatalf("ParseGoSum should return no error for missing go.sum, got: %v", err)
	}

	if len(versions) != 0 {
		t.Errorf("Expected empty map, got %d entries", len(versions))
	}
}

func TestGoSumExists(t *testing.T) {
	tmpDir := t.TempDir()

	// No go.sum
	if GoSumExists(tmpDir) {
		t.Error("Expected GoSumExists to be false for missing file")
	}

	// Create go.sum
	os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte{}, 0644)

	if !GoSumExists(tmpDir) {
		t.Error("Expected GoSumExists to be true for existing file")
	}
}

func TestResolveVersionsWithGoSum(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal go.sum with valid base64
	goSumContent := `github.com/fizz/buzz v3.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(goSumContent), 0644); err != nil {
		t.Fatal(err)
	}

	deps := []dependency.Dependency{
		{
			ID:        "go:github.com/fizz/buzz@latest",
			Name:      "github.com/fizz/buzz",
			Version:   "latest",
			Ecosystem: "go",
			Path:      "/tmp/test",
			Direct:    true,
		},
	}

	resolved, err := ResolveVersionsWithGoSum(deps, tmpDir)
	if err != nil {
		t.Fatalf("ResolveVersionsWithGoSum failed: %v", err)
	}

	if len(resolved) != 1 {
		t.Fatalf("Expected 1 resolved dep, got %d", len(resolved))
	}

	if resolved[0].Version != "v3.0.0" {
		t.Errorf("Expected version v3.0.0, got %s", resolved[0].Version)
	}
}

func TestResolveVersionsWithGoSum_Fallback(t *testing.T) {
	tmpDir := t.TempDir()

	deps := []dependency.Dependency{
		{
			ID:        "go:github.com/test/old@v1.0.0",
			Name:      "github.com/test/old",
			Version:   "v1.0.0",
			Ecosystem: "go",
			Path:      "/tmp/test",
			Direct:    true,
		},
	}

	resolved, err := ResolveVersionsWithGoSum(deps, tmpDir)
	if err != nil {
		t.Fatalf("ResolveVersionsWithGoSum failed: %v", err)
	}

	if len(resolved) != 1 {
		t.Fatalf("Expected 1 dep, got %d", len(resolved))
	}
	if resolved[0].Version != "v1.0.0" {
		t.Errorf("Expected version to remain v1.0.0, got %s", resolved[0].Version)
	}
}
