package gomod

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testdata(t *testing.T) string {
	// testdata/ is next to the parser source files.
	_, thisFile, _, _ := runtime.Caller(0)
	// internal/parser/gomod/parser_test.go -> internal/parser/gomod/
	pkgDir := filepath.Dir(thisFile)
	return filepath.Join(pkgDir, "testdata")
}

func TestParser_Detect(t *testing.T) {
	p := New()
	fixture := testdata(t)

	detected, manifest := p.Detect(fixture)
	if !detected {
		t.Errorf("Expected to detect go.mod in %s", fixture)
	}
	if manifest == "" {
		t.Error("Expected manifest path to be non-empty")
	}
	expectedManifest := filepath.Join(fixture, "go.mod")
	if manifest != expectedManifest {
		t.Errorf("Expected manifest %s, got %s", expectedManifest, manifest)
	}
}

func TestParser_Parse(t *testing.T) {
	p := New()
	fixture := testdata(t)

	deps, err := p.Parse(fixture)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) == 0 {
		t.Fatal("Expected at least one dependency")
	}

	// Should have both direct and indirect.
	directCount := 0
	indirectCount := 0
	for _, dep := range deps {
		if dep.Ecosystem != "go" {
			t.Errorf("Expected ecosystem 'go', got '%s'", dep.Ecosystem)
		}
		if dep.ID == "" {
			t.Error("Dependency ID should not be empty")
		}
		if dep.Path == "" {
			t.Error("Dependency Path should not be empty")
		}
		if dep.Direct {
			directCount++
		} else {
			indirectCount++
		}
	}

	if directCount == 0 {
		t.Error("Expected at least one direct dependency")
	}
	if indirectCount == 0 {
		t.Error("Expected at least one indirect dependency")
	}
}

func TestParser_ParseInlineRequire(t *testing.T) {
	// Create a temp go.mod with inline require syntax.
	tmpDir := t.TempDir()
	goModContent := `module testinline

go 1.23

require github.com/stretchr/testify v1.9.0

require golang.org/x/crypto v0.21.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatal(err)
	}

	p := New()
	deps, err := p.Parse(tmpDir)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) < 2 {
		t.Errorf("Expected at least 2 deps, got %d", len(deps))
	}
}

func TestParser_NotFound(t *testing.T) {
	p := New()
	detected, _ := p.Detect("/tmp")
	if detected {
		t.Error("Should not detect go.mod in /tmp")
	}
}

func TestParser_NonExistent(t *testing.T) {
	p := New()
	_, err := p.Parse("/nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
}

func TestGoDepID(t *testing.T) {
	fixture := testdata(t)
	p := New()
	deps, _ := p.Parse(fixture)

	for _, dep := range deps {
		if len(dep.ID) < 5 {
			t.Errorf("ID too short: %s", dep.ID)
		}
		if len(dep.ID) < 3 || dep.ID[:3] != "go:" {
			t.Errorf("ID should start with 'go:', got: %s", dep.ID)
		}
	}
}

func TestParser_MultipleRequireBlocks(t *testing.T) {
	tmpDir := t.TempDir()
	goModContent := `module test

go 1.23

require (
	github.com/foo/bar v1.0.0
)

require (
	github.com/baz/qux v2.0.0 // indirect
	github.com/aaa/zzz v3.0.0
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatal(err)
	}

	p := New()
	deps, err := p.Parse(tmpDir)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 3 {
		t.Errorf("Expected 3 deps, got %d", len(deps))
	}

	// Verify indirect detection.
	for _, d := range deps {
		if d.Name == "github.com/baz/qux" && d.Direct {
			t.Error("baz/qux should be indirect")
		}
	}
}

func TestParser_VersionPrefixoStripped(t *testing.T) {
	tmpDir := t.TempDir()
	goModContent := `module test

go 1.23

require github.com/foo/bar v1.2.3
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatal(err)
	}

	p := New()
	deps, _ := p.Parse(tmpDir)

	for _, d := range deps {
		if d.Version == "v1.2.3" {
			t.Error("Version prefix 'v' should be stripped for OSV compat")
		}
		if d.Version != "1.2.3" {
			t.Errorf("Expected version 1.2.3, got %s", d.Version)
		}
	}
}
