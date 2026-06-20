package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParse_Detect(t *testing.T) {
	p := New()

	// Temp dir with package.json
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatal(err)
	}

	detected, manifest := p.Detect(dir)
	if !detected {
		t.Error("Expected to detect package.json")
	}
	if manifest == "" {
		t.Error("Expected manifest path to be non-empty")
	}
}

func TestParse_BasicDeps(t *testing.T) {
	p := New()
	dir := t.TempDir()
	pkg := map[string]interface{}{
		"name":    "test-pkg",
		"version": "1.0.0",
		"dependencies": map[string]string{
			"express":  "4.18.2",
			"lodash":   "^4.17.21",
			"axios":    "~0.27.2",
			"minimist": "1.2.5",
		},
		"devDependencies": map[string]string{
			"jest":    "^29.7.0",
			"ts-jest": "~29.1.0",
		},
	}
	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := p.Parse(dir)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 6 {
		t.Fatalf("Expected 6 deps (4 direct + 2 dev), got %d", len(deps))
	}

	// Check version cleaning (^ ~ removed)
	for _, dep := range deps {
		if dep.ID == "" {
			t.Error("Dep ID should not be empty")
		}
		if dep.Ecosystem != "npm" {
			t.Errorf("Expected ecosystem npm, got %s", dep.Ecosystem)
		}
	}

	// Check lodash version was cleaned (^4.17.21 -> 4.17.21)
	for _, dep := range deps {
		if dep.Name == "lodash" && dep.Version != "4.17.21" {
			t.Errorf("Expected lodash version 4.17.21, got %s", dep.Version)
		}
	}

	// Check devDep has proper ID prefix
	hasDev := false
	for _, dep := range deps {
		if dep.Name == "jest" {
			hasDev = true
			break
		}
	}
	if !hasDev {
		t.Error("Expected jest (dev dependency) to be included")
	}
}

func TestParse_EmptyDeps(t *testing.T) {
	p := New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"empty"}`), 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := p.Parse(dir)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("Expected 0 deps for empty package.json, got %d", len(deps))
	}
}

func TestParse_NonExistent(t *testing.T) {
	p := New()
	_, err := p.Parse("/nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
}

func TestParse_NoPackageJSON(t *testing.T) {
	p := New()
	dir := t.TempDir()
	detected, _ := p.Detect(dir)
	if detected {
		t.Error("Should not detect package.json in empty dir")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	p := New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{invalid}`), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := p.Parse(dir)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}
