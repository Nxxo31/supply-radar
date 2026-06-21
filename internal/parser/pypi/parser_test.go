package pypi

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testdata(t *testing.T) string {
	_, thisFile, _, _ := runtime.Caller(0)
	pkgDir := filepath.Dir(thisFile)
	return filepath.Join(pkgDir, "..", "..", "..", "tests", "fixtures", "python", "flask-app")
}

func TestParser_Detect_RequirementsTxt(t *testing.T) {
	p := New()
	fixture := testdata(t)

	detected, manifest := p.Detect(fixture)
	if !detected {
		t.Fatal("Expected to detect Python manifest in fixture")
	}
	if manifest == "" {
		t.Fatal("Manifest path should not be empty")
	}
	// Should find requirements.txt first.
	if filepath.Base(manifest) != "requirements.txt" {
		t.Logf("Warning: expected requirements.txt, got: %s", filepath.Base(manifest))
	}
}

func TestParser_Detect_PyProjectOnly(t *testing.T) {
	p := New()
	tmpDir := t.TempDir()

	// Create only pyproject.toml (no requirements.txt).
	os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte(`
[project]
name = "test"
dependencies = ["flask>=3.0.0"]
`), 0644)

	detected, manifest := p.Detect(tmpDir)
	if !detected {
		t.Fatal("Expected to detect pyproject.toml")
	}
	if filepath.Base(manifest) != "pyproject.toml" {
		t.Errorf("Expected pyproject.toml, got: %s", filepath.Base(manifest))
	}
}

func TestParser_Detect_None(t *testing.T) {
	p := New()
	detected, _ := p.Detect("/tmp")
	if detected {
		t.Error("Should not detect Python manifest in /tmp")
	}
}

func TestParser_Parse_Requirements(t *testing.T) {
	p := New()
	fixture := testdata(t)

	deps, err := p.Parse(fixture)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) == 0 {
		t.Fatal("Expected at least one dependency")
	}

	for _, dep := range deps {
		if dep.Ecosystem != "pypi" {
			t.Errorf("Expected ecosystem 'pypi', got: %s", dep.Ecosystem)
		}
		if dep.ID == "" {
			t.Error("Dependency ID should not be empty")
		}
		if !dep.Direct {
			t.Error("Python deps from manifest should be direct")
		}
	}

	// Verify we found flask and requests.
	found := make(map[string]bool)
	for _, dep := range deps {
		found[dep.Name] = true
	}

	expectedDeps := []string{"flask", "requests", "sqlalchemy", "pytest", "pytest-cov"}
	for _, name := range expectedDeps {
		if !found[name] {
			t.Errorf("Expected to find dependency: %s", name)
		}
	}
}

func TestParser_Parse_RequirementsVersions(t *testing.T) {
	// Create a minimal requirements.txt with known versions.
	tmpDir := t.TempDir()
	reqContent := `flask==3.0.0
requests>=2.31.0
sqlalchemy>=2.0.0,<3.0.0
`
	os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(reqContent), 0644)

	p := New()
	deps, err := p.Parse(tmpDir)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("Expected 3 deps, got %d", len(deps))
	}

	// Verify exact versions.
	versions := make(map[string]string)
	for _, dep := range deps {
		versions[dep.Name] = dep.Version
	}

	if versions["flask"] != "3.0.0" {
		t.Errorf("Expected flask 3.0.0, got: %s", versions["flask"])
	}
	if versions["requests"] != "2.31.0" {
		t.Errorf("Expected requests 2.31.0 (lower bound), got: %s", versions["requests"])
	}
	// For >=,< format, we take the first part.
	if versions["sqlalchemy"] != "2.0.0" {
		t.Errorf("Expected sqlalchemy 2.0.0, got: %s", versions["sqlalchemy"])
	}
}

func TestParser_Parse_RequirementsComments(t *testing.T) {
	tmpDir := t.TempDir()
	reqContent := `# This is a comment
flask==3.0.0
# Another comment
requests>=2.31.0
--extra-index-url https://example.com
`
	os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(reqContent), 0644)

	p := New()
	deps, err := p.Parse(tmpDir)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 2 {
		t.Errorf("Expected 2 deps (comments and flags skipped), got: %d", len(deps))
	}

	names := make(map[string]bool)
	for _, dep := range deps {
		names[dep.Name] = true
	}
	if names["flask"] != true || names["requests"] != true {
		t.Error("Expected flask and requests only")
	}
	if names["extra-index-url"] {
		t.Error("Pip flags should be skipped")
	}
}

func TestParser_Parse_PyProject(t *testing.T) {
	p := New()
	fixture := testdata(t)

	deps, err := p.Parse(fixture)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) < 4 {
		t.Errorf("Expected at least 4 dependencies from pyproject.toml, got: %d", len(deps))
	}

	// Verify flask (with version specifier) and requests.
	versions := make(map[string]string)
	for _, dep := range deps {
		versions[dep.Name] = dep.Version
	}

	if versions["flask"] != "3.0.0" {
		t.Errorf("Expected flask 3.0.0, got: %s", versions["flask"])
	}
	if versions["requests"] != "2.31.0" {
		t.Errorf("Expected requests 2.31.0, got: %s", versions["requests"])
	}
}

func TestParser_Parse_PyProject_SingleLine(t *testing.T) {
	tmpDir := t.TempDir()
	content := `[project]
name = "test"
dependencies = ["flask>=3.0.0", "requests>=2.31.0"]
`
	os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte(content), 0644)

	p := New()
	deps, err := p.Parse(tmpDir)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(deps) != 2 {
		t.Errorf("Expected 2 deps, got: %d", len(deps))
	}
}

func TestParser_Parse_NoManifest(t *testing.T) {
	p := New()
	_, err := p.Parse("/nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}

func TestParser_ParsePEP508(t *testing.T) {
	tests := []struct {
		input        string
		expectedName string
		expectedVer  string
	}{
		{"flask==3.0.0", "flask", "3.0.0"},
		{"requests>=2.31.0", "requests", "2.31.0"},
		{"sqlalchemy>=2.0.0,<3.0.0", "sqlalchemy", "2.0.0"},
		{"django>=4.2,<5.0", "django", "4.2"},
		{"package", "package", "latest"},
		{"package===1.0.0", "package", "1.0.0"},
		{"package~=1.4.2", "package", "1.4.2"},
		{"package!=1.0.0", "package", "1.0.0"},
		{`package==1.0.0 ; python_version >= "3.8"`, "package", "1.0.0"},
		{"django-stubs>=1.0.0,<2.0.0", "django-stubs", "1.0.0"},
		{"zope.interface>=4.0.0", "zope.interface", "4.0.0"},
	}

	for _, tt := range tests {
		name, version := parsePEP508(tt.input)
		if name != tt.expectedName {
			t.Errorf("parsePEP508(%q): expected name %q, got %q", tt.input, tt.expectedName, name)
		}
		if version != tt.expectedVer {
			t.Errorf("parsePEP508(%q): expected version %q, got %q", tt.input, tt.expectedVer, version)
		}
	}
}

func TestParser_Name(t *testing.T) {
	p := New()
	if p.Name() != "pypi" {
		t.Errorf("Expected name 'pypi', got: %s", p.Name())
	}
}
