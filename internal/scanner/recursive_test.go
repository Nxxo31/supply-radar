package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

// fixtureMonorepoPath returns the testdata path for the polyglot monorepo fixture.
// It uses runtime.Caller so the tests run from any working directory (Go test
// invokes binaries from the package dir, but CI sometimes cds elsewhere).
func fixtureMonorepoPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	pkgDir := filepath.Dir(thisFile)
	return filepath.Join(pkgDir, "..", "..", "tests", "fixtures", "monorepo")
}

// TestScan_Recursive_PolyglotMonorepo verifies the recursive scan finds deps
// in all four subprojects across three ecosystems (go-mod, npm, pypi) and
// reports the project ecosystem as "multi".
func TestScan_Recursive_PolyglotMonorepo(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Path = fixtureMonorepoPath(t)
	cfg.Recursive = true
	cfg.Offline = true
	cfg.CacheTTL = time.Hour
	cfg.ToolVersion = "test"

	result, err := Scan(cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result is nil")
	}

	// We expect dependencies across the four subprojects:
	//   services/api-gateway:      go.mod with 2 deps (mux, logrus)
	//   services/web-frontend:     package.json with 2 deps (express, lodash)
	//   services/auth-service:      requirements.txt with 2 deps (flask, requests)
	//   packages/shared-utils:      go.mod with 2 deps (testify, x/net)
	// Total expected: 8 dependencies.
	if got := len(result.Analysis.Dependencies); got != 8 {
		t.Errorf("Expected 8 dependencies across the monorepo, got %d", got)
		for _, d := range result.Analysis.Dependencies {
			t.Logf("  dep: %s @ %s", d.ID, d.Path)
		}
	}

	// The recursive scan should report a "multi" ecosystem label because
	// we discovered more than one ecosystem.
	if got := result.Analysis.Project.Ecosystem; got != "multi" {
		t.Errorf("Expected project ecosystem 'multi' for polyglot monorepo, got %q", got)
	}

	// Verify each ecosystem was actually exercised by collecting unique ecosystems.
	ecoSet := make(map[string]struct{})
	for _, d := range result.Analysis.Dependencies {
		ecoSet[d.Ecosystem] = struct{}{}
	}
	if len(ecoSet) != 3 {
		t.Errorf("Expected 3 distinct ecosystems in the monorepo (go, npm, pypi), got %d: %v", len(ecoSet), ecoSet)
	}
}

// TestScan_Recursive_SkipsVendorDirs confirms the pruner prevents scanning
// inside node_modules, vendor, .git, and build outputs. We plant a decoy
// manifest inside a node_modules folder of a tmp dir and assert the recursive
// scan does not pick it up.
func TestScan_Recursive_SkipsVendorDirs(t *testing.T) {
	root := t.TempDir()

	// Real subproject at root — must be detected so the scan does not error.
	if err := writeSubfile(filepath.Join(root, "services", "primary", "go.mod"), "module example\n\ngo 1.23\n\nrequire (\n\tgithub.com/foo/bar v1.0.0\n)\n"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Decoy manifest inside node_modules — must NEVER be picked up.
	if err := writeSubfile(filepath.Join(root, "services", "primary", "node_modules", "evil", "package.json"),
		`{"name":"evil-should-be-skipped","dependencies":{"hax":"1.0.0"}}`); err != nil {
		t.Fatalf("setup node_modules: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Path = root
	cfg.Recursive = true
	cfg.Offline = true
	cfg.ToolVersion = "test"

	result, err := Scan(cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	for _, d := range result.Analysis.Dependencies {
		if d.Name == "hax" {
			t.Errorf("Recursive scan leaked into node_modules: picked up %q from %s", d.Name, d.Path)
		}
	}
}

// TestScan_Recursive_KeepsDuplicateDepsAcrossSubprojects ensures two subprojects
// declaring the same dependency (e.g. the same Go module) are counted
// independently — the dedup key is ID@Path, and the paths differ per service.
func TestScan_Recursive_KeepsDuplicateDepsAcrossSubprojects(t *testing.T) {
	root := t.TempDir()

	// Two services both depending on gorilla/mux v1.8.1.
	if err := writeSubfile(filepath.Join(root, "svc-a", "go.mod"), "module example/a\n\ngo 1.23\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.1\n)\n"); err != nil {
		t.Fatalf("setup a: %v", err)
	}
	if err := writeSubfile(filepath.Join(root, "svc-b", "go.mod"), "module example/b\n\ngo 1.23\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.1\n)\n"); err != nil {
		t.Fatalf("setup b: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Path = root
	cfg.Recursive = true
	cfg.Offline = true
	cfg.ToolVersion = "test"

	result, err := Scan(cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Both occurrences of gorilla/mux must survive deduplication because their
	// Path fields differ. gather the distinct paths for that dep.
	muxPaths := make(map[string]struct{})
	for _, d := range result.Analysis.Dependencies {
		if d.Name == "github.com/gorilla/mux" {
			muxPaths[d.Path] = struct{}{}
		}
	}
	if len(muxPaths) != 2 {
		t.Errorf("Expected gorilla/mux at 2 distinct subproject paths, got %d: %v", len(muxPaths), muxPaths)
	}
}

// TestScan_NonRecursive_PreservesSingleEcosystem confirms the non-recursive
// path still reports a single ecosystem (regression guard for the refactor
// that introduced detectedEcosystems).
func TestScan_NonRecursive_PreservesSingleEcosystem(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Path = fixturePath(t, "go/real-app")
	cfg.ToolVersion = "test"
	cfg.Offline = true
	cfg.CacheTTL = time.Hour

	result, err := Scan(cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if want, got := "go-mod", result.Analysis.Project.Ecosystem; got != want {
		t.Errorf("Non-recursive scan should report the single detected ecosystem; got %q want %q", got, want)
	}
}

// TestShouldSkipDir exercises the vendor/prune list so adding a new entry does
// not silently change behaviour. We assert both the prune set and the negatives
// (directories that must still be walked).
func TestShouldSkipDir(t *testing.T) {
	skip := []string{
		"node_modules", "vendor",
		".git", ".hg", ".svn",
		"dist", "build", "target", ".next", ".cache",
	}
	for _, name := range skip {
		if !shouldSkipDir(name) {
			t.Errorf("shouldSkipDir(%q) = false, want true", name)
		}
	}

	keep := []string{"src", "services", "packages", "apps", "lib", "cmd", "internal", "tests"}
	for _, name := range keep {
		if shouldSkipDir(name) {
			t.Errorf("shouldSkipDir(%q) = true, want false", name)
		}
	}
}

// TestResolveEcosystemLabel pins the label-collapse rules used in the run
// metadata. In particular the recursive multi-ecosystem case must report
// "multi" so downstream report consumers can branch on it.
func TestResolveEcosystemLabel(t *testing.T) {
	tests := []struct {
		name      string
		found     map[string]struct{}
		recursive bool
		fallback  string
		want      string
	}{
		{name: "non-recursive uses fallback", found: map[string]struct{}{"go-mod": {}}, recursive: false, fallback: "go-mod", want: "go-mod"},
		{name: "non-recursive empty fallback falls back to set", found: map[string]struct{}{"npm": {}}, recursive: false, fallback: "", want: "npm"},
		{name: "non-recursive empty everything", found: map[string]struct{}{}, recursive: false, fallback: "", want: ""},
		{name: "recursive single ecosystem", found: map[string]struct{}{"pypi": {}}, recursive: true, fallback: "", want: "pypi"},
		{name: "recursive multi-ecosystem collapses to 'multi'", found: map[string]struct{}{"go-mod": {}, "npm": {}, "pypi": {}}, recursive: true, fallback: "", want: "multi"},
		{name: "recursive empty", found: map[string]struct{}{}, recursive: true, fallback: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveEcosystemLabel(tt.found, tt.recursive, tt.fallback)
			if got != tt.want {
				t.Errorf("resolveEcosystemLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestScan_Recursive_DetectedEcosystemsSortedByEcosystemName verifies the
// recursive scan actually exercises every parser type available. We don't
// assert the value of the detected ecosystem label but the set of ecosystems
// among the deps, which validates the recursion across parser boundaries.
func TestScan_Recursive_DetectedEcosystemsSortedByEcosystemName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Path = fixtureMonorepoPath(t)
	cfg.Recursive = true
	cfg.Offline = true
	cfg.ToolVersion = "test"

	result, err := Scan(cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	got := make([]string, 0)
	seen := make(map[string]struct{})
	for _, d := range result.Analysis.Dependencies {
		if _, ok := seen[d.Ecosystem]; !ok {
			seen[d.Ecosystem] = struct{}{}
			got = append(got, d.Ecosystem)
		}
	}
	sort.Strings(got)

	want := []string{"go", "npm", "pypi"}
	if len(got) != len(want) {
		t.Fatalf("Expected %d ecosystems, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Ecosystem[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// writeSubfile is a tiny helper to write a file inside a t.TempDir subpath,
// creating any parent directories required. It keeps the recursive test cases
// readable.
func writeSubfile(path string, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
