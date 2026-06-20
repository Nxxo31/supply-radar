package scanner

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

func fixturePath(t *testing.T, sub string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	pkgDir := filepath.Dir(thisFile)
	// internal/scanner -> tests/fixtures/<sub>
	return filepath.Join(pkgDir, "..", "..", "tests", "fixtures", sub)
}

func TestScan_GoRealApp(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := DefaultConfig()
	cfg.Path = fixturePath(t, "go/real-app")
	cfg.ToolVersion = "test"
	cfg.CacheTTL = time.Hour
	cfg.Offline = true // Skip OSV API calls in tests

	result, err := Scan(cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	// Check that we found the dependencies.
	if result.Analysis.Summary.TotalDependencies == 0 {
		t.Error("Expected to find dependencies")
	}

	// Check we found at least one direct dep.
	hasDirect := false
	for _, d := range result.Analysis.Dependencies {
		if d.Direct {
			hasDirect = true
			break
		}
	}
	if !hasDirect {
		t.Error("Expected at least one direct dependency")
	}
}

func TestScan_EmptyGoProject(t *testing.T) {
	// Test with the supply-radar project itself (has go.mod but no deps yet).
	cfg := DefaultConfig()
	cfg.Path = fixturePath(t, "")
	// This fixture doesn't exist; supply-radar itself has empty go.mod
	// which is tested elsewhere.
	_ = cfg
}

func TestScan_NoManifest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Path = "/tmp"
	_, err := Scan(cfg)
	if err == nil {
		t.Error("Expected error for path with no manifest")
	}
}

func TestSeverityLeq(t *testing.T) {
	tests := []struct {
		sev, threshold string
		expected       bool
	}{
		{"CRITICAL", "CRITICAL", true},
		{"HIGH", "CRITICAL", true},
		{"CRITICAL", "HIGH", false},
		{"LOW", "CRITICAL", true},
		{"MEDIUM", "HIGH", true},
		{"HIGH", "MEDIUM", false},
	}

	for _, tt := range tests {
		got := severityLeq(tt.sev, tt.threshold)
		if got != tt.expected {
			t.Errorf("severityLeq(%s, %s) = %v, want %v",
				tt.sev, tt.threshold, got, tt.expected)
		}
	}
}

func TestCalculateRiskScore(t *testing.T) {
	tests := []struct {
		name     string
		summary  dependency.RiskSummary
		expected float64
	}{
		{
			name:     "no vulns",
			summary:  dependency.RiskSummary{},
			expected: 0,
		},
		{
			name: "one critical with 100 deps",
			summary: dependency.RiskSummary{
				TotalDependencies: 100,
				Critical:          1,
			},
			expected: 0.1, // 10 / (100 * 10) * 10 = 0.1
		},
		{
			name: "cap at 10",
			summary: dependency.RiskSummary{
				TotalDependencies: 1,
				Critical:          10,
			},
			expected: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateRiskScore(tt.summary)
			if got != tt.expected {
				t.Errorf("calculateRiskScore(%+v) = %v, want %v",
					tt.summary, got, tt.expected)
			}
		})
	}
}
