package markdown

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

func TestReporter_Name(t *testing.T) {
	r := New()
	if r.Name() != "markdown" {
		t.Errorf("Name() = %q, want %q", r.Name(), "markdown")
	}
}

func TestReporter_Generate_NoVulnerabilities(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{
			Name:      "test-project",
			Path:      "/test/path",
			Ecosystem: "npm",
		},
		ToolVersion: "v1.0.0",
		Timestamp:   time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Duration:    2500 * time.Millisecond,
		Summary: dependency.RiskSummary{
			TotalDependencies: 10,
			VulnerableDeps:    0,
			TotalVulns:        0,
		},
		RiskScore: 0.0,
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Check header.
	if !strings.Contains(output, "# supply-radar security report") {
		t.Error("Expected report header")
	}

	// Check no vulnerabilities message.
	if !strings.Contains(output, "No vulnerabilities detected") {
		t.Error("Expected 'No vulnerabilities detected' message")
	}

	// Check summary values.
	if !strings.Contains(output, "| Total dependencies | 10 |") {
		t.Errorf("Expected total dependencies 10 in output:\n%s", output)
	}
	if !strings.Contains(output, "| Vulnerable deps | 0 |") {
		t.Errorf("Expected vulnerable deps 0 in output:\n%s", output)
	}
}

func TestReporter_Generate_WithVulnerabilities(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{
			Name:      "my-app",
			Path:      "/projects/my-app",
			Ecosystem: "go",
		},
		ToolVersion: "v1.1.0",
		Timestamp:   time.Date(2024, 6, 20, 14, 0, 0, 0, time.UTC),
		Duration:    500 * time.Millisecond,
		Summary: dependency.RiskSummary{
			TotalDependencies: 5,
			VulnerableDeps:    1,
			TotalVulns:        2,
			Critical:          1,
			High:              0,
			Medium:            1,
			Low:               0,
		},
		RiskScore: 7.5,
		Dependencies: []dependency.Dependency{
			{
				ID:        "go:github.com/vulnerable/pkg@v1.0.0",
				Name:      "github.com/vulnerable/pkg",
				Version:   "1.0.0",
				Ecosystem: "go",
				Path:      "/projects/my-app/go.mod",
				Direct:    true,
			},
		},
		Vulnerabilities: map[string][]dependency.Vulnerability{
			"go:github.com/vulnerable/pkg@v1.0.0": {
				{
					ID:       "GO-2024-0001",
					Title:    "Remote Code Execution",
					Severity: "CRITICAL",
					CVSS:     9.8,
					FixedIn:  "1.1.0",
				},
				{
					ID:       "GO-2024-0002",
					Title:    "SQL Injection",
					Severity: "MEDIUM",
					CVSS:     6.5,
					FixedIn:  "1.0.5",
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Check metadata.
	if !strings.Contains(output, "| Project | my-app |") {
		t.Errorf("Expected project name my-app:\n%s", output)
	}
	if !strings.Contains(output, "| Ecosystem | go |") {
		t.Errorf("Expected ecosystem go:\n%s", output)
	}
	if !strings.Contains(output, "| **Risk score** | **7.5/10** |") {
		t.Errorf("Expected **Risk score** **7.5/10**:\n%s", output)
	}

	// Check severity counts.
	if !strings.Contains(output, "| Critical | 1 |") {
		t.Errorf("Expected Critical 1:\n%s", output)
	}
	if !strings.Contains(output, "| Medium | 1 |") {
		t.Errorf("Expected Medium 1:\n%s", output)
	}

	// Check dependency section.
	if !strings.Contains(output, "### github.com/vulnerable/pkg") {
		t.Errorf("Expected dependency section header:\n%s", output)
	}

	// Check vulnerability table headers.
	if !strings.Contains(output, "| ID | Title | Severity | CVSS |") {
		t.Errorf("Expected vuln table headers:\n%s", output)
	}

	// Check vuln rows.
	if !strings.Contains(output, "| GO-2024-0001 |") {
		t.Errorf("Expected vuln ID GO-2024-0001:\n%s", output)
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Errorf("Expected CRITICAL severity in output:\n%s", output)
	}
	if !strings.Contains(output, "9.8") {
		t.Errorf("Expected CVSS 9.8 in output:\n%s", output)
	}
	if !strings.Contains(output, "| 1.1.0 |") {
		t.Errorf("Expected fixed version in output:\n%s", output)
	}
}

func TestReporter_Generate_SortBySeverity(t *testing.T) {
	r := New()

	deps := []dependency.Dependency{
		{ID: "go:low@1.0.0", Name: "low", Version: "1.0.0", Direct: true},
		{ID: "go:high@1.0.0", Name: "high", Version: "1.0.0", Direct: true},
		{ID: "go:critical@1.0.0", Name: "critical", Version: "1.0.0", Direct: true},
	}

	vulns := map[string][]dependency.Vulnerability{
		"go:low@1.0.0":      {{ID: "V1", Severity: "LOW", Title: "Low"}},
		"go:high@1.0.0":     {{ID: "V2", Severity: "HIGH", Title: "High"}},
		"go:critical@1.0.0": {{ID: "V3", Severity: "CRITICAL", Title: "Critical"}},
	}

	result := dependency.AnalysisResult{
		Project: dependency.Project{
			Name:      "test",
			Path:      "/test",
			Ecosystem: "go",
		},
		ToolVersion: "v1.0.0",
		Timestamp:   time.Now(),
		Duration:    time.Second,
		Summary: dependency.RiskSummary{
			TotalDependencies: 3,
			VulnerableDeps:    3,
			TotalVulns:        3,
			Critical:          1,
			High:              1,
			Low:               1,
		},
		RiskScore:       5.0,
		Dependencies:    deps,
		Vulnerabilities: vulns,
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	output := buf.String()

	// Critical should appear before High and Low.
	ci := strings.Index(output, "### critical")
	hi := strings.Index(output, "### high")
	li := strings.Index(output, "### low")

	if ci > hi || hi > li {
		t.Errorf("Vulns not sorted by severity (critical->high->low):\n%s", output)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		max      int
		expected string
	}{
		// Strings that fit within max are returned unchanged.
		{"short", 10, "short"},
		{"abc", 3, "abc"}, // len=3 <= max=3, no truncation
		// Pipe escaping always happens first.
		{"pipe|char", 10, "pipe\\|char"},
		// Newline conversion.
		{"multi\nline", 20, "multi line"},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.expected)
		}
	}
}

func TestTruncate_EdgeCases(t *testing.T) {
	// Test truncation actually happens for long strings.
	// len=65 > max=60, so should return s[:59] + "..."
	long := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 65 a's
	got := truncate(long, 60)
	if len(got) != 62 { // 59 + "..."
		t.Errorf("truncate 65-char string: got len %d, want 62", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncate should end with ..., got %q", got)
	}
}

func TestYesNo(t *testing.T) {
	if yesNo(true) != "yes" {
		t.Error("yesNo(true) should be 'yes'")
	}
	if yesNo(false) != "no (indirect)" {
		t.Error("yesNo(false) should be 'no (indirect)'")
	}
}
