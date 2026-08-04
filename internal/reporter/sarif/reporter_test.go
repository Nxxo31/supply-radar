package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

func TestReporter_Name(t *testing.T) {
	r := New()
	if r.Name() != "sarif" {
		t.Errorf("Expected name 'sarif', got: %s", r.Name())
	}
}

func TestReporter_Generate_EmptyVulns(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{
			Name:      "test-project",
			Path:      "/tmp/test",
			Ecosystem: "npm",
		},
		Dependencies:    []dependency.Dependency{},
		Vulnerabilities: map[string][]dependency.Vulnerability{},
		Summary:         dependency.RiskSummary{TotalDependencies: 0},
		RiskScore:       0,
		Timestamp:       time.Now(),
		Duration:        0,
		ToolVersion:     "v0.1.0",
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "$schema") {
		t.Error("Output should contain $schema field")
	}
	// The canonical SARIF 2.1.0 schema location is schemastore.org — the
	// legacy oasis-tcs master/Schemata URL was broken by a branch rename
	// (oasis-tcs/sarif-spec#646) and GitHub Code Scanning resolves against
	// schemastore.org. Both URLs contain "sarif" + "2.1.0"; assert on the
	// canonical identifier fragments rather than a brittle full-URL match.
	if !strings.Contains(out, "sarif-2.1.0.json") {
		t.Error("Output should reference the SARIF 2.1.0 schema (sarif-2.1.0.json)")
	}
	if !strings.Contains(out, "supply-radar") {
		t.Error("Output should mention supply-radar")
	}
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Error("Output should contain SARIF version 2.1.0")
	}
}

// TestReporter_Generate_EmptyVulns_OmitsRulesAndResults asserts that when the
// analysis finds no vulnerabilities, the SARIF output omits the "rules"
// field entirely (via omitempty on a nil slice) rather than serialising an
// empty array. This matches what GitHub Code Scanning expects; emitting
// "rules": [] triggers a schema-validation warning.
func TestReporter_Generate_EmptyVulns_OmitsRulesAndResults(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{
			Name:      "test-project",
			Path:      "/tmp/test",
			Ecosystem: "npm",
		},
		Dependencies:    []dependency.Dependency{},
		Vulnerabilities: map[string][]dependency.Vulnerability{},
		Summary:         dependency.RiskSummary{TotalDependencies: 0},
		RiskScore:       0,
		Timestamp:       time.Now(),
		Duration:        0,
		ToolVersion:     "v0.1.0",
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var parsed struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results          []json.RawMessage        `json:"results"`
			Invocations      []json.RawMessage        `json:"invocations"`
			AutomationDetails *struct {
				ID       string `json:"id"`
				Category string `json:"category"`
			} `json:"automationDetails"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v\nOutput: %s", err, buf.String())
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(parsed.Runs))
	}
	if len(parsed.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("Empty-vuln run should emit no rules, got %d", len(parsed.Runs[0].Tool.Driver.Rules))
	}
	if len(parsed.Runs[0].Results) != 0 {
		t.Errorf("Empty-vuln run should emit no results, got %d", len(parsed.Runs[0].Results))
	}
}

// TestReporter_InvocationsAndAutomationDetails verifies the run includes the
// two pieces of metadata GitHub Code Scanning needs: an invocation with
// endTimeUtc and executionSuccessful, and an automationDetails with the
// supply-radar run category. Without these the SARIF uploads but the alert
// run appears "unfinished" in the GitHub UI.
func TestReporter_InvocationsAndAutomationDetails(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{Name: "test", Path: "/tmp"},
		Dependencies: []dependency.Dependency{
			{ID: "test:1", Name: "test", Version: "1.0.0", Ecosystem: "npm", Path: "/tmp/package.json"},
		},
		Vulnerabilities: map[string][]dependency.Vulnerability{
			"test:1": {{ID: "TEST-1", Title: "Vuln", Severity: "HIGH", CVSS: 7.5}},
		},
		ToolVersion: "v1.0.0",
		Timestamp:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Duration:    250 * time.Millisecond,
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var parsed struct {
		Runs []struct {
			Invocations []struct {
				StartTimeUTC        string `json:"startTimeUtc"`
				EndTimeUTC          string `json:"endTimeUtc"`
				ExecutionSuccessful bool   `json:"executionSuccessful"`
			} `json:"invocations"`
			AutomationDetails *struct {
				ID       string `json:"id"`
				Category string `json:"category"`
			} `json:"automationDetails"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	if len(parsed.Runs[0].Invocations) != 1 {
		t.Fatalf("Expected exactly one invocation, got %d", len(parsed.Runs[0].Invocations))
	}
	inv := parsed.Runs[0].Invocations[0]
	if !inv.ExecutionSuccessful {
		t.Error("Invocation should report executionSuccessful=true")
	}
	if inv.StartTimeUTC != "2026-01-01T12:00:00Z" {
		t.Errorf("Expected startTimeUtc 2026-01-01T12:00:00Z, got %q", inv.StartTimeUTC)
	}
	if inv.EndTimeUTC != "2026-01-01T12:00:00.25Z" {
		t.Errorf("Expected endTimeUtc 2026-01-01T12:00:00.25Z (start+250ms), got %q", inv.EndTimeUTC)
	}
	if parsed.Runs[0].AutomationDetails == nil {
		t.Fatal("automationDetails must be present")
	}
	if got, want := parsed.Runs[0].AutomationDetails.Category, "supply-radar/scan"; got != want {
		t.Errorf("automationDetails.category = %q, want %q", got, want)
	}
	if !strings.HasPrefix(parsed.Runs[0].AutomationDetails.ID, "supply-radar/") {
		t.Errorf("automationDetails.id should be prefixed with 'supply-radar/', got %q", parsed.Runs[0].AutomationDetails.ID)
	}
}

// TestReporter_ZeroTimestampFallback confirms formatRFC3339 emits a valid
// RFC 3339 UTC string even when the analysis result has a zero timestamp
// (e.g. constructed in unit tests that omit time.Now()), so the SARIF output
// never violates the spec.
func TestReporter_ZeroTimestampFallback(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{Name: "zero-time-test", Path: "/tmp"},
		// Zero Timestamp + Zero Duration
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !strings.Contains(buf.String(), "1970-01-01T00:00:00Z") {
		t.Error("Zero timestamp should fall back to the Unix epoch RFC3339 string")
	}
}

func TestReporter_Generate_WithVulns(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{
			Name:      "express-app",
			Path:      "/tmp/express-app",
			Ecosystem: "npm",
		},
		Dependencies: []dependency.Dependency{
			{
				ID:        "npm:minimist@1.2.5",
				Name:      "minimist",
				Version:   "1.2.5",
				Ecosystem: "npm",
				Path:      "/tmp/express-app/package.json",
				Direct:    true,
			},
		},
		Vulnerabilities: map[string][]dependency.Vulnerability{
			"npm:minimist@1.2.5": {
				{
					ID:       "GHSA-xvch-5gv4-984h",
					Title:    "Prototype Pollution in minimist",
					Severity: "CRITICAL",
					CVSS:     9.8,
					FixedIn:  "1.2.6",
					References: []string{
						"https://github.com/advisories/GHSA-xvch-5gv4-984h",
					},
				},
			},
		},
		Summary: dependency.RiskSummary{
			TotalDependencies: 1,
			Critical:          1,
			TotalVulns:        1,
		},
		RiskScore:   10.0,
		Timestamp:   time.Now(),
		Duration:    time.Second,
		ToolVersion: "v0.1.0",
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify output parses as valid SARIF JSON
	var parsed struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message map[string]interface{}
			} `json:"results"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v\nOutput: %s", err, buf.String())
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got: %s", parsed.Version)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("Expected 1 run, got: %d", len(parsed.Runs))
	}
	if parsed.Runs[0].Tool.Driver.Name != "supply-radar" {
		t.Errorf("Expected driver name 'supply-radar', got: %s", parsed.Runs[0].Tool.Driver.Name)
	}
	if len(parsed.Runs[0].Results) != 1 {
		t.Fatalf("Expected 1 result, got: %d", len(parsed.Runs[0].Results))
	}

	r0 := parsed.Runs[0].Results[0]
	if r0.RuleID != "GHSA-xvch-5gv4-984h" {
		t.Errorf("Expected RuleID GHSA-xvch-5gv4-984h, got: %s", r0.RuleID)
	}
	if r0.Level != "error" { // CRITICAL maps to error
		t.Errorf("Expected level 'error' for CRITICAL severity, got: %s", r0.Level)
	}
}

func TestReporter_SeverityMapping(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{Name: "test", Path: "/tmp"},
		Dependencies: []dependency.Dependency{
			{ID: "test:1", Name: "test", Version: "1.0.0", Ecosystem: "npm", Path: "/tmp/package.json"},
		},
		Vulnerabilities: map[string][]dependency.Vulnerability{
			"test:1": {
				{ID: "TEST-1", Title: "Critical vuln", Severity: "CRITICAL", CVSS: 9.5, FixedIn: "1.0.1"},
				{ID: "TEST-2", Title: "High vuln", Severity: "HIGH", CVSS: 7.5, FixedIn: "1.0.1"},
				{ID: "TEST-3", Title: "Medium vuln", Severity: "MEDIUM", CVSS: 5.0, FixedIn: "1.0.1"},
				{ID: "TEST-4", Title: "Low vuln", Severity: "LOW", CVSS: 2.0, FixedIn: "1.0.1"},
				{ID: "TEST-5", Title: "Unknown vuln", Severity: "UNKNOWN", CVSS: 0, FixedIn: "1.0.1"},
			},
		},
		Summary:     dependency.RiskSummary{TotalVulns: 5},
		RiskScore:   5.0,
		ToolVersion: "v0.1.0",
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	var parsed struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	expectedLevels := map[string]string{
		"TEST-1": "error",
		"TEST-2": "error",
		"TEST-3": "warning",
		"TEST-4": "note",
		"TEST-5": "note",
	}

	results := parsed.Runs[0].Results
	if len(results) != 5 {
		t.Fatalf("Expected 5 results, got: %d", len(results))
	}

	// Sort by ID to match expected order
	resultLevels := make(map[string]string)
	for _, r := range results {
		resultLevels[r.RuleID] = r.Level
	}

	for id, expectedLevel := range expectedLevels {
		if got := resultLevels[id]; got != expectedLevel {
			t.Errorf("Expected level %s for vuln %s, got: %s", expectedLevel, id, got)
		}
	}
}

func TestReporter_WithFix(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{Name: "test", Path: "/tmp"},
		Dependencies: []dependency.Dependency{
			{ID: "test:1", Name: "test", Version: "1.0.0", Ecosystem: "npm", Path: "/tmp/package.json"},
		},
		Vulnerabilities: map[string][]dependency.Vulnerability{
			"test:1": {
				{ID: "TEST-1", Title: "Test vuln", Severity: "HIGH", CVSS: 7.5, FixedIn: "1.0.1"},
			},
		},
		ToolVersion: "v0.1.0",
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify fix is included in output
	out := buf.String()
	if !strings.Contains(out, "\"fix\"") {
		t.Error("Output should include fix information when FixedIn is available")
	}
	if !strings.Contains(out, "1.0.1") {
		t.Error("Fix should mention the fixed-in version 1.0.1")
	}
}

func TestReporter_UniqueRules(t *testing.T) {
	r := New()
	result := dependency.AnalysisResult{
		Project: dependency.Project{Name: "test", Path: "/tmp"},
		Dependencies: []dependency.Dependency{
			{ID: "test:1", Name: "a", Version: "1.0.0", Ecosystem: "npm", Path: "/tmp/p.json"},
			{ID: "test:2", Name: "b", Version: "1.0.0", Ecosystem: "npm", Path: "/tmp/p.json"},
		},
		Vulnerabilities: map[string][]dependency.Vulnerability{
			"test:1": {{ID: "CVE-SAME", Title: "Same vuln", Severity: "HIGH", CVSS: 7.0}},
			"test:2": {{ID: "CVE-SAME", Title: "Same vuln", Severity: "HIGH", CVSS: 7.0}},
		},
		ToolVersion: "v0.1.0",
	}

	var buf bytes.Buffer
	if err := r.Generate(result, &buf); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should have only ONE rule and TWO results pointing to it
	var parsed struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	rules := parsed.Runs[0].Tool.Driver.Rules
	results := parsed.Runs[0].Results

	if len(rules) != 1 {
		t.Errorf("Expected 1 unique rule, got: %d", len(rules))
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got: %d", len(results))
	}

	// Both results should reference rule index 0
	for _, res := range results {
		if res.RuleIndex != 0 {
			t.Errorf("Expected RuleIndex 0, got: %d", res.RuleIndex)
		}
	}
}

func TestSortResultsBySeverity(t *testing.T) {
	results := []sarifResult{
		{RuleID: "Z", Level: "note"},
		{RuleID: "A", Level: "error"},
		{RuleID: "B", Level: "warning"},
		{RuleID: "C", Level: "error"},
	}

	sorted := sortResultsBySeverity(results)

	// Expected: A (error), C (error), B (warning), Z (note)
	expectedOrder := []string{"A", "C", "B", "Z"}
	for i, exp := range expectedOrder {
		if sorted[i].RuleID != exp {
			t.Errorf("Expected order[%d] = %s, got: %s", i, exp, sorted[i].RuleID)
		}
	}
}

func TestCvssToSeverityString(t *testing.T) {
	tests := []struct {
		cvss     float64
		expected string
	}{
		{10.0, "10.0"},
		{9.5, "10.0"},
		{9.0, "10.0"},
		{8.5, "7.0"},
		{7.0, "7.0"},
		{6.5, "4.0"},
		{4.0, "4.0"},
		{3.5, "2.0"},
		{2.0, "2.0"},
		{1.0, "2.0"},
		{0.0, "0.0"},
	}

	for _, tt := range tests {
		got := cvssToSeverityString(tt.cvss)
		if got != tt.expected {
			t.Errorf("cvssToSeverityString(%.1f) = %s, want: %s", tt.cvss, got, tt.expected)
		}
	}
}

func TestSanitizeRuleName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Simple Title", "Simple Title"},
		{"With-dash inside", "With-dash inside"},
		{"With!special?chars", "Withspecialchars"},
		{"  spaces  ", "spaces"},
	}

	for _, tt := range tests {
		got := sanitizeRuleName(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeRuleName(%q) = %q, want: %q", tt.input, got, tt.expected)
		}
	}
}
