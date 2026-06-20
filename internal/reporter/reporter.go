// Package reporter defines the Reporter interface and implementations.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// Reporter generates reports from analysis results.
type Reporter interface {
	// Name returns the reporter identifier.
	Name() string
	// Generate writes the report to the given writer.
	Generate(result dependency.AnalysisResult, w io.Writer) error
}

// JSONReporter generates JSON output.
type JSONReporter struct{}

// NewJSON creates a new JSON reporter.
func NewJSON() *JSONReporter {
	return &JSONReporter{}
}

// Name returns "json".
func (r *JSONReporter) Name() string {
	return "json"
}

// Generate writes the analysis result as JSON.
func (r *JSONReporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// JSONSummaryReporter outputs a compact summary in JSON format.
type JSONSummaryReporter struct{}

// NewJSONSummary creates a summary JSON reporter.
func NewJSONSummary() *JSONSummaryReporter {
	return &JSONSummaryReporter{}
}

func (r *JSONSummaryReporter) Name() string {
	return "json-summary"
}

func (r *JSONSummaryReporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	summary := struct {
		Project        string  `json:"project"`
		Dependencies   int     `json:"dependencies"`
		VulnerableDeps int     `json:"vulnerable_deps"`
		TotalVulns     int     `json:"total_vulnerabilities"`
		Critical       int     `json:"critical"`
		High           int     `json:"high"`
		Medium         int     `json:"medium"`
		Low            int     `json:"low"`
		RiskScore      float64 `json:"risk_score"`
		DurationMs     int64   `json:"duration_ms"`
	}{
		Project:        result.Project.Name,
		Dependencies:   result.Summary.TotalDependencies,
		VulnerableDeps: result.Summary.VulnerableDeps,
		TotalVulns:     result.Summary.TotalVulns,
		Critical:       result.Summary.Critical,
		High:           result.Summary.High,
		Medium:         result.Summary.Medium,
		Low:            result.Summary.Low,
		RiskScore:      result.RiskScore,
		DurationMs:     result.Duration.Milliseconds(),
	}
	return json.NewEncoder(w).Encode(summary)
}

// FallbackReporter returns an error for unknown formats.
type FallbackReporter struct{ Format string }

func (r *FallbackReporter) Name() string {
	return r.Format
}

func (r *FallbackReporter) Generate(_ dependency.AnalysisResult, _ io.Writer) error {
	return fmt.Errorf("unsupported output format: %s", r.Format)
}
