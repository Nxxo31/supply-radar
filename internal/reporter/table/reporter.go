// Package table provides a terminal table reporter.
package table

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// Reporter generates a formatted table report for the terminal.
type Reporter struct{}

// New creates a new table reporter.
func New() *Reporter {
	return &Reporter{}
}

// Name returns "table".
func (r *Reporter) Name() string {
	return "table"
}

// Generate writes the analysis result as an ASCII table.
func (r *Reporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	printHeader(w, result)
	printSummary(w, result)

	// Sort vulnerabilities: critical first, then by name.
	sortedDeps := sortByVulnSeverity(result)

	if len(sortedDeps) == 0 {
		fmt.Fprintln(w, "\n  No vulnerable dependencies found.")
		return nil
	}

	fmt.Fprintln(w, "\n Vulnerable Dependencies:")
	fmt.Fprintln(w, formatDivider(60, "─"))
	fmt.Fprintln(w, fmt.Sprintf(" %-40s %-10s %s", "PACKAGE", "SEVERITY", "CVSS"))
	fmt.Fprintln(w, formatDivider(60, "─"))

	for _, depID := range sortedDeps {
		vulns := result.Vulnerabilities[depID]
		if len(vulns) == 0 {
			continue
		}

		// Group by severity for this dep.
		dep := findDep(result.Dependencies, depID)
		severity, cvss := worstVuln(vulns)
		marker := ""
		if !dep.Direct {
			marker = " (indirect)"
		}
		severityLabel := severityColor(severity, severity)
		cvssLabel := ""
		if cvss > 0 {
			cvssLabel = fmt.Sprintf("%.1f", cvss)
		}
		fmt.Fprintf(w, " %-40s %-10s %s\n", dep.Name+marker, severityLabel, cvssLabel)

		// Print each vulnerability ID if many.
		if len(vulns) == 1 {
			fmt.Fprintf(w, "   %s\n", vulns[0].ID)
		} else {
			fmt.Fprintf(w, "   %d vulnerabilities\n", len(vulns))
		}
	}

	fmt.Fprintln(w, formatDivider(60, "─"))
	return nil
}

func printHeader(w io.Writer, result dependency.AnalysisResult) {
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, " ╭─ %s", bold("supply-radar"))
	fmt.Fprintf(w, " %s", result.ToolVersion)
	fmt.Fprintln(w, " ─────────────────────────────")
	fmt.Fprintf(w, " │ Project:  %s\n", result.Project.Name)
	fmt.Fprintf(w, " │ Path:     %s\n", result.Project.Path)
	fmt.Fprintf(w, " │ Time:     %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, " │ Duration: %dms\n", result.Duration.Milliseconds())
	fmt.Fprintln(w, " ╰─────────────────────────────────────────────────────────────")
}

func printSummary(w io.Writer, result dependency.AnalysisResult) {
	s := result.Summary
	hasVulns := s.TotalVulns > 0

	if !hasVulns {
		fmt.Fprintln(w, "\n  ✅ No vulnerabilities detected.")
		fmt.Fprintf(w, "  Total dependencies scanned: %d\n", s.TotalDependencies)
		return
	}

	// Color-coded summary (no color codes for maximum compatibility).
	summaryLine := fmt.Sprintf("  ⚠ Found %d vulnerabilities in %d dependencies",
		s.TotalVulns, s.VulnerableDeps)
	if s.Critical > 0 {
		summaryLine += " — CRITICAL issues require immediate action"
	}
	fmt.Fprintln(w, summaryLine)

	fmt.Fprintf(w, "   CRITICAL: %d  |  HIGH: %d  |  MEDIUM: %d  |  LOW: %d\n",
		s.Critical, s.High, s.Medium, s.Low)
	fmt.Fprintf(w, "   Risk Score: %.1f/10\n", result.RiskScore)
}

func sortByVulnSeverity(result dependency.AnalysisResult) []string {
	type depRisk struct {
		id       string
		severity int // higher = more severe
		hasVuln  bool
	}

	var ranked []depRisk
	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	for _, dep := range result.Dependencies {
		vulns := result.Vulnerabilities[dep.ID]
		if len(vulns) == 0 {
			continue
		}

		maxSev := 0
		for _, v := range vulns {
			if s, ok := severityOrder[v.Severity]; ok && s > maxSev {
				maxSev = s
			}
		}
		ranked = append(ranked, depRisk{id: dep.ID, severity: maxSev, hasVuln: true})
	}

	// Sort by severity descending, then by name ascending.
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].severity != ranked[j].severity {
			return ranked[i].severity > ranked[j].severity
		}
		return ranked[i].id < ranked[j].id
	})

	ids := make([]string, len(ranked))
	for i, r := range ranked {
		ids[i] = r.id
	}
	return ids
}

func worstVuln(vulns []dependency.Vulnerability) (severity string, cvss float64) {
	severity = "LOW"
	cvss = 0.0
	order := map[string]float64{
		"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
	}
	for _, v := range vulns {
		if order[v.Severity] > order[severity] {
			severity = v.Severity
			cvss = v.CVSS
		}
	}
	return
}

func findDep(deps []dependency.Dependency, id string) dependency.Dependency {
	for _, d := range deps {
		if d.ID == id {
			return d
		}
	}
	return dependency.Dependency{Name: id}
}

func severityColor(severity, label string) string {
	// Return plain label for compatibility.
	// In a TUI context, use a color library.
	return label
}

func bold(s string) string {
	return s
}

func formatDivider(width int, char string) string {
	var b strings.Builder
	b.WriteString(" ")
	for i := 0; i < width; i++ {
		b.WriteString(char)
	}
	return b.String()
}
