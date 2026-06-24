// Package markdown provides a Markdown reporter for supply-radar results.
package markdown

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// Reporter generates Markdown output.
type Reporter struct{}

// New creates a new Markdown reporter.
func New() *Reporter {
	return &Reporter{}
}

// Name returns "markdown".
func (r *Reporter) Name() string {
	return "markdown"
}

// Generate writes the analysis result as Markdown.
func (r *Reporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	fmt.Fprintln(w, "# supply-radar security report")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Field | Value |")
	fmt.Fprintln(w, "|-------|-------|")
	fmt.Fprintf(w, "| Tool | supply-radar %s |\n", result.ToolVersion)
	fmt.Fprintf(w, "| Project | %s |\n", result.Project.Name)
	fmt.Fprintf(w, "| Path | %s |\n", result.Project.Path)
	fmt.Fprintf(w, "| Ecosystem | %s |\n", result.Project.Ecosystem)
	fmt.Fprintf(w, "| Generated | %s |\n", result.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "| Duration | %dms |\n", result.Duration.Milliseconds())
	fmt.Fprintln(w)

	// Summary.
	fmt.Fprintln(w, "## Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Metric | Value |")
	fmt.Fprintln(w, "|--------|-------:|")
	fmt.Fprintf(w, "| Total dependencies | %d |\n", result.Summary.TotalDependencies)
	fmt.Fprintf(w, "| Vulnerable deps | %d |\n", result.Summary.VulnerableDeps)
	fmt.Fprintf(w, "| Critical | %d |\n", result.Summary.Critical)
	fmt.Fprintf(w, "| High | %d |\n", result.Summary.High)
	fmt.Fprintf(w, "| Medium | %d |\n", result.Summary.Medium)
	fmt.Fprintf(w, "| Low | %d |\n", result.Summary.Low)
	fmt.Fprintf(w, "| **Total vulnerabilities** | **%d** |\n", result.Summary.TotalVulns)
	fmt.Fprintf(w, "| **Risk score** | **%.1f/10** |\n", result.RiskScore)
	fmt.Fprintln(w)

	if result.Summary.TotalVulns == 0 {
		fmt.Fprintln(w, "> **No vulnerabilities detected.**")
		fmt.Fprintln(w)
		return nil
	}

	// Vulnerabilities.
	fmt.Fprintln(w, "## Vulnerabilities")
	fmt.Fprintln(w)

	// Sort by severity then name.
	type entry struct {
		dep        dependency.Dependency
		vulns      []dependency.Vulnerability
		maxSevRank int
	}

	sevRank := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

	var entries []entry
	for _, dep := range result.Dependencies {
		vulns := result.Vulnerabilities[dep.ID]
		if len(vulns) == 0 {
			continue
		}
		rank := 0
		for _, v := range vulns {
			if sr, ok := sevRank[v.Severity]; ok && sr > rank {
				rank = sr
			}
		}
		entries = append(entries, entry{dep: dep, vulns: vulns, maxSevRank: rank})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].maxSevRank != entries[j].maxSevRank {
			return entries[i].maxSevRank > entries[j].maxSevRank
		}
		return entries[i].dep.Name < entries[j].dep.Name
	})

	for _, e := range entries {
		fmt.Fprintf(w, "### %s\n", e.dep.Name)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "- **Version:**", e.dep.Version)
		fmt.Fprintln(w, "- **Direct:**", yesNo(e.dep.Direct))
		fmt.Fprintln(w, "- **Vulnerabilities:**", len(e.vulns))
		fmt.Fprintln(w)

		fmt.Fprintln(w, "| ID | Title | Severity | CVSS | Fixed in |")
		fmt.Fprintln(w, "|----|-------|----------|------|----------|")
		for _, v := range e.vulns {
			title := truncate(v.Title, 60)
			fixed := v.FixedIn
			if fixed == "" {
				fixed = "_n/a_"
			}
			fmt.Fprintf(w, "| %s | %s | %s | %.1f | %s |\n",
				v.ID, title, v.Severity, v.CVSS, fixed)
		}
		fmt.Fprintln(w)
	}

	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no (indirect)"
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "..."
}
