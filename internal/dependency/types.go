// Package dependency defines the core domain types for supply-radar.
package dependency

import "time"

// Dependency represents a single software dependency.
type Dependency struct {
	// ID is a stable identifier derived from name+version+ecosystem.
	ID string `json:"id"`
	// Name is the package name (e.g., "lodash", "golang.org/x/net").
	Name string `json:"name"`
	// Version is the resolved version string.
	Version string `json:"version"`
	// Ecosystem identifies the package manager (go, npm, pypi, etc.).
	Ecosystem string `json:"ecosystem"`
	// Path is the file path in the project where this dep is declared.
	Path string `json:"path"`
	// Direct indicates whether this is a top-level dependency (true) or transitive (false).
	Direct bool `json:"direct"`
	// License is the detected SPDX license identifier, if available.
	License string `json:"license,omitempty"`
	// Repository is the canonical source repository URL, if available.
	Repository string `json:"repository_url,omitempty"`
	// UpdatedAt is the timestamp of the latest upstream release.
	UpdatedAt time.Time `json:"last_updated,omitempty"`
}

// Vulnerability represents a known CVE or advisory.
type Vulnerability struct {
	// ID is the advisory identifier (e.g., "GHSA-xxxx-xxxx-xxxx").
	ID string `json:"id"`
	// CVE is the CVE identifier, if assigned.
	CVE string `json:"cve_id,omitempty"`
	// Title is a short human-readable summary.
	Title string `json:"title"`
	// Description provides details about the vulnerability.
	Description string `json:"description"`
	// Severity is the severity level (CRITICAL, HIGH, MEDIUM, LOW).
	Severity string `json:"severity"`
	// CVSS is the CVSS score (0.0 - 10.0).
	CVSS float64 `json:"cvss_score"`
	// CVSSVector is the CVSS vector string.
	CVSSVector string `json:"cvss_vector,omitempty"`
	// PublishedAt is when the advisory was first published.
	PublishedAt time.Time `json:"published"`
	// ModifiedAt is when the advisory was last modified.
	ModifiedAt time.Time `json:"modified"`
	// FixedIn is the version that fixes this vulnerability, if known.
	FixedIn string `json:"fixed_in,omitempty"`
	// References is a list of URLs with more information.
	References []string `json:"references,omitempty"`
}

// Project represents the scanned project.
type Project struct {
	// Name is derived from the project path or manifest.
	Name string `json:"name"`
	// Path is the absolute or relative path scanned.
	Path string `json:"path"`
	// Version is the project version, if discoverable.
	Version string `json:"version,omitempty"`
	// Ecosystem is the primary ecosystem detected.
	Ecosystem string `json:"ecosystem,omitempty"`
}

// AnalysisResult is the complete output of scanning a project.
type AnalysisResult struct {
	// Project contains metadata about the scanned project.
	Project Project `json:"project"`
	// Dependencies is the full list of dependencies found.
	Dependencies []Dependency `json:"dependencies"`
	// Vulnerabilities maps dependency IDs to their known vulnerabilities.
	Vulnerabilities map[string][]Vulnerability `json:"vulnerabilities"`
	// Summary provides aggregated risk metrics.
	Summary RiskSummary `json:"summary"`
	// RiskScore is an aggregate score from 0 (safe) to 10 (critical risk).
	RiskScore float64 `json:"risk_score"`
	// Timestamp is when the scan started.
	Timestamp time.Time `json:"timestamp"`
	// Duration is how long the scan took.
	Duration time.Duration `json:"duration_ms"`
	// ToolVersion is the supply-radar version used.
	ToolVersion string `json:"tool_version"`
}

// RiskSummary provides aggregated vulnerability counts.
type RiskSummary struct {
	TotalDependencies int `json:"total_dependencies"`
	VulnerableDeps    int `json:"vulnerable"`
	Critical          int `json:"critical"`
	High              int `json:"high"`
	Medium            int `json:"medium"`
	Low               int `json:"low"`
	TotalVulns        int `json:"total_vulns"`
}
