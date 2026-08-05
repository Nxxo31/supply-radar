// Package sarif provides a SARIF 2.1.0 reporter for supply-radar.
// SARIF (Static Analysis Results Interchange Format) integrates with
// GitHub Code Scanning and other tools that support the OASIS standard.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// Reporter generates SARIF 2.1.0 output for GitHub Code Scanning integration.
type Reporter struct{}

// New creates a new SARIF reporter.
func New() *Reporter {
	return &Reporter{}
}

// Name returns "sarif".
func (r *Reporter) Name() string {
	return "sarif"
}

// Generate writes the analysis result as SARIF 2.1.0 JSON.
func (r *Reporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	sarifReport := buildSARIF(result)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifReport)
}

// --- SARIF type definitions ---

type sarifReport struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool             tool          `json:"tool"`
	Results          []sarifResult `json:"results"`
	Invocations      []invocation  `json:"invocations,omitempty"`
	AutomationDetails *automationDetails `json:"automationDetails,omitempty"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name            string  `json:"name"`
	Version         string  `json:"version"`
	InformationURI  string  `json:"informationUri,omitempty"`
	SemanticVersion string  `json:"semanticVersion,omitempty"`
	Rules           []rule  `json:"rules,omitempty"`
}

type rule struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	ShortDescription message `json:"shortDescription"`
	FullDescription  message `json:"fullDescription,omitempty"`
	Help             help    `json:"help,omitempty"`
	DefaultRuleLevel string  `json:"defaultRuleLevel,omitempty"`
	Properties       struct {
		Tags     []string `json:"tags,omitempty"`
		Severity string   `json:"security-severity,omitempty"`
	} `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type help struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex,omitempty"`
	Level     string     `json:"level"` // error, warning, note
	Message   message    `json:"message"`
	Locations []location `json:"locations,omitempty"`
	Fix       *fix       `json:"fix,omitempty"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation,omitempty"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region,omitempty"`
}

type artifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type region struct {
	StartLine   int `json:"startLine,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type fix struct {
	Description message  `json:"description"`
	Changes     []change `json:"changes"`
}

type change struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Key              string           `json:"key"`
	Value            string           `json:"value"`
}

// invocation records how the tool was invoked for this run. GitHub Code
// Scanning uses invocation.endTimeUtc and executionSuccessful to deduplicate
// reruns and to display run metadata in the alert timeline.
type invocation struct {
	AutomationID       string  `json:"automationId,omitempty"`
	StartTimeUTC       string  `json:"startTimeUtc,omitempty"`
	EndTimeUTC         string  `json:"endTimeUtc,omitempty"`
	ExecutionSuccessful bool    `json:"executionSuccessful"`
	CommandLine        string  `json:"commandLine,omitempty"`
	WorkingDirectory   string  `json:"workingDirectory,omitempty"`
	ToolExecutionURL   string  `json:"toolExecutionUri,omitempty"`
}

// automationDetails identifies the run category — GitHub uses this to group
// alerts from the same workflow across different commits/PRs.
type automationDetails struct {
	ID      string `json:"id"`
	GUID    string `json:"guid,omitempty"`
	Category string `json:"category,omitempty"`
}

// --- Build logic ---

// schemaSARIF210 is the canonical URL for the SARIF 2.1.0 JSON schema.
// We use the schemastore.org URL because it is the one GitHub Code Scanning
// resolves for validation; the legacy oasis-tcs master/Schemata path was
// broken by a branch rename (oasis-tcs/sarif-spec#646).
const schemaSARIF210 = "https://json.schemastore.org/sarif-2.1.0.json"

// runCategory is the automationDetails.category GitHub Code Scanning uses to
// group alert instances across reruns of the same workflow. supply-radar is
// a CLI scanner, so a stable category lets GitHub correlate successive scans
// of the same repository.
const runCategory = "supply-radar/scan"

func buildSARIF(result dependency.AnalysisResult) *sarifReport {
	sevToLevel := map[string]string{
		"CRITICAL": "error",
		"HIGH":     "error",
		"MEDIUM":   "warning",
		"LOW":      "note",
		"UNKNOWN":  "note",
	}

	// Collect unique rules. We keep the rules slice nil when no vulns are
	// reported so the JSON output omits "rules" entirely (omitempty), which
	// makes the empty-vuln case match what GitHub Code Scanning expects.
	ruleMap := make(map[string]int) // ruleID -> index
	var rules []rule               // stays nil if we never append
	ruleOrder := make([]string, 0)

	for _, vulns := range result.Vulnerabilities {
		for _, v := range vulns {
			if _, exists := ruleMap[v.ID]; !exists {
				idx := len(rules)
				ruleMap[v.ID] = idx
				ruleOrder = append(ruleOrder, v.ID)

				level := sevToLevel[v.Severity]
				if level == "" {
					level = "warning"
				}

				r := rule{
					ID:               v.ID,
					Name:             sanitizeRuleName(v.Title),
					ShortDescription: message{Text: v.Title},
					FullDescription:  message{Text: v.Description},
					DefaultRuleLevel: level,
				}
				r.Properties.Tags = []string{"security", "supply-chain"}
				r.Properties.Severity = cvssToSeverityString(v.CVSS)
				rules = append(rules, r)
			}
		}
	}
	_ = ruleOrder // ordered stable via rules slice

	// Build results. Same nil-slice trick: emits `"results": null` when empty,
	// matching the SARIF schema which explicitly allows an empty array (so this
	// is a stylistic choice, not a correctness requirement).
	var results []sarifResult
	for depID, vulns := range result.Vulnerabilities {
		for _, v := range vulns {
			// Look up dependency metadata (including version) from the dependencies list.
			depName := depID
			depPath := ""
			depVersion := ""
			for _, dep := range result.Dependencies {
				if dep.ID == depID {
					depName = dep.Name
					depPath = dep.Path
					depVersion = dep.Version
					break
				}
			}

			idx := ruleMap[v.ID]

			level := sevToLevel[v.Severity]
			if level == "" {
				level = "warning"
			}

			sr := sarifResult{
				RuleID:    v.ID,
				RuleIndex: idx,
				Level:     level,
				Message:   message{Text: buildMessage(depName, depVersion, v)},
				Locations: []location{
					{
						PhysicalLocation: physicalLocation{
							ArtifactLocation: artifactLocation{
								URI: depPath,
							},
						},
					},
				},
			}

			if v.FixedIn != "" {
				sr.Fix = &fix{
					Description: message{
						Text: fmt.Sprintf("Upgrade %s to version %s or later to resolve %s",
							depName, v.FixedIn, v.ID),
					},
					Changes: []change{
						{
							ArtifactLocation: artifactLocation{URI: depPath},
							Key:              "version",
							Value:            v.FixedIn,
						},
					},
				}
			}

			results = append(results, sr)
		}
	}

	// Sort results by severity (error > warning > note).
	results = sortResultsBySeverity(results)

	// Build invocation metadata. GitHub Code Scanning requires an invocation
	// with endTimeUtc and executionSuccessful to display run provenance; without
	// it the SARIF upload succeeds but the run appears "unfinished" in the UI.
	runInvocations := []invocation{
		{
			StartTimeUTC:       formatRFC3339(result.Timestamp),
			EndTimeUTC:         formatRFC3339(result.Timestamp.Add(result.Duration)),
			ExecutionSuccessful: true,
		},
	}

	return &sarifReport{
		Schema:  schemaSARIF210,
		Version: "2.1.0",
		Runs: []run{
			{
				Tool: tool{
					Driver: driver{
						Name:           "supply-radar",
						Version:        result.ToolVersion,
						InformationURI: "https://github.com/Nxxo31/supply-radar",
						Rules:          rules,
					},
				},
				Results:           results,
				Invocations:       runInvocations,
				AutomationDetails: &automationDetails{ID: "supply-radar/" + result.ToolVersion, Category: runCategory},
			},
		},
	}
}

func buildMessage(depName, depVersion string, v dependency.Vulnerability) string {
	msg := fmt.Sprintf("Vulnerability %s in %s@%s", v.ID, depName, depVersion)
	if v.FixedIn != "" {
		msg += fmt.Sprintf(" — fix available in %s", v.FixedIn)
	}
	if v.CVSS > 0 {
		msg += fmt.Sprintf(" (CVSS %.1f)", v.CVSS)
	}
	if v.Title != "" {
		msg += fmt.Sprintf(": %s", v.Title)
	}
	return msg
}

func sanitizeRuleName(title string) string {
	var result strings.Builder
	for _, r := range title {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' || r == '-' {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

func sortResultsBySeverity(results []sarifResult) []sarifResult {
	sevOrder := map[string]int{"error": 3, "warning": 2, "note": 1}
	sort.Slice(results, func(i, j int) bool {
		l1 := sevOrder[results[i].Level]
		l2 := sevOrder[results[j].Level]
		if l1 != l2 {
			return l1 > l2
		}
		return results[i].RuleID < results[j].RuleID
	})
	return results
}

func cvssToSeverityString(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "10.0"
	case cvss >= 7.0:
		return "7.0"
	case cvss >= 4.0:
		return "4.0"
	case cvss > 0:
		return "2.0"
	default:
		return "0.0"
	}
}

// formatRFC3339 emits a SARIF-compliant RFC 3339 UTC timestamp. SARIF 2.1.0
// expects UTC formatted per RFC 3339 with a "Z" suffix; we use a zero-time
// fallback ("1970-01-01T00:00:00Z") so nil-timestamp analysis results (e.g.
// constructed directly in tests) still emit a valid value rather than an
// empty string the spec rejects. We use RFC3339Nano to preserve sub-second
// precision for short scans, which is valid RFC 3339 and matches what GitHub
// Code Scanning's own CLI emits.
func formatRFC3339(t time.Time) string {
	if t.IsZero() {
		return "1970-01-01T00:00:00Z"
	}
	return t.UTC().Format(time.RFC3339Nano)
}
