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
	Tool    tool          `json:"tool"`
	Results []sarifResult `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	InformationURI  string `json:"informationUri,omitempty"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	Rules           []rule `json:"rules,omitempty"`
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

// --- Build logic ---

func buildSARIF(result dependency.AnalysisResult) *sarifReport {
	sevToLevel := map[string]string{
		"CRITICAL": "error",
		"HIGH":     "error",
		"MEDIUM":   "warning",
		"LOW":      "note",
		"UNKNOWN":  "note",
	}

	// Collect unique rules.
	ruleMap := make(map[string]int) // ruleID -> index
	rules := make([]rule, 0)
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

				rule := rule{
					ID:               v.ID,
					Name:             sanitizeRuleName(v.Title),
					ShortDescription: message{Text: v.Title},
					FullDescription:  message{Text: v.Description},
					DefaultRuleLevel: level,
				}
				rule.Properties.Tags = []string{"security", "supply-chain"}
				rule.Properties.Severity = cvssToSeverityString(v.CVSS)
				rules = append(rules, rule)
			}
		}
	}

	// Build results.
	results := make([]sarifResult, 0)
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

			sarifResult := sarifResult{
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
				sarifResult.Fix = &fix{
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

			results = append(results, sarifResult)
		}
	}

	// Sort results by severity (error > warning > note).
	results = sortResultsBySeverity(results)

	return &sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
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
				Results: results,
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
