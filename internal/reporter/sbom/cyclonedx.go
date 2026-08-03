// Package sbom implements SBOM reporters (SPDX, CycloneDX).
package sbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// CycloneDXReporter generates CycloneDX 1.5 JSON SBOM.
type CycloneDXReporter struct{}

// NewCycloneDX creates a new CycloneDX reporter.
func NewCycloneDX() *CycloneDXReporter {
	return &CycloneDXReporter{}
}

// Name returns the reporter identifier.
func (r *CycloneDXReporter) Name() string {
	return "sbom-cyclonedx"
}

// Generate writes the CycloneDX 1.5 SBOM to the given writer.
func (r *CycloneDXReporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	components := r.components(result.Dependencies)
	vulns := r.vulnerabilities(result.Vulnerabilities, result.Dependencies)

	bom := CycloneDXDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		SerialNumber: generateUUID(),
		Version:     1,
		Metadata: CycloneDXMetadata{
			Timestamp: result.Timestamp.UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{
					Vendor:  "supply-radar",
					Name:    "supply-radar",
					Version: result.ToolVersion,
				},
			},
			Component: CycloneDXComponent{
				Name:   result.Project.Name,
				Type:   "application",
				BOMRef: "Component-" + sanitizeID(result.Project.Name),
			},
		},
		Components:     components,
		Vulnerabilities: vulns,
	}

	return enc.Encode(bom)
}

// components converts dependencies to CycloneDX 1.5 components.
func (r *CycloneDXReporter) components(deps []dependency.Dependency) []CycloneDXComponent {
	components := make([]CycloneDXComponent, 0, len(deps))
	for _, dep := range deps {
		purl := buildPURL(dep)
		cpe := cpeForDep(dep)

		comp := CycloneDXComponent{
			Name:    dep.Name,
			Version: dep.Version,
			Type:    "library",
			BOMRef:  "pkg:" + dep.Ecosystem + "/" + dep.Name + "@" + dep.Version,
			PURL:    purl,
			CPE:     cpe,
			Supplier: &CycloneDXSupplier{
				Name: dep.Name,
			},
		}

		if dep.License != "" {
			comp.Licenses = []CycloneDXLicenseChoice{
				{
					Expression: dep.License,
				},
			}
		}

		if dep.Repository != "" {
			comp.ExternalReferences = []CycloneDXExternalReference{
				{
					Type: "vcs",
					URL:  dep.Repository,
				},
			}
		}

		components = append(components, comp)
	}
	return components
}

// vulnerabilities converts OSV vulnerability data to CycloneDX 1.5 vulnerability entries.
func (r *CycloneDXReporter) vulnerabilities(vulnsByDep map[string][]dependency.Vulnerability, deps []dependency.Dependency) []CycloneDXVulnerability {
	if len(vulnsByDep) == 0 {
		return nil
	}
	depByID := make(map[string]dependency.Dependency, len(deps))
	for _, d := range deps {
		depByID[d.ID] = d
	}

	var vulns []CycloneDXVulnerability
	for depID, depVulns := range vulnsByDep {
		dep, ok := depByID[depID]
		if !ok {
			continue
		}
		bomRef := "pkg:" + dep.Ecosystem + "/" + dep.Name + "@" + dep.Version
		for _, v := range depVulns {
			vulnID := v.ID
			if v.CVE != "" {
				vulnID = v.CVE
			}

		 ratings := []CycloneDXRating{
				{
					Severity:    strings.ToLower(v.Severity),
					Method:      "other",
					Score:       v.CVSS,
					Vector:      v.CVSSVector,
				},
			}

			vuln := CycloneDXVulnerability{
				ID:       v.ID,
				Source: &CycloneDXSource{
					Name: "OSV",
					URL:  "https://osv.dev/vulnerability/" + v.ID,
				},
				Ratings: ratings,
				Description:          v.Description,
				Recommendation:       "",
				Affects: []CycloneDXAffect{
					{
						Ref: bomRef,
					},
				},
			}
			if v.FixedIn != "" {
				vuln.Recommendation = "Upgrade to version " + v.FixedIn
			}
			_ = vulnID // vuln ID is already in v.ID

			vulns = append(vulns, vuln)
		}
	}
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].ID < vulns[j].ID
	})
	return vulns
}

// generateUUID creates a random UUID v4 URN for the CycloneDX serialNumber.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// CycloneDXDocument represents the CycloneDX 1.5 BOM document.
type CycloneDXDocument struct {
	BOMFormat       string                 `json:"bomFormat"`
	SpecVersion     string                 `json:"specVersion"`
	SerialNumber    string                 `json:"serialNumber,omitempty"`
	Version         int                    `json:"version"`
	Metadata        CycloneDXMetadata      `json:"metadata"`
	Components      []CycloneDXComponent   `json:"components"`
	Vulnerabilities []CycloneDXVulnerability `json:"vulnerabilities,omitempty"`
}

// CycloneDXMetadata represents the metadata section.
type CycloneDXMetadata struct {
	Timestamp string            `json:"timestamp"`
	Tools     []CycloneDXTool   `json:"tools"`
	Component CycloneDXComponent `json:"component"`
}

// CycloneDXTool represents a tool used to generate the BOM.
type CycloneDXTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// CycloneDXComponent represents a component in the BOM.
type CycloneDXComponent struct {
	Name               string                     `json:"name,omitempty"`
	Version            string                     `json:"version,omitempty"`
	Type               string                     `json:"type,omitempty"`
	BOMRef             string                     `json:"bom-ref,omitempty"`
	PURL               string                     `json:"purl,omitempty"`
	CPE                string                     `json:"cpe,omitempty"`
	Supplier           *CycloneDXSupplier         `json:"supplier,omitempty"`
	Licenses           []CycloneDXLicenseChoice   `json:"licenses,omitempty"`
	ExternalReferences []CycloneDXExternalReference `json:"externalReferences,omitempty"`
}

// CycloneDXSupplier represents the supplier of a component.
type CycloneDXSupplier struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXLicenseChoice represents a license choice (SPDX expression or license object).
type CycloneDXLicenseChoice struct {
	Expression string                 `json:"expression,omitempty"`
	License    *CycloneDXLicenseEntry `json:"license,omitempty"`
}

// CycloneDXLicenseEntry represents a named license entry.
type CycloneDXLicenseEntry struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CycloneDXExternalReference represents an external reference.
type CycloneDXExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// CycloneDXVulnerability represents a vulnerability in CycloneDX 1.5.
type CycloneDXVulnerability struct {
	ID             string             `json:"id"`
	Source         *CycloneDXSource   `json:"source,omitempty"`
	Ratings        []CycloneDXRating  `json:"ratings,omitempty"`
	Description    string             `json:"description,omitempty"`
	Recommendation string             `json:"recommendation,omitempty"`
	Affects        []CycloneDXAffect `json:"affects"`
}

// CycloneDXSource represents the source of vulnerability data.
type CycloneDXSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXRating represents a vulnerability rating/severity.
type CycloneDXRating struct {
	Severity string  `json:"severity,omitempty"`
	Method   string  `json:"method,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Vector   string  `json:"vector,omitempty"`
}

// CycloneDXAffect links a vulnerability to an affected component.
type CycloneDXAffect struct {
	Ref string `json:"ref"`
}
