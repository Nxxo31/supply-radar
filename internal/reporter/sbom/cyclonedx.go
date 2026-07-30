// Package sbom implements SBOM reporters (SPDX, CycloneDX).
package sbom

import (
	"encoding/json"
	"io"
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

// Generate writes the CycloneDX SBOM to the given writer.
func (r *CycloneDXReporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	bom := CycloneDX{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{
					Vendor:  "supply-radar",
					Name:    "supply-radar",
					Version: result.ToolVersion,
				},
			},
			Component: Component{
				Name:    result.Project.Name,
				Type:    "application",
				BOMREF:  "Component-" + result.Project.Name,
			},
		},
		Components: r.components(result.Dependencies),
	}

	return enc.Encode(bom)
}

// components converts dependencies to CycloneDX components.
func (r *CycloneDXReporter) components(deps []dependency.Dependency) []Component {
	components := make([]Component, 0, len(deps))
	for _, dep := range deps {
		components = append(components, Component{
			Name:    dep.Name,
			Version: dep.Version,
			Type:    "library",
			BOMREF:  "Component-" + dep.ID,
			Licenses: []License{
				{
					License: LicenseData{
						ID: dep.License,
					},
				},
			},
			ExternalReferences: []ExternalReference{
				{
					Type:    "distribution",
					URL:     dep.Repository,
					Comment: "Source repository",
				},
				{
					Type: "purl",
					URL:  "pkg:" + dep.Ecosystem + "/" + dep.Name + "@" + dep.Version,
				},
			},
		})
	}
	return components
}

// CycloneDX represents the CycloneDX 1.5 document.
type CycloneDX struct {
	BOMFormat    string    `json:"bomFormat"`
	SpecVersion  string    `json:"specVersion"`
	Version      int       `json:"version"`
	Metadata     Metadata  `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata represents the metadata section.
type Metadata struct {
	Timestamp string   `json:"timestamp"`
	Tools     []Tool   `json:"tools"`
	Component Component `json:"component"`
}

// Tool represents a tool used to generate the BOM.
type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Component represents a component in the BOM.
type Component struct {
	Name              string              `json:"name,omitempty"`
	Version           string              `json:"version,omitempty"`
	Type              string              `json:"type,omitempty"`
	BOMREF            string              `json:"bom-ref,omitempty"`
	Licenses          []License           `json:"licenses,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
}

// License represents license information.
type License struct {
	License LicenseData `json:"license,omitempty"`
}

// LicenseData represents the license data.
type LicenseData struct {
	ID string `json:"id,omitempty"`
}

// ExternalReference represents an external reference.
type ExternalReference struct {
	Type    string `json:"type,omitempty"`
	URL     string `json:"url,omitempty"`
	Comment string `json:"comment,omitempty"`
}