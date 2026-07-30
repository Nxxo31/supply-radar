// Package sbom implements SBOM reporters (SPDX, CycloneDX).
package sbom

import (
	"encoding/json"
	"io"
	"time"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// SPDXReporter generates SPDX 2.3 JSON SBOM.
type SPDXReporter struct{}

// NewSPDX creates a new SPDX reporter.
func NewSPDX() *SPDXReporter {
	return &SPDXReporter{}
}

// Name returns the reporter identifier.
func (r *SPDXReporter) Name() string {
	return "sbom-spdx"
}

// Generate writes the SPDX SBOM to the given writer.
func (r *SPDXReporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	spdx := SPDX{
		SPDXVersion:       "SPDX-2.3",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              result.Project.Name,
		DocumentNamespace: "https://supply-radar.dev/sbom/" + result.Project.Name + "-" + time.Now().Format(time.RFC3339Nano),
		CreationInfo: CreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: supply-radar"},
		},
		Packages: r.packages(result.Dependencies),
	}

	return enc.Encode(spdx)
}

// packages converts dependencies to SPDX packages.
func (r *SPDXReporter) packages(deps []dependency.Dependency) []Package {
	pkgs := make([]Package, 0, len(deps))
	for _, dep := range deps {
		pkgs = append(pkgs, Package{
			Name:             dep.Name,
			SPDXID:           "SPDXRef-Package-" + dep.ID,
			VersionInfo:      dep.Version,
			DownloadLocation: r.downloadLocation(dep),
			LicenseConcluded: r.licenseOrNoAssertion(dep.License),
			LicenseDeclared:  r.licenseOrNoAssertion(dep.License),
			CopyrightText:    "NOASSERTION",
			Supplier:         Supplier{Name: "NOASSERTION"},
		})
	}
	return pkgs
}

// downloadLocation returns the download location or NOASSERTION.
func (r *SPDXReporter) downloadLocation(dep dependency.Dependency) string {
	if dep.Repository != "" {
		return dep.Repository
	}
	return "NOASSERTION"
}

// licenseOrNoAssertion returns the license or NOASSERTION if empty.
func (r *SPDXReporter) licenseOrNoAssertion(license string) string {
	if license != "" {
		return license
	}
	return "NOASSERTION"
}

// SPDX represents the SPDX 2.3 document.
type SPDX struct {
	SPDXVersion       string      `json:"SPDXVersion"`
	SPDXID            string      `json:"SPDXID"`
	Name              string      `json:"name,omitempty"`
	DocumentNamespace string      `json:"nameSpace"`
	CreationInfo      CreationInfo `json:"creationInfo"`
	Packages          []Package    `json:"packages"`
}

// CreationInfo represents the creationInfo field.
type CreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// Package represents an SPDX package.
type Package struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	DownloadLocation string `json:"downloadLocation,omitempty"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	CopyrightText    string `json:"copyrightText"`
	Supplier         Supplier `json:"supplier,omitempty"`
}

// Supplier represents the supplier of a package.
type Supplier struct {
	Name string `json:"name,omitempty"`
}