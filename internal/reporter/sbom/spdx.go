// Package sbom implements SBOM reporters (SPDX, CycloneDX).
package sbom

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
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

// Generate writes the SPDX 2.3 SBOM to the given writer.
func (r *SPDXReporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	packages := r.packages(result.Dependencies)
	packageRefs := make([]string, len(packages))
	for i, p := range packages {
		packageRefs[i] = p.SPDXID
	}

	spdx := SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              result.Project.Name,
		DocumentNamespace: fmt.Sprintf("https://supply-radar.dev/sbom/%s-%s", result.Project.Name, result.Timestamp.Format("20060102150405")),
		CreationInfo: CreationInfo{
			Created:  result.Timestamp.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: supply-radar", fmt.Sprintf("Organization: supply-radar (%s)", result.ToolVersion)},
			LicenseListVersion: "3.21",
		},
		DocumentDescribes: packageRefs,
		Packages:          packages,
		Vulnerabilities:   r.vulnerabilities(result.Vulnerabilities, result.Dependencies),
	}

	return enc.Encode(spdx)
}

// packages converts dependencies to SPDX 2.3 packages.
func (r *SPDXReporter) packages(deps []dependency.Dependency) []SPDXPackage {
	pkgs := make([]SPDXPackage, 0, len(deps))
	for _, dep := range deps {
		spdxID := "SPDXRef-Package-" + sanitizeID(dep.ID)
		externalRefs := r.externalRefs(dep)

		pkgs = append(pkgs, SPDXPackage{
			Name:                  dep.Name,
			SPDXID:                spdxID,
			VersionInfo:           dep.Version,
			DownloadLocation:      r.downloadLocation(dep),
			LicenseConcluded:      r.licenseOrNoAssertion(dep.License),
			LicenseDeclared:       r.licenseOrNoAssertion(dep.License),
			CopyrightText:         "NOASSERTION",
			Supplier:              Supplier{Supplier: r.supplierString(dep)},
			PackageVerificationCode: PackageVerificationCode{
				PackageVerificationCodeValue: r.verificationCode(dep),
			},
			ExternalRefs: externalRefs,
		})
	}
	return pkgs
}

// vulnerabilities converts OSV vulnerability data to SPDX vulnerability entries.
func (r *SPDXReporter) vulnerabilities(vulnsByDep map[string][]dependency.Vulnerability, deps []dependency.Dependency) []SPDXVulnerability {
	if len(vulnsByDep) == 0 {
		return nil
	}
	depByID := make(map[string]dependency.Dependency, len(deps))
	for _, d := range deps {
		depByID[d.ID] = d
	}

	var vulns []SPDXVulnerability
	for depID, depVulns := range vulnsByDep {
		dep, ok := depByID[depID]
		if !ok {
			continue
		}
		pkgRef := "SPDXRef-Package-" + sanitizeID(dep.ID)
		for _, v := range depVulns {
			vulnID := v.ID
			if v.CVE != "" {
				vulnID = v.CVE
			}
			vulns = append(vulns, SPDXVulnerability{
				SPDXID:      "SPDXRef-Vuln-" + sanitizeID(vulnID),
				Name:        vulnID,
				Category:    "security",
				Severity:    strings.ToLower(v.Severity),
				Description: v.Title,
				Affects: []SPDXAffects{
					{AffectsRef: pkgRef},
				},
				ExternalReferences: []SPDXExternalRef{
					{
						ReferenceCategory: "SECURITY",
						ReferenceLocator:  "https://osv.dev/vulnerability/" + v.ID,
						ReferenceType:     "osv",
					},
				},
			})
		}
	}
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].Name < vulns[j].Name
	})
	return vulns
}

// externalRefs builds external references for a package (purl).
func (r *SPDXReporter) externalRefs(dep dependency.Dependency) []SPDXExternalRef {
	refs := []SPDXExternalRef{}
	purl := buildPURL(dep)
	if purl != "" {
		refs = append(refs, SPDXExternalRef{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  purl,
		})
	}
	return refs
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

// supplierString returns a supplier string for the package.
func (r *SPDXReporter) supplierString(dep dependency.Dependency) string {
	if dep.Repository != "" {
		return "NOASSERTION"
	}
	return "NOASSERTION"
}

// verificationCode returns a deterministic verification code for the package.
// SPDX 2.3 requires a packageVerificationCode; we compute a SHA1 of the package identity.
func (r *SPDXReporter) verificationCode(dep dependency.Dependency) string {
	h := sha1.New()
	h.Write([]byte(dep.ID + dep.Version + dep.Name))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SPDXDocument represents the SPDX 2.3 document.
type SPDXDocument struct {
	SPDXVersion       string             `json:"SPDXVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      CreationInfo       `json:"creationInfo"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []SPDXPackage      `json:"packages"`
	Vulnerabilities   []SPDXVulnerability `json:"vulnerabilities,omitempty"`
}

// CreationInfo represents the creationInfo field.
type CreationInfo struct {
	Created            string   `json:"created"`
	Creators          []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
}

// SPDXPackage represents an SPDX 2.3 package.
type SPDXPackage struct {
	Name                    string                  `json:"name"`
	SPDXID                  string                  `json:"SPDXID"`
	VersionInfo             string                  `json:"versionInfo,omitempty"`
	DownloadLocation        string                  `json:"downloadLocation"`
	LicenseConcluded        string                  `json:"licenseConcluded"`
	LicenseDeclared         string                  `json:"licenseDeclared"`
	CopyrightText           string                  `json:"copyrightText"`
	Supplier                Supplier                `json:"supplier,omitempty"`
	PackageVerificationCode PackageVerificationCode `json:"packageVerificationCode"`
	ExternalRefs            []SPDXExternalRef       `json:"externalRefs,omitempty"`
}

// Supplier represents the supplier of a package (SPDX 2.3 format).
type Supplier struct {
	Supplier string `json:"supplier"`
}

// PackageVerificationCode per SPDX 2.3 spec.
type PackageVerificationCode struct {
	PackageVerificationCodeValue string `json:"packageVerificationCodeValue"`
}

// SPDXExternalRef represents an external reference in SPDX 2.3.
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType,omitempty"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXVulnerability represents a security vulnerability in SPDX 2.3.
type SPDXVulnerability struct {
	SPDXID             string             `json:"SPDXID"`
	Name               string             `json:"name"`
	Category           string             `json:"category"`
	Severity           string             `json:"severity,omitempty"`
	Description        string             `json:"description,omitempty"`
	Affects            []SPDXAffects      `json:"affects,omitempty"`
	ExternalReferences []SPDXExternalRef `json:"externalReferences,omitempty"`
}

// SPDXAffects links a vulnerability to the packages it affects.
type SPDXAffects struct {
	AffectsRef string `json:"SPDXID"`
}
