// Package sbom implements SBOM reporters (SPDX, CycloneDX).
package sbom

import (
	"strings"

	"github.com/nxxo31/supply-radar/internal/dependency"
)

// sanitizeID converts a dependency ID into a safe string for use in SPDXIDs and BOM-REFs.
func sanitizeID(id string) string {
	s := strings.NewReplacer(
		"/", "-",
		".", "-",
		"@", "-",
		" ", "-",
		":", "-",
		"+", "-",
	).Replace(id)
	// Collapse multiple dashes.
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

// buildPURL constructs a Package URL (purl) per the purl spec (https://github.com/package-url/purl-spec).
// Format: pkg:<type>/<namespace>/<name>@<version> or pkg:<type>/<name>@<version>
func buildPURL(dep dependency.Dependency) string {
	ecosystem := purlType(dep.Ecosystem)
	if ecosystem == "" {
		return ""
	}
	if dep.Version == "" {
		return ""
	}
	// Handle namespaced packages (e.g., golang.org/x/net → golang.org/x/net)
	if strings.Contains(dep.Name, "/") && ecosystem != "npm" {
		return "pkg:" + ecosystem + "/" + dep.Name + "@" + dep.Version
	}
	// npm scoped packages (e.g., @babel/core)
	if ecosystem == "npm" && strings.HasPrefix(dep.Name, "@") {
		// @scope/name → npm/%40scope/name
		return "pkg:" + ecosystem + "/" + strings.TrimPrefix(dep.Name, "@") + "@" + dep.Version
	}
	return "pkg:" + ecosystem + "/" + dep.Name + "@" + dep.Version
}

// purlType maps ecosystem names to purl type identifiers.
func purlType(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "go", "gomod":
		return "golang"
	case "npm":
		return "npm"
	case "pypi", "python":
		return "pypi"
	case "cargo", "rust":
		return "cargo"
	default:
		return ecosystem
	}
}

// cpeForDep generates a CPE 2.3 URI string if possible.
// Format: cpe:2.3:<part>:<vendor>:<product>:<version>:::<target_sw>:::<others>
func cpeForDep(dep dependency.Dependency) string {
	if dep.Name == "" || dep.Version == "" {
		return ""
	}
	// We don't have reliable vendor data, so we use the name as a best-effort.
	// This is a best-effort CPE; downstream tools may not match it exactly.
	vendor := sanitizeCPEVendor(dep.Name)
	product := sanitizeCPEField(dep.Name)
	version := sanitizeCPEField(dep.Version)
	return "cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
}

func sanitizeCPEField(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(
		"/", "_",
		".", "_",
		" ", "_",
		"@", "_",
	).Replace(s)
	return s
}

func sanitizeCPEVendor(name string) string {
	// Best-effort: use the first segment of a namespaced package.
	if idx := strings.Index(name, "/"); idx > 0 {
		return sanitizeCPEField(name[:idx])
	}
	return sanitizeCPEField(name)
}
