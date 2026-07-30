// Package sbom provides SBOM reporters (SPDX and CycloneDX).
package sbom

import (
	"fmt"
	"io"

	"github.com/nxxo31/supply-radar/internal/dependency"
	"github.com/nxxo31/supply-radar/internal/reporter"
)

// Reporter is a wrapper that selects the appropriate SBOM reporter based on format.
type Reporter struct {
	format   string
	reporter reporter.Reporter
}

// NewReporter creates a new SBOM reporter for the given format.
// Supported formats: "sbom-spdx", "sbom-cyclonedx".
func NewReporter(format string) (*Reporter, error) {
	var rep reporter.Reporter
	switch format {
	case "sbom-spdx":
		rep = NewSPDX()
	case "sbom-cyclonedx":
		rep = NewCycloneDX()
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
	return &Reporter{
		format:   format,
		reporter: rep,
	}, nil
}

// Name returns the reporter identifier.
func (r *Reporter) Name() string {
	return r.format
}

// Generate writes the SBOM report to the given writer.
func (r *Reporter) Generate(result dependency.AnalysisResult, w io.Writer) error {
	return r.reporter.Generate(result, w)
}