// Package scanner orchestrates the analysis workflow.
package scanner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/nxxo31/supply-radar/internal/cache"
	"github.com/nxxo31/supply-radar/internal/dependency"
	"github.com/nxxo31/supply-radar/internal/parser"
	"github.com/nxxo31/supply-radar/internal/parser/gomod"
	"github.com/nxxo31/supply-radar/internal/parser/npm"
	"github.com/nxxo31/supply-radar/internal/reporter"
	"github.com/nxxo31/supply-radar/internal/reporter/markdown"
	"github.com/nxxo31/supply-radar/internal/reporter/sarif"
	"github.com/nxxo31/supply-radar/internal/reporter/table"
	"github.com/nxxo31/supply-radar/internal/vulnerability/osv"
)

// Config holds scanner configuration.
type Config struct {
	// Path is the project path to scan.
	Path string
	// SeverityThreshold filters vulnerabilities below this level.
	// Empty means show all.
	SeverityThreshold string
	// FailOnVulnerabilities causes exit code 1 when vulnerabilities are found.
	FailOnVulnerabilities bool
	// Format specifies the output format ("table", "json", "json-summary").
	Format string
	// OutputPath specifies where to write the report ("-" for stdout).
	OutputPath string
	// Offline enables offline mode (uses only cached data).
	Offline bool
	// CacheTTL sets the vulnerability cache TTL.
	CacheTTL time.Duration
	// ToolVersion is the supply-radar version string.
	ToolVersion string
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Format:      "table",
		OutputPath:  "-",
		CacheTTL:    24 * time.Hour,
		ToolVersion: "v0.1.0",
	}
}

// Result wraps the analysis result and the CLI exit code suggestion.
type Result struct {
	Analysis  dependency.AnalysisResult
	ExitCode  int
	FailError error
}

// Scan executes the full analysis pipeline and returns the result.
func Scan(cfg Config) (*Result, error) {
	start := time.Now()

	// Resolve absolute path.
	absPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	// 1. Detect and instantiate parsers.
	parsers := []parser.Parser{
		gomod.New(),
		npm.New(),
	}

	var allDeps []dependency.Dependency
	var detectedEcosystem string

	for _, p := range parsers {
		detected, _ := p.Detect(absPath)
		if !detected {
			continue
		}
		detectedEcosystem = p.Name()
		deps, err := p.Parse(absPath)
		if err != nil {
			// If one parser fails (other than "no deps"), try the next.
			continue
		}
		if deps != nil {
			allDeps = append(allDeps, deps...)
		}
	}

	if len(allDeps) == 0 {
		// Check if any parser detected a manifest (to give better diagnostic).
		var detectedAny string
		for _, p := range parsers {
			if ok, _ := p.Detect(absPath); ok {
				detectedAny = p.Name()
				break
			}
		}
		if detectedAny != "" {
			return nil, fmt.Errorf("%s manifest found at %s but no dependencies declared", detectedAny, absPath)
		}
		return nil, fmt.Errorf("no supported manifest files found in %s", absPath)
	}

	// 2. Query vulnerabilities.
	memCache := cache.New(cfg.CacheTTL)
	osvProvider := osv.New()

	vulnsByDep := make(map[string][]dependency.Vulnerability)

	// Deduplicate deps by ID.
	depMap := make(map[string]dependency.Dependency)
	for _, d := range allDeps {
		depMap[d.ID] = d
	}

	uniqueDeps := make([]dependency.Dependency, 0, len(depMap))
	for _, d := range depMap {
		uniqueDeps = append(uniqueDeps, d)
	}

	totalDeps := len(uniqueDeps)
	queried := 0
	cached := 0
	hasVulns := 0

	// Threshold filter: when set, we might skip some queries.
	shouldQuery := func(sev string) bool {
		if cfg.SeverityThreshold == "" {
			return true
		}
		return severityLeq(sev, cfg.SeverityThreshold)
	}

	for i, dep := range uniqueDeps {
		// Progress feedback to stderr (non-interfering with stdout).
		if totalDeps > 1 && (i == 0 || i == len(uniqueDeps)-1 || i%(totalDeps/4) == 0) {
			pct := int(float64(queried) / float64(totalDeps) * 100)
			if pct > 100 {
				pct = 100
			}
			_ = fmt.Sprintf("scanning %d/%d (%d%%)\n", i+1, totalDeps, pct)
		}

		// Check cache first.
		if cachedData, ok := memCache.Get(dep.ID); ok {
			vulnsByDep[dep.ID] = cachedData
			cached++
			queried++
			continue
		}

		if cfg.Offline {
			// In offline mode, skip API calls.
			continue
		}

		vulns, err := osvProvider.Query(dep)
		queried++
		if err != nil {
			// Log but don't fail.
			continue
		}

		if len(vulns) > 0 {
			hasVulns++
			// Filter by threshold.
			var filtered []dependency.Vulnerability
			for _, v := range vulns {
				if shouldQuery(v.Severity) {
					filtered = append(filtered, v)
				}
			}
			vulnsByDep[dep.ID] = filtered
			memCache.Set(dep.ID, filtered)
		} else {
			memCache.Set(dep.ID, nil)
		}
	}

	// 3. Build AnalysisResult.
	summary := buildSummary(uniqueDeps, vulnsByDep)
	riskScore := calculateRiskScore(summary)

	result := dependency.AnalysisResult{
		Project: dependency.Project{
			Name:      filepath.Base(absPath),
			Path:      absPath,
			Ecosystem: detectedEcosystem,
		},
		Dependencies:    uniqueDeps,
		Vulnerabilities: vulnsByDep,
		Summary:         summary,
		RiskScore:       riskScore,
		Timestamp:       start,
		Duration:        time.Since(start),
		ToolVersion:     cfg.ToolVersion,
	}

	// 4. Determine exit code.
	exitCode := 0
	if cfg.FailOnVulnerabilities && result.Summary.TotalVulns > 0 {
		exitCode = 1
	}

	return &Result{
		Analysis: result,
		ExitCode: exitCode,
	}, nil
}

// WriteReport writes the analysis result using the specified reporter.
func WriteReport(result dependency.AnalysisResult, format, outputPath string) error {
	var rep reporter.Reporter
	switch format {
	case "json":
		rep = reporter.NewJSON()
	case "json-summary":
		rep = reporter.NewJSONSummary()
	case "table", "":
		rep = table.New()
	case "markdown":
		rep = markdown.New()
	case "sarif":
		rep = sarif.New()
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	var out io.Writer
	if outputPath == "" || outputPath == "-" {
		out = os.Stdout
	} else {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	return rep.Generate(result, out)
}

func buildSummary(deps []dependency.Dependency, vulns map[string][]dependency.Vulnerability) dependency.RiskSummary {
	s := dependency.RiskSummary{
		TotalDependencies: len(deps),
	}

	sevOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

	for depID, vulns := range vulns {
		if len(vulns) == 0 {
			continue
		}
		s.VulnerableDeps++
		for _, v := range vulns {
			s.TotalVulns++
			switch v.Severity {
			case "CRITICAL":
				s.Critical++
			case "HIGH":
				s.High++
			case "MEDIUM":
				s.Medium++
			default:
				s.Low++
			}
		}
		_ = depID
		_ = sevOrder
	}

	return s
}

func calculateRiskScore(summary dependency.RiskSummary) float64 {
	// Simple risk scoring:
	// (critical * 10 + high * 7 + medium * 4 + low * 1) / totalDeps, capped at 10.
	if summary.TotalDependencies == 0 {
		return 0
	}
	score := float64(summary.Critical*10 + summary.High*7 + summary.Medium*4 + summary.Low*1)
	maxScore := float64(summary.TotalDependencies) * 10.0
	if maxScore == 0 {
		return 0
	}
	risk := score / maxScore * 10.0
	if risk > 10 {
		risk = 10
	}
	return risk
}

// severityLeq returns true if sev is less than or equal to threshold.
// "CRITICAL" >= "HIGH" >= "MEDIUM" >= "LOW".
func severityLeq(sev, threshold string) bool {
	order := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	s1, ok1 := order[sev]
	s2, ok2 := order[threshold]
	if !ok1 || !ok2 {
		return true
	}
	return s1 <= s2
}
