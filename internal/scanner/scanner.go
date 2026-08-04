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
	"github.com/nxxo31/supply-radar/internal/parser/pypi"
	"github.com/nxxo31/supply-radar/internal/reporter"
	"github.com/nxxo31/supply-radar/internal/reporter/markdown"
	"github.com/nxxo31/supply-radar/internal/reporter/sarif"
	"github.com/nxxo31/supply-radar/internal/reporter/sbom"
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
	// Format specifies the output format ("table", "json", "json-summary", etc.).
	Format string
	// OutputPath specifies where to write the report ("-" for stdout).
	OutputPath string
	// Offline enables offline mode (uses only cached data).
	Offline bool
	// CacheTTL sets the vulnerability cache TTL.
	CacheTTL time.Duration
	// ToolVersion is the supply-radar version string.
	ToolVersion string
	// Recursive enables recursive scanning of subdirectories for monorepos.
	Recursive bool
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
		pypi.New(),
	}

	var allDeps []dependency.Dependency
	// detectedEcosystems records every ecosystem discovered across the scan.
	// In non-recursive mode this collapses to a single ecosystem at the root;
	// in recursive mode it captures the union of ecosystems across all subprojects
	// (a monorepo commonly mixes go-mod, npm and pypi manifests per service).
	detectedEcosystems := make(map[string]struct{})
	var detectedEcosystem string

	if !cfg.Recursive {
		// Non-recursive mode: scan only the given directory.
		for _, p := range parsers {
			detected, _ := p.Detect(absPath)
			if !detected {
				continue
			}
			detectedEcosystems[p.Name()] = struct{}{}
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
	} else {
		// Recursive mode: walk the directory tree and scan every directory
		// that contains a manifest. We prune dependency vendor directories
		// (node_modules, vendor, .git, etc.) so we do not re-scan the
		// universe of transitive deps — we want the manifests the user
		// actually owns per service, not the contents of every lockfile
		// shipped inside third-party packages.
		err := filepath.WalkDir(absPath, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !d.IsDir() {
				return nil
			}
			base := d.Name()
			// Prune directories that contain their own dependency manifests
			// we do not want to treat as first-class subprojects. Returning
			// filepath.SkipDir avoids descending into potentially huge trees
			// (node_modules alone can contain thousands of nested manifests).
			if shouldSkipDir(base) {
				return filepath.SkipDir
			}
			var depsInDir []dependency.Dependency
			for _, p := range parsers {
				if detected, _ := p.Detect(path); detected {
					detectedEcosystems[p.Name()] = struct{}{}
					deps, pErr := p.Parse(path)
					if pErr != nil {
						// Skip this directory for this parser, but continue with others.
						continue
					}
					depsInDir = append(depsInDir, deps...)
				}
			}
			allDeps = append(allDeps, depsInDir...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// Resolve the canonical ecosystem label: in non-recursive mode this is the
	// single detected ecosystem. In recursive mode we report the union — "multi"
	// when more than one ecosystem was found, otherwise the single ecosystem.
	detectedEcosystem = resolveEcosystemLabel(detectedEcosystems, cfg.Recursive, detectedEcosystem)

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

	// Deduplicate deps by ID and Path (to keep duplicates across subprojects).
	depMap := make(map[string]dependency.Dependency)
	for _, d := range allDeps {
		key := d.ID + "@" + d.Path
		depMap[key] = d
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
			pct := int(float64(i+1) / float64(totalDeps) * 100)
			if pct > 100 {
				pct = 100
			}
			fmt.Fprintf(os.Stderr, "\rscanning %d/%d (%d%%)", i+1, totalDeps, pct)
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

	// Clear progress line.
	if totalDeps > 1 {
		fmt.Fprintln(os.Stderr, "")
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
	case "sbom-spdx":
		rep = sbom.NewSPDX()
	case "sbom-cyclonedx":
		rep = sbom.NewCycloneDX()
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

// shouldSkipDir reports whether a directory entry should be pruned during
// recursive scanning. These are well-known directory names that either hold
// transitive dependencies (re-scanning them duplicates work and risks picking
// up vendored manifests the user does not own) or are pure metadata stores.
//
// Pruning node_modules is especially important: a typical install contains
// thousands of nested package.json files, none of them representing the
// project being scanned. The same applies to Go's vendor/ trees. VCS metadata
// (".git", ".hg", ".svn") contains no manifests worth scanning and is hidden
// by convention. "dist", "build", and "target" are conventional output
// directories that may contain generated manifests.
func shouldSkipDir(name string) bool {
	switch name {
	case "node_modules", "vendor":
		return true
	case ".git", ".hg", ".svn":
		return true
	case "dist", "build", "target", ".next", ".cache":
		return true
	}
	return false
}

// resolveEcosystemLabel collapses a set of detected ecosystems into a single
// downstream-friendly label. In non-recursive mode the caller already set
// detectedEcosystem to the single match; we honour it. In recursive mode we
// report "multi" when more than one ecosystem appears (typical of polyglot
// monorepos with go-mod/npm/pypi services side by side), the lone ecosystem
// when only one is present, and whatever the caller passed through otherwise.
func resolveEcosystemLabel(found map[string]struct{}, recursive bool, fallback string) string {
	if !recursive {
		// Non-recursive: the loop above set the single detected ecosystem already.
		if fallback != "" {
			return fallback
		}
		// Fall back to the first (only) ecosystem in the set if fallback was empty.
		for eco := range found {
			return eco
		}
		return ""
	}
	switch len(found) {
	case 0:
		return ""
	case 1:
		for eco := range found {
			return eco
		}
		return "" // unreachable; satisfies the compiler
	default:
		return "multi"
	}
}
