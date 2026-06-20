// Package config handles configuration loading from flags, env vars, and config files.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config holds global configuration.
type Config struct {
	// Project path (positional argument).
	Path string
	// Output format.
	Format string
	// Output file path.
	Output string
	// Severity threshold (CRITICAL, HIGH, MEDIUM, LOW).
	SeverityThreshold string
	// Fail on vulnerabilities found.
	FailOnVulnerabilities bool
	// Offline mode (no API calls).
	Offline bool
	// Cache TTL duration string (e.g., "24h").
	CacheTTL string
	// Tool version.
	Version string
}

// FromEnv reads configuration from environment variables.
func FromEnv() Config {
	cfg := DefaultConfig()

	if v := os.Getenv("SUPPLY_RADAR_FORMAT"); v != "" {
		cfg.Format = v
	}
	if v := os.Getenv("SUPPLY_RADAR_OUTPUT"); v != "" {
		cfg.Output = v
	}
	if v := os.Getenv("SUPPLY_RADAR_THRESHOLD"); v != "" {
		cfg.SeverityThreshold = v
	}
	if os.Getenv("SUPPLY_RADAR_FAIL_ON_VULNS") == "true" {
		cfg.FailOnVulnerabilities = true
	}
	if os.Getenv("SUPPLY_RADAR_OFFLINE") == "true" {
		cfg.Offline = true
	}

	return cfg
}

// ToScannerConfig converts CLI config to scanner config.
func (c Config) ToScannerConfig() map[string]interface{} {
	cfg := map[string]interface{}{
		"path":                    c.Path,
		"severity_threshold":      c.SeverityThreshold,
		"fail_on_vulnerabilities": c.FailOnVulnerabilities,
		"format":                  c.Format,
		"output_path":             c.Output,
		"offline":                 c.Offline,
		"tool_version":            c.Version,
	}

	// Parse TTL.
	ttl := 24 * time.Hour
	if c.CacheTTL != "" {
		if d, err := time.ParseDuration(c.CacheTTL); err == nil {
			ttl = d
		}
	}
	cfg["cache_ttl"] = ttl

	return cfg
}

// DefaultConfig returns default configuration values.
func DefaultConfig() Config {
	return Config{
		Format:   "table",
		Output:   "-",
		CacheTTL: "24h",
		Version:  "v0.1.0",
	}
}

// ParseFlags parses command-line arguments.
// Returns the remaining non-flag arguments (typically the path).
func ParseFlags(args []string) (Config, []string, error) {
	cfg := DefaultConfig()

	// Load env vars first as defaults.
	cfg = FromEnv()

	// Simple flag parser using stdlib.
	fs := newFlagSet("supply-radar")

	fs.StringVar(&cfg.Format, "format", cfg.Format, "Output format: table, json, json-summary")
	fs.StringVar(&cfg.Output, "output", cfg.Output, "Output file path ('-' for stdout)")
	fs.StringVar(&cfg.SeverityThreshold, "threshold", cfg.SeverityThreshold, "Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)")
	fs.BoolVar(&cfg.FailOnVulnerabilities, "fail-on-vulnerabilities", cfg.FailOnVulnerabilities, "Exit with code 1 if vulnerabilities are found")
	fs.BoolVar(&cfg.Offline, "offline", cfg.Offline, "Disable network requests; use only cached data")

	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "Show version and exit")

	// Parse known flags.
	remaining, err := fs.Parse(args)
	if err != nil {
		// If it's an unknown flag, show help and continue or return error.
		return cfg, nil, err
	}

	if showVersion {
		fmt.Printf("supply-radar %s\n", cfg.Version)
		os.Exit(0)
	}

	// Validate format.
	validFormats := map[string]bool{"table": true, "json": true, "json-summary": true}
	if !validFormats[cfg.Format] {
		return cfg, nil, fmt.Errorf("invalid format: %s (valid: table, json, json-summary)", cfg.Format)
	}

	// Validate threshold.
	if cfg.SeverityThreshold != "" {
		validSev := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}
		if !validSev[strings.ToUpper(cfg.SeverityThreshold)] {
			return cfg, nil, fmt.Errorf("invalid threshold: %s (valid: CRITICAL, HIGH, MEDIUM, LOW)", cfg.SeverityThreshold)
		}
		cfg.SeverityThreshold = strings.ToUpper(cfg.SeverityThreshold)
	}

	return cfg, remaining, nil
}

// newFlagSet creates a flag.FlagSet with common settings.
func newFlagSet(name string) *flagSet {
	return &flagSet{name: name}
}

// flagSet is a simple wrapper around the flag package for basic parsing.
type flagSet struct {
	name string
	args []string
}

func (fs *flagSet) StringVar(p *string, name, value, usage string) {
	if os.Getenv("FLAG_"+name) == "" {
		// Simple approach: check positional args.
	}
	// We parse by hand to avoid importing flag package complications.
	_ = usage
	_ = name
	// This is a placeholder; actual parsing done in main.go.
	*p = value
}

func (fs *flagSet) BoolVar(p *bool, name string, value bool, usage string) {
	_ = usage
	_ = name
	*p = value
}

func (fs *flagSet) Parse(args []string) ([]string, error) {
	// We'll do manual flag parsing in main.go.
	// This is just a stub.
	return args, nil
}

// configFile returns the path to the config file.
func configFile() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "supply-radar", "config.yaml")
}
