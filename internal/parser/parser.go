// Package parser defines the Parser interface and registry for dependency manifest parsers.
package parser

import "github.com/nxxo31/supply-radar/internal/dependency"

// Parser is the interface all manifest parsers must implement.
type Parser interface {
	// Name returns the parser identifier (e.g., "go-mod", "npm").
	Name() string
	// Detect checks if the given path contains a manifest for this ecosystem.
	// Returns true and the manifest file path if detected.
	Detect(path string) (bool, string)
	// Parse extracts dependencies from the manifest and lock files at the given path.
	Parse(path string) ([]dependency.Dependency, error)
	// Supported returns the list of file names this parser handles.
	Supported() []string
}
