package main

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/ApkSentinel/internal/analyzer"
	"github.com/ismailtsdln/ApkSentinel/internal/scanner"
)

func main() {
	// 1. Test Scanner with new patterns
	s, err := scanner.NewScanner("internal/patterns")
	if err != nil {
		fmt.Printf("Error initializing scanner: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Scanning test assets...")
	results, err := s.ScanDirectory("test_assets/sources")
	if err != nil {
		fmt.Printf("Error during scan: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d patterns in source code.\n", len(results))
	for _, r := range results {
		fmt.Printf("- [%s] %s (Line %d): %s\n", r.Severity, r.PatternName, r.Line, r.Content)
	}

	// 2. Test Manifest Analysis
	manifestPath := "test_assets/resources/AndroidManifest.xml"
	fmt.Println("\nAnalyzing test manifest...")
	findings, err := analyzer.AnalyzeManifest(manifestPath)
	if err != nil {
		fmt.Printf("Error during manifest analysis: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d security findings in manifest.\n", len(findings))
	for _, f := range findings {
		fmt.Printf("- [%s] %s: %s\n", f.Severity, f.Type, f.Description)
	}
}
