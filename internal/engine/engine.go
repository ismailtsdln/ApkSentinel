package engine

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ismailtsdln/ApkSentinel/internal/analyzer"
	"github.com/ismailtsdln/ApkSentinel/internal/decompiler"
	"github.com/ismailtsdln/ApkSentinel/internal/report"
	"github.com/ismailtsdln/ApkSentinel/internal/scanner"
	"github.com/ismailtsdln/ApkSentinel/internal/utils"
)

// Config holds the configuration for the analysis engine.
type Config struct {
	InputPath      string
	OutputDir      string
	OutputFormat   string
	CustomPatterns string
	JadxPath       string
	Verbose        bool
}

// Engine orchestrates the APK analysis process.
type Engine struct {
	config Config
}

// NewEngine creates a new analysis engine.
func NewEngine(config Config) *Engine {
	return &Engine{config: config}
}

// Run executes the full analysis pipeline.
func (e *Engine) Run() error {
	// 1. Decompile
	decomp := decompiler.NewDecompiler(e.config.JadxPath, filepath.Join(e.config.OutputDir, "decompiled"))
	decompiledDir, err := decomp.Decompile(e.config.InputPath)
	if err != nil {
		return fmt.Errorf("decompilation failed: %w", err)
	}

	// 2. Scan
	patternPath := e.config.CustomPatterns
	if patternPath == "" {
		patternPath = "internal/patterns"
	}

	s, err := scanner.NewScanner(patternPath)
	if err != nil {
		return fmt.Errorf("scanner initialization failed: %w", err)
	}

	utils.Info("Scanning decompiled source code...")
	results, err := s.ScanDirectory(decompiledDir)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// 3. Manifest Analysis
	manifestPath := filepath.Join(decompiledDir, "resources", "AndroidManifest.xml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifestPath = filepath.Join(decompiledDir, "AndroidManifest.xml")
	}

	var findings []analyzer.SecurityFinding
	if _, err := os.Stat(manifestPath); err == nil {
		utils.Info("Analyzing AndroidManifest.xml...")
		findings, err = analyzer.AnalyzeManifest(manifestPath)
		if err != nil {
			utils.Warning("Failed to analyze manifest: %v", err)
		}
	} else {
		utils.Warning("AndroidManifest.xml not found, skipping manifest analysis")
	}

	// 4. Report
	r := report.Report{
		APKPath:  e.config.InputPath,
		Results:  results,
		Findings: findings,
	}

	utils.Success("Scan complete! Found %d secrets and %d security findings.", len(results), len(findings))

	if e.config.OutputFormat == "json" || e.config.OutputFormat == "both" {
		if err := report.SaveJSON(r, e.config.OutputDir); err != nil {
			utils.Error("Error saving JSON report: %v", err)
		}
	}

	if e.config.OutputFormat == "html" || e.config.OutputFormat == "both" {
		if err := report.SaveHTML(r, e.config.OutputDir); err != nil {
			utils.Error("Error saving HTML report: %v", err)
		}
	}

	return nil
}
