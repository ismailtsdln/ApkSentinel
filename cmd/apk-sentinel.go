package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ismailtsdln/ApkSentinel/internal/analyzer"
	"github.com/ismailtsdln/ApkSentinel/internal/decompiler"
	"github.com/ismailtsdln/ApkSentinel/internal/report"
	"github.com/ismailtsdln/ApkSentinel/internal/scanner"
	"github.com/ismailtsdln/ApkSentinel/internal/utils"
	"github.com/spf13/cobra"
)

var (
	inputPath      string
	outputDir      string
	outputFormat   string
	customPatterns string
	jadxPath       string
	verbose        bool
)

var rootCmd = &cobra.Command{
	Use:   "apk-sentinel",
	Short: "ApkSentinel is a high-performance APK static analysis tool",
	Long: `ApkSentinel is a high-performance APK static analysis tool designed to 
detect hard-coded secrets, API keys, and sensitive URLs in Android applications.`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.PrintBanner()

		if inputPath == "" {
			utils.Error("Input APK path is required.")
			cmd.Help()
			os.Exit(1)
		}

		// 1. Decompile
		decomp := decompiler.NewDecompiler(jadxPath, filepath.Join(outputDir, "decompiled"))
		decompiledDir, err := decomp.Decompile(inputPath)
		if err != nil {
			utils.Error("Error during decompilation: %v", err)
			os.Exit(1)
		}

		// 2. Scan
		patternFile := customPatterns
		if patternFile == "" {
			// fallback to default patterns
			patternFile = "internal/patterns/default_patterns.json"
		}

		s, err := scanner.NewScanner(patternFile)
		if err != nil {
			utils.Error("Error initializing scanner: %v", err)
			os.Exit(1)
		}

		utils.Info("Scanning decompiled source code...")
		results, err := s.ScanDirectory(decompiledDir)
		if err != nil {
			utils.Error("Error during scan: %v", err)
			os.Exit(1)
		}

		// 3. Manifest Analysis
		manifestPath := filepath.Join(decompiledDir, "resources", "AndroidManifest.xml")
		// Sometimes jadx puts it in the root depending on version/config
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			manifestPath = filepath.Join(decompiledDir, "AndroidManifest.xml")
		}

		var findings []analyzer.SecurityFinding
		if _, err := os.Stat(manifestPath); err == nil {
			utils.Info("Analyzing AndroidManifest.xml...")
			findings, _ = analyzer.AnalyzeManifest(manifestPath)
		}

		// 4. Report
		r := report.Report{
			APKPath:  inputPath,
			Results:  results,
			Findings: findings,
		}

		if outputFormat == "json" || outputFormat == "both" {
			if err := report.SaveJSON(r, outputDir); err != nil {
				utils.Error("Error saving JSON report: %v", err)
			}
		}

		if outputFormat == "html" || outputFormat == "both" {
			if err := report.SaveHTML(r, outputDir); err != nil {
				utils.Error("Error saving HTML report: %v", err)
			}
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&inputPath, "input", "i", "", "Input APK path (required)")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "./report", "Output directory")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "json", "Output format (json|html)")
	rootCmd.PersistentFlags().StringVarP(&customPatterns, "pattern", "p", "", "Custom pattern file (JSON)")
	rootCmd.PersistentFlags().StringVar(&jadxPath, "jadx-path", "jadx", "Path to jadx executable")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Show verbose output")
}

func main() {
	Execute()
}
