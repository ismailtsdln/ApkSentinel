package main

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/ApkSentinel/internal/engine"
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

		// Validation
		if inputPath == "" {
			utils.Error("Input APK path is required.")
			cmd.Help()
			os.Exit(1)
		}

		// Validate output format
		if outputFormat != "json" && outputFormat != "html" && outputFormat != "both" {
			utils.Error("Invalid output format. Must be 'json', 'html', or 'both'.")
			os.Exit(1)
		}

		// Ensure output directory exists
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			utils.Error("Failed to create output directory: %v", err)
			os.Exit(1)
		}

		cfg := engine.Config{
			InputPath:      inputPath,
			OutputDir:      outputDir,
			OutputFormat:   outputFormat,
			CustomPatterns: customPatterns,
			JadxPath:       jadxPath,
			Verbose:        verbose,
		}

		e := engine.NewEngine(cfg)
		if err := e.Run(); err != nil {
			utils.Error("Analysis failed: %v", err)
			os.Exit(1)
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
