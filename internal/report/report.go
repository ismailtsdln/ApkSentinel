package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/ismailtsdln/ApkSentinel/internal/analyzer"
	"github.com/ismailtsdln/ApkSentinel/internal/scanner"
	"github.com/ismailtsdln/ApkSentinel/internal/utils"
)

//go:embed report.html
var htmlTemplate string

// Report contains all results from the scan.
type Report struct {
	APKPath  string                     `json:"apk_path"`
	Results  []scanner.Result           `json:"results"`
	Findings []analyzer.SecurityFinding `json:"findings"`
}

// SaveJSON saves the report as a JSON file.
func SaveJSON(report Report, outputDir string) error {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	filePath := filepath.Join(outputDir, "report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	utils.Success("JSON report saved to %s", filePath)
	return nil
}

// SaveHTML saves the report as an HTML file.
func SaveHTML(report Report, outputDir string) error {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	filePath := filepath.Join(outputDir, "report.html")
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, report); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	utils.Success("HTML report saved to %s", filePath)
	return nil
}
