package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/ismailtsdln/ApkSentinel/internal/analyzer"
	"github.com/ismailtsdln/ApkSentinel/internal/scanner"
	"github.com/ismailtsdln/ApkSentinel/internal/utils"
)

// Report contains all results from the scan.
type Report struct {
	APKPath  string                     `json:"apk_path"`
	Results  []scanner.Result           `json:"results"`
	Findings []analyzer.SecurityFinding `json:"findings"`
}

// SaveJSON saves the report as a JSON file.
func SaveJSON(report Report, outputDir string) error {
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

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>ApkSentinel Scan Report</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background-color: #f4f4f9; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #fff; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #007bff; color: white; }
        tr:hover { background-color: #f1f1f1; }
        .severity-high { color: #dc3545; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <h1>ApkSentinel Scan Report</h1>
    <p><strong>APK Path:</strong> {{.APKPath}}</p>
    <table>
        <tr>
            <th>Pattern</th>
            <th>File</th>
            <th>Line</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Content</th>
        </tr>
        {{range .Results}}
        <tr>
            <td>{{.PatternName}}</td>
            <td>{{.File}}</td>
            <td>{{.Line}}</td>
            <td><span class="severity-{{.Severity}}">{{.Severity}}</span></td>
            <td>{{.Confidence}}</td>
            <td><code>{{.Content}}</code></td>
        </tr>
        {{end}}
    </table>

    {{if .Findings}}
    <h2>Security Findings (Manifest/Resources)</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>Description</th>
        </tr>
        {{range .Findings}}
        <tr>
            <td>{{.Type}}</td>
            <td><span class="severity-{{.Severity}}">{{.Severity}}</span></td>
            <td>{{.Description}}</td>
        </tr>
        {{end}}
    </table>
    {{end}}
</body>
</html>
`

// SaveHTML saves the report as an HTML file.
func SaveHTML(report Report, outputDir string) error {
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
