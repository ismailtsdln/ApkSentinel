package analyzer

import (
	"encoding/xml"
	"fmt"
	"os"
)

// Manifest represents a simplified AndroidManifest.xml structure.
type Manifest struct {
	XMLName     xml.Name    `xml:"manifest"`
	Application Application `xml:"application"`
}

// Application represents the application tag in AndroidManifest.xml.
type Application struct {
	Debuggable  string `xml:"http://schemas.android.com/apk/res/android debuggable,attr"`
	AllowBackup string `xml:"http://schemas.android.com/apk/res/android allowBackup,attr"`
}

// SecurityFinding represents a security issue found in the manifest or resources.
type SecurityFinding struct {
	Type        string
	Description string
	Severity    string
}

// AnalyzeManifest parses AndroidManifest.xml and returns security findings.
func AnalyzeManifest(manifestPath string) ([]SecurityFinding, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest Manifest
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	var findings []SecurityFinding

	if manifest.Application.Debuggable == "true" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Application is debuggable",
			Severity:    "high",
		})
	}

	if manifest.Application.AllowBackup != "false" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Application allows backup (allowBackup is not false)",
			Severity:    "medium",
		})
	}

	return findings, nil
}
