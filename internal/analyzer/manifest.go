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
	Debuggable            string `xml:"http://schemas.android.com/apk/res/android debuggable,attr"`
	AllowBackup           string `xml:"http://schemas.android.com/apk/res/android allowBackup,attr"`
	NetworkSecurityConfig string `xml:"http://schemas.android.com/apk/res/android networkSecurityConfig,attr"`
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

	// AllowBackup should be explicitly set to false for production apps
	// Empty string means attribute is not set (default is true)
	if manifest.Application.AllowBackup == "true" || manifest.Application.AllowBackup == "" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Application allows backup (allowBackup should be explicitly false)",
			Severity:    "medium",
		})
	}

	if manifest.Application.NetworkSecurityConfig != "" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Network Security Configuration is defined: " + manifest.Application.NetworkSecurityConfig,
			Severity:    "info",
		})
	}

	return findings, nil
}
