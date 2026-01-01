package analyzer

import (
	"encoding/xml"
	"fmt"
	"os"
)

// Manifest represents a simplified AndroidManifest.xml structure.
type Manifest struct {
	XMLName     xml.Name     `xml:"manifest"`
	Permissions []Permission `xml:"uses-permission"`
	Application Application  `xml:"application"`
}

// Permission represents a uses-permission tag.
type Permission struct {
	Name string `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

// Application represents the application tag in AndroidManifest.xml.
type Application struct {
	Debuggable            string      `xml:"http://schemas.android.com/apk/res/android debuggable,attr"`
	AllowBackup           string      `xml:"http://schemas.android.com/apk/res/android allowBackup,attr"`
	NetworkSecurityConfig string      `xml:"http://schemas.android.com/apk/res/android networkSecurityConfig,attr"`
	Activities            []Component `xml:"activity"`
	Services              []Component `xml:"service"`
	Receivers             []Component `xml:"receiver"`
}

// Component represents an activity, service, or receiver.
type Component struct {
	Name     string `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported string `xml:"http://schemas.android.com/apk/res/android exported,attr"`
}

// SecurityFinding represents a security issue found in the manifest or resources.
type SecurityFinding struct {
	Type        string
	Description string
	Severity    string
}

var dangerousPermissions = map[string]bool{
	"android.permission.READ_SMS":               true,
	"android.permission.RECEIVE_SMS":            true,
	"android.permission.READ_CONTACTS":          true,
	"android.permission.WRITE_CONTACTS":         true,
	"android.permission.READ_CALL_LOG":          true,
	"android.permission.WRITE_CALL_LOG":         true,
	"android.permission.ACCESS_FINE_LOCATION":   true,
	"android.permission.ACCESS_COARSE_LOCATION": true,
	"android.permission.RECORD_AUDIO":           true,
	"android.permission.CAMERA":                 true,
	"android.permission.READ_EXTERNAL_STORAGE":  true,
	"android.permission.WRITE_EXTERNAL_STORAGE": true,
	"android.permission.GET_ACCOUNTS":           true,
	"android.permission.USE_SIP":                true,
	"android.permission.PROCESS_OUTGOING_CALLS": true,
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

	// 1. Dangerous Permissions
	for _, p := range manifest.Permissions {
		if dangerousPermissions[p.Name] {
			findings = append(findings, SecurityFinding{
				Type:        "Permission",
				Description: "Dangerous permission requested: " + p.Name,
				Severity:    "medium",
			})
		}
	}

	// 2. Debuggable
	if manifest.Application.Debuggable == "true" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Application is debuggable",
			Severity:    "high",
		})
	}

	// 3. AllowBackup
	if manifest.Application.AllowBackup == "true" || manifest.Application.AllowBackup == "" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Application allows backup (allowBackup should be explicitly false)",
			Severity:    "medium",
		})
	}

	// 4. Network Security Config
	if manifest.Application.NetworkSecurityConfig != "" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Network Security Configuration is defined: " + manifest.Application.NetworkSecurityConfig,
			Severity:    "info",
		})
	}

	// 5. Exported Components
	checkExported(manifest.Application.Activities, "Activity", &findings)
	checkExported(manifest.Application.Services, "Service", &findings)
	checkExported(manifest.Application.Receivers, "Receiver", &findings)

	return findings, nil
}

func checkExported(components []Component, componentType string, findings *[]SecurityFinding) {
	for _, c := range components {
		if c.Exported == "true" {
			*findings = append(*findings, SecurityFinding{
				Type:        componentType,
				Description: fmt.Sprintf("Exported %s found: %s", componentType, c.Name),
				Severity:    "medium",
			})
		}
	}
}
