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
	UsesCleartextTraffic  string      `xml:"http://schemas.android.com/apk/res/android usesCleartextTraffic,attr"`
	FullBackupContent     string      `xml:"http://schemas.android.com/apk/res/android fullBackupContent,attr"`
	Activities            []Component `xml:"activity"`
	Services              []Component `xml:"service"`
	Receivers             []Component `xml:"receiver"`
	Providers             []Component `xml:"provider"`
}

// Component represents an activity, service, receiver, or provider.
type Component struct {
	Name          string         `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported      string         `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	Permission    string         `xml:"http://schemas.android.com/apk/res/android permission,attr"`
	IntentFilters []IntentFilter `xml:"intent-filter"`
}

// IntentFilter represents an intent-filter within a component.
type IntentFilter struct {
	Actions []Action `xml:"action"`
}

// Action represents an action within an intent-filter.
type Action struct {
	Name string `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

// SecurityFinding represents a security issue found in the manifest or resources.
type SecurityFinding struct {
	Type        string
	Description string
	Severity    string
	MASVS       string
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

	// 1. Dangerous Permissions (MASVS-PRIVACY)
	for _, p := range manifest.Permissions {
		if dangerousPermissions[p.Name] {
			findings = append(findings, SecurityFinding{
				Type:        "Permission",
				Description: "Dangerous permission requested: " + p.Name,
				Severity:    "medium",
				MASVS:       "MASVS-PRIVACY-1",
			})
		}
	}

	// 2. Debuggable (MASVS-RESILIENCE)
	if manifest.Application.Debuggable == "true" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Application is debuggable",
			Severity:    "high",
			MASVS:       "MASVS-RESILIENCE-2",
		})
	}

	// 3. AllowBackup (MASVS-STORAGE)
	if manifest.Application.AllowBackup == "true" || manifest.Application.AllowBackup == "" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Application allows backup (allowBackup should be explicitly false)",
			Severity:    "medium",
			MASVS:       "MASVS-STORAGE-2",
		})
	}

	// 4. Cleartext Traffic (MASVS-NETWORK)
	if manifest.Application.UsesCleartextTraffic == "true" || manifest.Application.UsesCleartextTraffic == "" {
		findings = append(findings, SecurityFinding{
			Type:        "Network",
			Description: "Application allows cleartext traffic (HTTP). Set usesCleartextTraffic to false.",
			Severity:    "high",
			MASVS:       "MASVS-NETWORK-1",
		})
	}

	// 5. Network Security Config
	if manifest.Application.NetworkSecurityConfig != "" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Network Security Configuration is defined: " + manifest.Application.NetworkSecurityConfig,
			Severity:    "info",
			MASVS:       "MASVS-NETWORK-1",
		})
	}

	// 6. Full Backup Content
	if manifest.Application.FullBackupContent == "" && manifest.Application.AllowBackup != "false" {
		findings = append(findings, SecurityFinding{
			Type:        "Manifest",
			Description: "Full backup content not specified. Define android:fullBackupContent to control backup",
			Severity:    "low",
			MASVS:       "MASVS-STORAGE-2",
		})
	}

	// 7. Exported Components (MASVS-PLATFORM)
	checkExportedWithIntentFilter(manifest.Application.Activities, "Activity", &findings)
	checkExportedWithIntentFilter(manifest.Application.Services, "Service", &findings)
	checkExportedWithIntentFilter(manifest.Application.Receivers, "Receiver", &findings)
	checkExportedWithIntentFilter(manifest.Application.Providers, "Provider", &findings)

	return findings, nil
}

func checkExportedWithIntentFilter(components []Component, componentType string, findings *[]SecurityFinding) {
	for _, c := range components {
		// If explicitly exported=true
		if c.Exported == "true" {
			// Check if it has permission protection
			if c.Permission == "" {
				*findings = append(*findings, SecurityFinding{
					Type:        componentType,
					Description: fmt.Sprintf("Exported %s without permission: %s", componentType, c.Name),
					Severity:    "high",
					MASVS:       "MASVS-PLATFORM-1",
				})
			} else {
				*findings = append(*findings, SecurityFinding{
					Type:        componentType,
					Description: fmt.Sprintf("Exported %s found (with permission): %s", componentType, c.Name),
					Severity:    "info",
					MASVS:       "MASVS-PLATFORM-1",
				})
			}
		}

		// If component has intent-filter, it's implicitly exported (Android < 12)
		if len(c.IntentFilters) > 0 && c.Exported == "" {
			*findings = append(*findings, SecurityFinding{
				Type:        componentType,
				Description: fmt.Sprintf("%s with intent-filter is implicitly exported: %s (set exported explicitly)", componentType, c.Name),
				Severity:    "medium",
				MASVS:       "MASVS-PLATFORM-1",
			})
		}
	}
}
