package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeManifest(t *testing.T) {
	manifestData := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <uses-permission android:name="android.permission.READ_SMS" />
    <application android:debuggable="true" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>`

	tempDir := t.TempDir()
	manifestFile := filepath.Join(tempDir, "AndroidManifest.xml")
	os.WriteFile(manifestFile, []byte(manifestData), 0644)

	findings, err := AnalyzeManifest(manifestFile)
	if err != nil {
		t.Fatalf("AnalyzeManifest failed: %v", err)
	}

	expectedFindings := 4 // 1 permission, 1 debuggable, 1 allowBackup, 1 exported activity
	if len(findings) != expectedFindings {
		t.Errorf("Expected %d findings, got %d", expectedFindings, len(findings))
	}

	// Verify specific findings
	hasDebuggable := false
	hasSMSPermission := false
	for _, f := range findings {
		if f.Description == "Application is debuggable" {
			hasDebuggable = true
		}
		if f.Type == "Permission" && f.Description == "Dangerous permission requested: android.permission.READ_SMS" {
			hasSMSPermission = true
		}
	}

	if !hasDebuggable {
		t.Errorf("Finding 'Application is debuggable' not found")
	}
	if !hasSMSPermission {
		t.Errorf("Finding 'READ_SMS permission' not found")
	}
}

func TestResolveBase64(t *testing.T) {
	resolver := NewObfuscationResolver()

	// Test basic Base64
	input := "The secret is SGVsbG8gV29ybGQh" // sgVsbG8gV29ybGQh -> "Hello World!"
	decoded := resolver.ResolveBase64(input)

	found := false
	for _, d := range decoded {
		if d == "Hello World!" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected to find 'Hello World!', got %v", decoded)
	}
}

func TestIsPrintable(t *testing.T) {
	if !isPrintable([]byte("Hello World")) {
		t.Errorf("Expected 'Hello World' to be printable")
	}
	if isPrintable([]byte{0, 1, 2, 3}) {
		t.Errorf("Expected binary data to be non-printable")
	}
}
