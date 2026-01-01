package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewScanner(t *testing.T) {
	// Create a dummy pattern file
	patternDir := t.TempDir()
	patternFile := filepath.Join(patternDir, "test_patterns.json")
	patternData := `{
		"patterns": [
			{"name": "Test Pattern", "regex": "test-secret", "severity": "high", "confidence": "high"}
		]
	}`
	err := os.WriteFile(patternFile, []byte(patternData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test pattern file: %v", err)
	}

	s, err := NewScanner(patternDir)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	if len(s.Patterns) != 1 {
		t.Errorf("Expected 1 pattern, got %d", len(s.Patterns))
	}

	if s.Patterns[0].Name != "Test Pattern" {
		t.Errorf("Expected pattern name 'Test Pattern', got '%s'", s.Patterns[0].Name)
	}
}

func TestScanFile(t *testing.T) {
	patternDir := t.TempDir()
	patternFile := filepath.Join(patternDir, "test_patterns.json")
	patternData := `{
		"patterns": [
			{"name": "API Key", "regex": "AKIA[0-9A-Z]{16}", "severity": "high", "confidence": "high"}
		]
	}`
	os.WriteFile(patternFile, []byte(patternData), 0644)

	s, _ := NewScanner(patternDir)

	testFile := filepath.Join(t.TempDir(), "test.java")
	content := "public String key = \"AKIA1234567890ABCDEF\";"
	os.WriteFile(testFile, []byte(content), 0644)

	s.ScanFile(testFile)

	if len(s.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(s.Results))
	}

	if s.Results[0].PatternName != "API Key" {
		t.Errorf("Expected result pattern name 'API Key', got '%s'", s.Results[0].PatternName)
	}
}
