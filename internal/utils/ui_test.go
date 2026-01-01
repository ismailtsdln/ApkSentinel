package utils

import (
	"testing"
)

func TestUIFunctions(t *testing.T) {
	// These functions just print to console, but we call them to ensure no panics
	PrintBanner()
	Info("Test info message: %s", "hello")
	Success("Test success message: %d", 123)
	Warning("Test warning message")
	Error("Test error message")
}
