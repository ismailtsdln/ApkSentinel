package decompiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ismailtsdln/ApkSentinel/internal/utils"
)

// Decompiler handles the APK to Java/Smali conversion logic.
type Decompiler struct {
	JadxPath  string
	OutputDir string
}

// NewDecompiler returns a new Decompiler instance.
func NewDecompiler(jadxPath, outputDir string) *Decompiler {
	return &Decompiler{
		JadxPath:  jadxPath,
		OutputDir: outputDir,
	}
}

// Decompile executes the jadx command to decompile the given APK path.
func (d *Decompiler) Decompile(apkPath string) (string, error) {
	if _, err := os.Stat(apkPath); os.IsNotExist(err) {
		return "", fmt.Errorf("APK file not found: %s", apkPath)
	}

	absAPKPath, err := filepath.Abs(apkPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path of APK: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(d.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	utils.Info("Decompiling %s to %s...", apkPath, d.OutputDir)

	// Build the jadx command
	// -d: output directory
	cmd := exec.Command(d.JadxPath, "-d", d.OutputDir, absAPKPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("jadx execution failed: %w", err)
	}

	utils.Success("Decompilation completed successfully.")
	return d.OutputDir, nil
}
