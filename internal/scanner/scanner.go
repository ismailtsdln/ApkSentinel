package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/ismailtsdln/ApkSentinel/internal/analyzer"
)

// Pattern defines a regex pattern for secret detection.
type Pattern struct {
	Name       string `json:"name"`
	Regex      string `json:"regex"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Compiled   *regexp.Regexp
}

// Result represents a finding during a scan.
type Result struct {
	File        string
	Line        int
	Content     string
	PatternName string
	Severity    string
	Confidence  string
}

// Scanner handles the scanning of files for sensitive patterns.
type Scanner struct {
	Patterns []Pattern
	Results  []Result
	mu       sync.Mutex
	resolver *analyzer.ObfuscationResolver
	context  *regexp.Regexp
}

// NewScanner initializes a Scanner with patterns from a JSON file.
func NewScanner(patternFilePath string) (*Scanner, error) {
	data, err := os.ReadFile(patternFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pattern file: %w", err)
	}

	var config struct {
		Patterns []Pattern `json:"patterns"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal patterns: %w", err)
	}

	for i := range config.Patterns {
		re, err := regexp.Compile(config.Patterns[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex for pattern %s: %w", config.Patterns[i].Name, err)
		}
		config.Patterns[i].Compiled = re
	}

	return &Scanner{
		Patterns: config.Patterns,
		resolver: analyzer.NewObfuscationResolver(),
		context:  regexp.MustCompile(`(?i)(api|key|secret|token|auth|pwd|pass|private|access)`),
	}, nil
}

// ScanFile scans a single file for patterns, including obfuscated strings and context.
func (s *Scanner) ScanFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return // Skip files that can't be opened
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 1. Normal Scan
		s.checkLine(line, filePath, lineNum)

		// 2. Obfuscation Scan (Base64)
		decoded := s.resolver.ResolveBase64(line)
		for _, d := range decoded {
			s.checkLine(d, filePath, lineNum)
		}
	}
}

func (s *Scanner) checkLine(line, filePath string, lineNum int) {
	for _, p := range s.Patterns {
		if p.Compiled.MatchString(line) {
			confidence := p.Confidence
			// Advanced Static Analysis: Context Check
			if s.context.MatchString(line) {
				confidence = "high"
			}

			s.mu.Lock()
			s.Results = append(s.Results, Result{
				File:        filePath,
				Line:        lineNum,
				Content:     line,
				PatternName: p.Name,
				Severity:    p.Severity,
				Confidence:  confidence,
			})
			s.mu.Unlock()
		}
	}
}

// ScanDirectory recursively scans a directory for secret patterns using goroutines.
func (s *Scanner) ScanDirectory(dirPath string) ([]Result, error) {
	var wg sync.WaitGroup
	filesChan := make(chan string, 100)

	// Worker goroutines
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range filesChan {
				s.ScanFile(filePath)
			}
		}()
	}

	// Walk directory and send files to channel
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			filesChan <- path
		}
		return nil
	})

	close(filesChan)
	wg.Wait()

	return s.Results, err
}
