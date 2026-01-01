package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"runtime"

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
	Patterns           []Pattern
	Results            []Result
	mu                 sync.Mutex
	resolver           *analyzer.ObfuscationResolver
	context            *regexp.Regexp
	excludedExtensions map[string]bool
}

// NewScanner initializes a Scanner with patterns from one or more JSON files.
func NewScanner(patternPath string) (*Scanner, error) {
	var patternFiles []string

	info, err := os.Stat(patternPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access pattern path: %w", err)
	}

	if info.IsDir() {
		files, err := os.ReadDir(patternPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read pattern directory: %w", err)
		}
		for _, f := range files {
			if !f.IsDir() && filepath.Ext(f.Name()) == ".json" {
				patternFiles = append(patternFiles, filepath.Join(patternPath, f.Name()))
			}
		}
	} else {
		patternFiles = append(patternFiles, patternPath)
	}

	var allPatterns []Pattern
	for _, pf := range patternFiles {
		data, err := os.ReadFile(pf)
		if err != nil {
			continue // Skip unreadable files
		}

		var config struct {
			Patterns []Pattern `json:"patterns"`
		}
		if err := json.Unmarshal(data, &config); err == nil {
			for i := range config.Patterns {
				re, err := regexp.Compile(config.Patterns[i].Regex)
				if err == nil {
					config.Patterns[i].Compiled = re
					allPatterns = append(allPatterns, config.Patterns[i])
				}
			}
		}
	}

	if len(allPatterns) == 0 {
		return nil, fmt.Errorf("no valid patterns found in %s", patternPath)
	}

	return &Scanner{
		Patterns: allPatterns,
		resolver: analyzer.NewObfuscationResolver(),
		context:  regexp.MustCompile(`(?i)(api|key|secret|token|auth|pwd|pass|private|access)`),
		excludedExtensions: map[string]bool{
			".png":  true,
			".jpg":  true,
			".jpeg": true,
			".gif":  true,
			".webp": true,
			".svg":  true,
			".mp3":  true,
			".mp4":  true,
			".wav":  true,
			".pdf":  true,
			".dex":  true,
			".arsc": true,
			".so":   true,
			".exe":  true,
			".dll":  true,
			".bin":  true,
			".dat":  true,
		},
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
	// Set a reasonable buffer size limit to avoid memory issues (10MB per line)
	const maxCapacity = 10 * 1024 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

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

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		// Log but don't fail - just skip this file
		return
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
	numWorkers := runtime.NumCPU() * 2

	// Worker goroutines
	for i := 0; i < numWorkers; i++ {
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
			ext := filepath.Ext(path)
			if !s.excludedExtensions[ext] {
				filesChan <- path
			}
		}
		return nil
	})

	close(filesChan)
	wg.Wait()

	return s.Results, err
}
