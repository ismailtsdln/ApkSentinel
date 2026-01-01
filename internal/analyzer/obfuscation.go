package analyzer

import (
	"encoding/base64"
	"regexp"
)

// ObfuscationResolver provides methods to decode common obfuscation techniques.
type ObfuscationResolver struct {
	base64Regex *regexp.Regexp
}

// NewObfuscationResolver initializes a new ObfuscationResolver.
func NewObfuscationResolver() *ObfuscationResolver {
	return &ObfuscationResolver{
		// Regex to find potential Base64 strings (minimum length 8 to avoid false positives)
		base64Regex: regexp.MustCompile(`[A-Za-z0-9+/]{8,}=*`),
	}
}

// ResolveBase64 looks for Base64 encoded strings in a line and returns the decoded versions.
func (or *ObfuscationResolver) ResolveBase64(input string) []string {
	var decodedStrings []string
	matches := or.base64Regex.FindAllString(input, -1)

	for _, match := range matches {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err == nil {
			// Only add if it contains printable characters (rough check)
			if isPrintable(decoded) {
				decodedStrings = append(decodedStrings, string(decoded))
			}
		}
	}
	return decodedStrings
}

// ResolveXOR attempts simple XOR decoding (future improvement: brute force common keys).
func (or *ObfuscationResolver) ResolveXOR(input string, key byte) string {
	data := []byte(input)
	for i := range data {
		data[i] ^= key
	}
	return string(data)
}

// isPrintable checks if the byte slice contains mostly printable ASCII characters.
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.8
}
