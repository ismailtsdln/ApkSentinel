<div align="center">

# 🛡️ ApkSentinel

**Advanced APK Static Analysis & Secret Detection Tool**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 📋 Overview

ApkSentinel is a powerful, high-performance CLI tool designed for **security researchers**, **penetration testers**, and **Android developers** to perform comprehensive static analysis on APK files. It detects hard-coded secrets, API keys, sensitive URLs, and security misconfigurations with advanced obfuscation resolution capabilities.

### Why ApkSentinel?

- 🚀 **High Performance**: Parallel processing with goroutines for fast analysis
- 🧠 **Intelligent Detection**: Context-aware pattern matching with confidence scoring
- 🔓 **Obfuscation Resolver**: Automatically decodes Base64 and other encoded strings
- 📊 **Multiple Output Formats**: JSON and HTML reports with detailed findings
- 🔌 **Plugin-Ready**: Extensible pattern system for custom detection rules
- 🛠️ **CI/CD Integration**: Ready-to-use GitHub Actions & GitLab CI/CD workflows

---

## ✨ Features

### Core Capabilities

- **APK Decompilation**: Leverages `jadx` for DEX to Java/Smali conversion
- **Secret Scanning**: Regex-based detection for:
  - Google API Keys
  - Firebase URLs
  - AWS Access Keys
  - OAuth Tokens
  - GitHub Tokens
  - And many more...

### Advanced Analysis

- **Obfuscation Resolution**: Detects and decodes Base64-encoded secrets
- **Context-Aware Scanning**: Identifies variable names like `api_key`, `secret`, `token`
- **Manifest Security Audit**: Detects `debuggable`, `allowBackup`, and Network Security configurations
- **Root & SSL Detection**: Built-in rules for Root Detection and SSL Pinning mechanisms

### Reporting & Integration

- **Rich Reports**: JSON and HTML formats with severity classification
- **CI/CD Ready**: Pre-configured workflows for GitHub Actions and GitLab
- **Colored CLI**: Beautiful terminal output with progress indicators

---

## 🚀 Installation

### Prerequisites

- Go 1.25 or higher
- [jadx](https://github.com/skylot/jadx) installed and accessible in PATH

### Install via Go

```bash
go install -v github.com/ismailtsdln/ApkSentinel@latest
```

### Build from Source

```bash
git clone https://github.com/ismailtsdln/ApkSentinel.git
cd ApkSentinel
go build -o apk-sentinel cmd/apk-sentinel.go
```

---

## 📖 Usage

### Basic Scan

```bash
apk-sentinel -i app.apk -o ./report -f json
```

### Advanced Usage

```bash
# Scan with custom patterns
apk-sentinel -i app.apk -p custom-patterns.json -o ./report

# Generate both JSON and HTML reports
apk-sentinel -i app.apk -o ./report -f both

# Specify custom jadx path
apk-sentinel -i app.apk --jadx-path /usr/local/bin/jadx -o ./report

# Verbose output
apk-sentinel -i app.apk -v
```

### Command-Line Options

```
Flags:
  -i, --input string       Input APK path (required)
  -o, --output string      Output directory (default "./report")
  -f, --format string      Output format: json|html|both (default "json")
  -p, --pattern string     Custom pattern file or directory (JSON)
      --jadx-path string   Path to jadx executable (default "jadx")
  -v, --verbose            Show verbose output
  -h, --help               Display help information
```

---

## 🔍 Detection Patterns

ApkSentinel comes with built-in patterns for detecting:

| Category | Examples |
|----------|----------|
| **API Keys** | Google API, Firebase, AWS, Azure |
| **OAuth Tokens** | Facebook, GitHub, Slack |
| **Secrets** | Private keys, passwords, auth tokens |
| **URLs** | Internal endpoints, staging servers |
| **Root Detection** | RootBeer, Su binary check, Magisk, Test-keys |
| **SSL Pinning** | OkHttp CertificatePinner, TrustKit, TrustManager |

### Adding Custom Patterns

Create a JSON file with your patterns:

```json
{
  "patterns": [
    {
      "name": "Custom API Key",
      "regex": "customapi_[0-9a-zA-Z]{32}",
      "severity": "high",
      "confidence": "high"
    }
  ]
}
```

Use it with `-p` flag:

```bash
apk-sentinel -i app.apk -p custom-patterns.json
```

---

## 📊 Sample Report

### JSON Output

```json
{
  "apk_path": "app.apk",
  "results": [
    {
      "file": "com/example/Config.java",
      "line": 42,
      "pattern_name": "Google API Key",
      "severity": "high",
      "confidence": "high",
      "content": "private static final String API_KEY = \"AIza...\";"
    }
  ],
  "findings": [
    {
      "type": "Manifest",
      "description": "Application is debuggable",
      "severity": "high"
    }
  ]
}
```

---

## 🔧 CI/CD Integration

### GitHub Actions

ApkSentinel includes a ready-to-use GitHub Actions workflow:

```yaml
# .github/workflows/scan.yml
name: APK Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run ApkSentinel
        run: |
          go install github.com/ismailtsdln/ApkSentinel@latest
          apk-sentinel -i app.apk -o results -f both
```

### GitLab CI/CD

```yaml
# .gitlab-ci.yml
scan_apk:
  script:
    - go build -o apk-sentinel cmd/apk-sentinel.go
    - ./apk-sentinel -i app.apk -o results -f both
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ismail Tasdelen**

- GitHub: [@ismailtsdln](https://github.com/ismailtsdln)
- LinkedIn: [ismailtasdelen](https://www.linkedin.com/in/ismailtasdelen/)

---

## 🙏 Acknowledgments

- [jadx](https://github.com/skylot/jadx) - Dex to Java decompiler
- [cobra](https://github.com/spf13/cobra) - CLI framework
- [fatih/color](https://github.com/fatih/color) - Colored terminal output

---

## ⚠️ Disclaimer

This tool is intended for **security research and educational purposes only**. Always obtain proper authorization before testing applications you don't own. The authors are not responsible for any misuse or damage caused by this tool.

---

<div align="center">

**If you find ApkSentinel useful, please consider giving it a ⭐ on GitHub!**

Made with ❤️ by [Ismail Tasdelen](https://github.com/ismailtsdln)

</div>
