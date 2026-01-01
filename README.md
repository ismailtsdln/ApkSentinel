# ApkSentinel

A high-performance APK static analysis tool for secret detection.

## Features

- **APK Decompilation**: Uses `jadx` to decompile APKs.
- **Secret Scanning**: Regex-based detection of API keys, tokens, and URLs.
- **Parallel Processing**: Fast analysis using Go's concurrency.
- **Modular Reporting**: JSON and HTML report outputs.
- **Extensible**: Add custom patterns via JSON/YAML.

## Installation

```bash
go install -v github.com/ismailtsdln/ApkSentinel@latest
```

## Usage

```bash
# Basic scan
apk-sentinel -i app.apk -o ./report -f json

# Scan with custom patterns
apk-sentinel -i app.apk -p my-patterns.json -o ./report
```

## License

MIT
