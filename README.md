# Unified Security Scanner

> A comprehensive security scanning platform for npm/React projects with industry-leading false positive reduction (<5%)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](package.json)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## 🚀 Features

- **Multi-Tool Orchestration**: Seamlessly integrates TruffleHog, Semgrep, and custom scanners
- **False Positive Reduction**: ML-powered and rule-based filtering achieves <5% FP rate
- **React/npm Specialization**: Custom rules for React hooks, Context API, and npm package security
- **Malicious Package Detection**: Identifies typosquatting, dependency confusion, and malicious scripts
- **Technical Debt Tracking**: Reports outdated packages, EOL dependencies, and upgrade paths
- **Multiple Output Formats**: SARIF (GitHub Security), JSON, HTML, and terminal output
- **CI/CD Ready**: Native GitHub Actions support, works with all major CI/CD platforms

## 📦 Installation

### Using npm

```bash
npm install -g @unified-scanner/cli
```

### Using pnpm (recommended)

```bash
pnpm add -g @unified-scanner/cli
```

### From source

```bash
git clone https://github.com/yourusername/unified-security-scanner.git
cd unified-security-scanner
pnpm install
pnpm build
```

## 🎯 Quick Start

### Basic Scan

```bash
# Scan current directory
unified-scanner scan

# Scan specific directory
unified-scanner scan ./my-project

# Scan with custom config
unified-scanner scan --config .security/config.json
```

### Example Output

```
┌─────────────────────────────────────────────────────────────┐
│  Unified Security Scanner v1.0                              │
│  Scanned: 1,247 files (10,432 LOC) in 42.3s               │
└─────────────────────────────────────────────────────────────┘
  🔴 CRITICAL: 2  │  🟠 HIGH: 5  │  🟡 MEDIUM: 12  │  ⚪ LOW: 8

╔═══════════╦═══════════════╦══════════════════════╦══════╦═══════════════════════════╗
║ Severity  ║ Type          ║ File                 ║ Line ║ Description              ║
╠═══════════╬═══════════════╬══════════════════════╬══════╬═══════════════════════════╣
║ 🔴 CRITICAL║ secrets       ║ src/config/api.ts   ║ 12   ║ Hardcoded API key        ║
║ 🟠 HIGH    ║ injection     ║ src/components/...  ║ 45   ║ Unsafe dangerouslySet... ║
╚═══════════╩═══════════════╩══════════════════════╩══════╩═══════════════════════════╝

ℹ️  Suppressed 15 potential false positives

✅ Security scan passed
```

## 🔧 Configuration

Create a `.securityrc.json` file in your project root:

```json
{
  "version": "1.0",
  "tools": {
    "truffleHog": {
      "enabled": true,
      "exclude": ["**/test-fixtures/**"]
    },
    "semgrep": {
      "enabled": true,
      "rules": ["./rules/react/*.yml"]
    },
    "customScanners": {
      "enabled": true,
      "modules": []
    }
  },
  "scan": {
    "target": ".",
    "exclude": [
      "**/node_modules/**",
      "**/dist/**",
      "**/*.test.ts"
    ],
    "includeTests": false,
    "maxFileSize": 10485760
  },
  "falsePositives": {
    "excludeTestFiles": true,
    "excludeStorybook": true,
    "patterns": [
      {
        "file": "**/*.config.ts",
        "pattern": "API_KEY",
        "reason": "Config templates with placeholders"
      }
    ]
  },
  "output": {
    "formats": ["terminal", "sarif", "json"],
    "dir": "./reports",
    "verbose": false
  },
  "severity": {
    "threshold": "LOW",
    "failOn": ["CRITICAL", "HIGH"]
  },
  "performance": {
    "parallelWorkers": 4,
    "cacheEnabled": true,
    "incrementalScan": true
  }
}
```

## 🔍 Detection Capabilities

### Secrets & Credentials

- ✅ Hardcoded API keys (AWS, OpenAI, Stripe, etc.)
- ✅ OAuth tokens and credentials
- ✅ Private keys (SSH, PGP, certificates)
- ✅ Database connection strings
- ✅ JWT tokens and session secrets

### React-Specific Vulnerabilities

- ✅ `dangerouslySetInnerHTML` without sanitization
- ✅ Hardcoded secrets in hooks
- ✅ Unsafe Context API usage
- ✅ `localStorage` with sensitive data
- ✅ Missing useEffect dependencies

### npm Package Security

- ✅ Typosquatting detection (Levenshtein distance)
- ✅ Dependency confusion attacks
- ✅ Malicious install hooks
- ✅ Suspicious package names
- ✅ Known vulnerable packages

### Technical Debt

- ✅ Outdated packages (major versions behind)
- ✅ End-of-life (EOL) dependencies
- ✅ Upgrade path recommendations
- ✅ npm audit vulnerabilities with fix suggestions

## 🤖 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main, develop]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Unified Scanner
        run: npm install -g @unified-scanner/cli

      - name: Run Security Scan
        run: unified-scanner scan --format=sarif,json --fail-on=critical,high

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: node:20
  script:
    - npm install -g @unified-scanner/cli
    - unified-scanner scan --format=json --output=reports
  artifacts:
    reports:
      sast: reports/results.json
    paths:
      - reports/
  only:
    - merge_requests
```

## 📊 Output Formats

### SARIF 2.1.0 (GitHub Security)

```bash
unified-scanner scan --format=sarif --output=./reports
```

Integrates with GitHub Security tab for native vulnerability tracking.

### JSON (CI/CD Pipelines)

```bash
unified-scanner scan --format=json --output=./reports
```

Machine-readable format for custom processing and dashboards.

### HTML Dashboard

```bash
unified-scanner scan --format=html --output=./reports
```

Interactive dashboard with charts and filtering.

## 🧪 Testing

The scanner includes comprehensive test coverage:

```bash
# Run all tests
pnpm test

# Run with coverage
pnpm test:coverage

# Watch mode
pnpm test:watch
```

### Test Coverage Targets

- Core engine: 95%+
- Adapters: 90%+
- Reporters: 100%
- Overall: 90%+

## 🛠️ Development

### Project Structure

```
unified-scanner/
├── packages/
│   ├── core/              # Scanning engine
│   │   ├── src/
│   │   │   ├── orchestrator/
│   │   │   ├── adapters/
│   │   │   ├── analyzers/
│   │   │   ├── reporters/
│   │   │   └── fp-reducer/
│   │   └── tests/
│   └── cli/               # Command-line interface
│       ├── src/
│       └── tests/
├── rules/                 # Security rules
│   ├── react/
│   └── npm/
├── configs/               # Example configurations
├── docs/                  # Documentation
└── .github/workflows/     # CI/CD workflows
```

### Building from Source

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run in development mode
pnpm dev

# Run linter
pnpm lint

# Format code
pnpm format
```

## 📈 Performance

| Project Size | LOC | Files | Scan Time | Workers |
|--------------|-----|-------|-----------|---------|
| Small | <5K | <100 | <30s | 2 |
| Medium | 5K-50K | 100-1K | <2min | 4 |
| Large | 50K-200K | 1K-5K | <5min | 8 |

### Optimization Tips

1. **Enable Caching**: Reuse results for unchanged files
2. **Incremental Scans**: Only scan git diff in CI/CD
3. **Exclude Patterns**: Skip node_modules, dist, build
4. **Parallel Workers**: Adjust based on CPU cores

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding Custom Rules

1. Create a rule file in `rules/` directory
2. Follow Semgrep syntax
3. Submit a PR with tests

Example:

```yaml
rules:
  - id: my-custom-rule
    patterns:
      - pattern: dangerous_function($ARG)
    message: Dangerous function usage detected
    severity: ERROR
    languages: [typescript, javascript]
```

## 📝 License

MIT License - see [LICENSE](LICENSE) for details

## 🙏 Acknowledgments

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secrets detection
- [Semgrep](https://semgrep.dev) - Pattern-based scanning
- [SARIF](https://sarifweb.azurewebsites.net/) - Standard output format
- Inspired by [MCP Sentinel Scanner](https://github.com/yourusername/mcp-sentinel-scanner)

## 📞 Support

- 📖 [Documentation](https://docs.unified-scanner.dev)
- 💬 [Discord Community](https://discord.gg/unified-scanner)
- 🐛 [Issue Tracker](https://github.com/yourusername/unified-security-scanner/issues)
- 📧 [Email Support](mailto:support@unified-scanner.dev)

---

**Built with ❤️ by the Unified Scanner Team**

*Securing the npm ecosystem, one scan at a time.*
