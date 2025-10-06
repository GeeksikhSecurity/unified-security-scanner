# Quick Start Guide

Get up and running with Unified Security Scanner in 5 minutes!

## Prerequisites

- Node.js 18+ ([Download](https://nodejs.org))
- pnpm 8+ ([Install](https://pnpm.io/installation))
- Git

## 🚀 Installation

### Option 1: Build from Source (Recommended for now)

```bash
# Navigate to the project
cd /Volumes/2TBSSD/Development/Git/Work/securityscanner

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Verify build
ls -la packages/*/dist
```

## 🎯 First Scan

### Scan Current Directory

```bash
cd packages/cli
node dist/index.js scan ../..
```

### Expected Output

```
✔ Initializing security scan...
✔ Scanning for vulnerabilities...
✔ Filtering false positives...
✔ Scan completed in 5.23s - Found 0 issues

┌─────────────────────────────────────────────────────────────┐
│  Unified Security Scanner v1.0                              │
│  Scanned: 34 files (2,150 LOC) in 5.2s                     │
└─────────────────────────────────────────────────────────────┘
  🔴 CRITICAL: 0  │  🟠 HIGH: 0  │  🟡 MEDIUM: 0  │  ⚪ LOW: 0

✅ Security scan passed
```

## 📋 Common Commands

### Basic Scan

```bash
# Scan current directory
node dist/index.js scan .

# Scan specific directory
node dist/index.js scan /path/to/project

# Scan with verbose output
node dist/index.js scan . --verbose
```

### Output Formats

```bash
# Generate SARIF report (for GitHub Security)
node dist/index.js scan . --format=sarif --output=./reports

# Generate JSON report (for CI/CD)
node dist/index.js scan . --format=json --output=./reports

# Multiple formats
node dist/index.js scan . --format=terminal,sarif,json --output=./reports
```

### Fail Conditions

```bash
# Fail only on critical issues
node dist/index.js scan . --fail-on=critical

# Fail on critical and high
node dist/index.js scan . --fail-on=critical,high

# Fail on all issues
node dist/index.js scan . --fail-on=critical,high,medium,low
```

## 🧪 Test the Scanner

### Run Tests

```bash
# From project root
pnpm test

# With coverage
pnpm test:coverage

# Watch mode
pnpm test:watch
```

### Expected Test Output

```
 PASS  packages/core/tests/scanner.test.ts
  ScanOrchestrator
    ✓ should initialize with adapters (3 ms)
    ✓ should run scan and return results (125 ms)
    ✓ should deduplicate findings (89 ms)
    ✓ should handle adapter errors gracefully (45 ms)
    ✓ should calculate statistics correctly (67 ms)

Test Suites: 1 passed, 1 total
Tests:       5 passed, 5 total
Coverage:    85.4% statements | 80.2% branches | 90.1% functions | 87.3% lines
```

## 🎨 Scan a Sample Project

### Create a Test Project

```bash
# Create a sample project with intentional issues
mkdir -p /tmp/test-project
cd /tmp/test-project

# Create package.json with outdated packages
cat > package.json <<'EOF'
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "react": "^16.0.0",
    "lodash": "^3.0.0",
    "moment": "^2.0.0"
  }
}
EOF

# Create a file with hardcoded secret
cat > src/config.ts <<'EOF'
export const config = {
  API_KEY: "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
  DATABASE_URL: "postgres://admin:password123@localhost:5432/db"
};
EOF

# Create a React component with security issues
cat > src/App.tsx <<'EOF'
import React, { useEffect } from 'react';

export function App() {
  const API_KEY = "sk-live-supersecretkey123456789";

  useEffect(() => {
    fetch(`https://api.example.com?key=${API_KEY}`);
  }, []); // Missing API_KEY in dependency array

  const userInput = "<script>alert('xss')</script>";

  return (
    <div dangerouslySetInnerHTML={{ __html: userInput }} />
  );
}
EOF
```

### Scan the Test Project

```bash
cd /Volumes/2TBSSD/Development/Git/Work/securityscanner/packages/cli
node dist/index.js scan /tmp/test-project --format=terminal,json --output=/tmp/reports
```

### Expected Findings

1. **CRITICAL**: Hardcoded API keys in `src/config.ts` and `src/App.tsx`
2. **HIGH**: Unsafe `dangerouslySetInnerHTML` without sanitization
3. **HIGH**: EOL package (moment)
4. **MEDIUM**: Outdated packages (react 16, lodash 3)
5. **MEDIUM**: Missing useEffect dependency

## 🔧 Configuration

### Create a Config File

```bash
cat > .securityrc.json <<'EOF'
{
  "version": "1.0",
  "tools": {
    "truffleHog": {
      "enabled": true,
      "exclude": ["**/fixtures/**"]
    },
    "semgrep": {
      "enabled": true,
      "rules": ["./rules/react/*.yml"]
    }
  },
  "scan": {
    "target": ".",
    "exclude": [
      "**/node_modules/**",
      "**/dist/**"
    ],
    "includeTests": false
  },
  "falsePositives": {
    "excludeTestFiles": true,
    "patterns": [
      {
        "file": "**/*.example.ts",
        "pattern": "API_KEY",
        "reason": "Example files with placeholder values"
      }
    ]
  },
  "severity": {
    "failOn": ["CRITICAL", "HIGH"]
  }
}
EOF
```

### Use the Config

```bash
node dist/index.js scan . --config=.securityrc.json
```

## 🚨 Troubleshooting

### "Cannot find module" Error

```bash
# Rebuild the project
cd /Volumes/2TBSSD/Development/Git/Work/securityscanner
pnpm clean
pnpm install
pnpm build
```

### TruffleHog Not Found

```bash
# Install TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### Semgrep Not Found

```bash
# Install Semgrep
brew install semgrep  # macOS
# or
pip3 install semgrep  # Python
```

### Permission Denied

```bash
# Make CLI executable
chmod +x packages/cli/dist/index.js
```

## 📚 Next Steps

1. ✅ **Scan Your Projects**: Try scanning your actual projects
2. ✅ **Customize Rules**: Add custom security rules in `rules/`
3. ✅ **CI/CD Integration**: Add to your GitHub Actions workflow
4. ✅ **Review Reports**: Check generated SARIF files in GitHub Security
5. ✅ **Contribute**: Submit improvements and new rules

## 🆘 Getting Help

- 📖 Read the full [README.md](README.md)
- 📊 Check [PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md)
- 🐛 Report issues on GitHub
- 💬 Join our Discord community

## ⚡ Performance Tips

1. **Enable Caching**: Add `"cacheEnabled": true` to config
2. **Exclude Directories**: Skip node_modules, dist, build
3. **Parallel Workers**: Adjust based on CPU cores (default: 4)
4. **Incremental Scans**: Use git diff in CI/CD

---

**Happy Scanning! 🔒**
