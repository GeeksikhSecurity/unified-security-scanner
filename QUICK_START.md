# Quick Start Guide

**Time to complete:** 5-10 minutes
**Difficulty:** Beginner
**Last updated:** November 11, 2025

## What You'll Accomplish

By the end of this guide, you'll run your first security scan and understand how to detect vulnerabilities, hardcoded secrets, and code quality issues in your projects.

**You'll learn:**

- ✅ How to install and verify the scanner (Knowledge)
- ✅ How to run your first scan and interpret results (Skills)
- ✅ When to use different scan configurations for your use case (Wisdom)

---

## Prerequisites

Before starting, ensure you have:

- [ ] **Node.js 18+** ([Download](https://nodejs.org)) - Required for running the scanner
  - **Why:** The scanner is built on Node.js runtime
  - **Check:** Run `node --version` (should show v18.0.0 or higher)

- [ ] **pnpm 8+** ([Install](https://pnpm.io/installation)) - Fast, efficient package manager
  - **Why:** Manages dependencies 3x faster than npm
  - **Check:** Run `pnpm --version` (should show 8.0.0 or higher)

- [ ] **Git** - Version control system
  - **Why:** Clone the repository and track security improvements
  - **Check:** Run `git --version` (any modern version works)

**Don't have these?** Follow the installation links above, then return to this guide.

---

## 🚀 Installation

### Step 1: Build from Source

**Why this step matters:** Building from source ensures you have the latest security rules and detection capabilities.

```bash
# Navigate to the project directory
cd /Volumes/2TBSSD/Development/Git/Work/securityscanner

# Install all dependencies (takes ~30 seconds)
pnpm install

# Build all packages (takes ~45 seconds)
pnpm build

# Verify the build succeeded
ls -la packages/*/dist
```

**Expected result:** You should see `dist/` directories in:

- `packages/cli/dist/` - Command-line interface
- `packages/core/dist/` - Scanner engine
- `packages/adapters/dist/` - Tool integrations

**Common issues:**

- **"pnpm: command not found"** → Install pnpm: `npm install -g pnpm`
- **"Permission denied"** → Use sudo or fix npm permissions ([guide](https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally))
- **Build errors** → Try: `pnpm clean && pnpm install && pnpm build`

💡 **Pro tip:** Add `alias scan='node /path/to/securityscanner/packages/cli/dist/index.js'` to your shell profile for quick access.

---

## 🎯 Your First Scan (Skills Level)

### Step 2: Run a Basic Scan

**What this does:** Scans your codebase for hardcoded secrets, vulnerabilities, and security issues.

```bash
cd packages/cli
node dist/index.js scan ../..
```

**Understanding the command:**

- `node dist/index.js` - Runs the scanner CLI
- `scan` - The scan command
- `../..` - Target directory (parent of parent = project root)

**Expected output (clean scan):**

```text
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

**What each severity means:**

- 🔴 **CRITICAL** - Exposed secrets, hardcoded API keys, credentials
  - **Action:** Fix immediately before committing code
  - **Example:** `API_KEY = "sk-live-abc123"`

- 🟠 **HIGH** - SQL injection, XSS vulnerabilities, insecure dependencies
  - **Action:** Fix before merging to production
  - **Example:** `dangerouslySetInnerHTML` without sanitization

- 🟡 **MEDIUM** - Outdated packages, missing security headers, weak crypto
  - **Action:** Address in current sprint
  - **Example:** React 16.x (no longer supported)

- ⚪ **LOW** - Code quality issues, minor optimizations
  - **Action:** Fix when convenient
  - **Example:** Missing error handling

**Verify success:**

You'll know the scan worked when:

- [ ] You see the progress indicators (✔ checkmarks)
- [ ] The summary box appears with file count
- [ ] Exit code is 0 (check with `echo $?`)
- [ ] No error messages in red text

**Common issues:**

- **"Cannot find module"** → Rebuild: `pnpm build` from project root
- **Scan hangs** → Check if target directory is too large (>100k files)
- **Permission errors** → Ensure read access to target directory

---

## 📋 Common Scan Patterns (Wisdom Level)

Now that you can run scans, here's **when** and **how** to use different configurations based on your context.

### Pattern 1: Local Development Workflow

**Use case:** Quick checks before committing code

```bash
# From anywhere in your project
node dist/index.js scan .
```

**When to use:**

- ✅ Before `git commit` (catch secrets early)
- ✅ After adding new dependencies
- ✅ When working with sensitive data

**Why it works:** Fast feedback loop, catches critical issues before they enter version control.

---

### Pattern 2: CI/CD Pipeline Integration

**Use case:** Automated security gates in GitHub Actions, GitLab CI, etc.

```bash
# Generate SARIF for GitHub Security tab
node dist/index.js scan . \
  --format=sarif \
  --output=./reports \
  --fail-on=critical,high
```

**When to use:**

- ✅ Pull request validation (block merges on critical/high)
- ✅ Nightly security audits (all severities)
- ✅ Pre-deployment checks (production releases)

**Why SARIF format:**

- Integrates with GitHub Security tab
- Shows inline code annotations in PRs
- Machine-readable for automation

**Example GitHub Action:**

```yaml
- name: Security Scan
  run: |
    node packages/cli/dist/index.js scan . \
      --format=sarif,terminal \
      --output=./reports \
      --fail-on=critical,high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: reports/security-results.sarif
```

---

### Pattern 3: Compliance & Audit Reports

**Use case:** Generate reports for security reviews, compliance audits, pen test prep

```bash
# Generate comprehensive JSON report
node dist/index.js scan . \
  --format=json,sarif \
  --output=./security-reports \
  --verbose
```

**When to use:**

- ✅ SOC 2 audit preparation
- ✅ Security team reviews
- ✅ Post-incident analysis
- ✅ Quarterly security assessments

**What you get:**

- `security-results.json` - Machine-readable findings
- `security-results.sarif` - GitHub Security compatible
- Verbose logs showing scan coverage

---

### Pattern 4: Progressive Security (Recommended)

**Use case:** Gradually improve security posture without breaking builds

```bash
# Week 1: Block only critical
node dist/index.js scan . --fail-on=critical

# Week 2-4: Fix high severity issues
node dist/index.js scan . --fail-on=critical,high

# Month 2+: Address medium issues
node dist/index.js scan . --fail-on=critical,high,medium
```

**When to use:**

- ✅ Legacy codebases with many issues
- ✅ New team adopting security practices
- ✅ Large refactoring projects

**Why this works:** Prevents "security bankruptcy" where too many issues cause teams to disable scanning.

---

### Output Format Decision Matrix

| Format | Use Case | Best For |
|--------|----------|----------|
| **terminal** (default) | Local development | Human readability, quick feedback |
| **sarif** | CI/CD, GitHub | GitHub Security tab, PR annotations |
| **json** | Automation, APIs | Custom tooling, dashboards, reports |
| **Multiple** | Compliance | Audit trail + developer experience |

---

### Fail-On Strategy Guide

| Setting | Use Case | Exit Code on Issues |
|---------|----------|---------------------|
| `--fail-on=critical` | Development branches | Only critical = fail |
| `--fail-on=critical,high` | Production merges | Critical or High = fail |
| `--fail-on=critical,high,medium` | Nightly audits | Critical/High/Medium = fail |
| No `--fail-on` flag | Monitoring only | Always succeed (0) |

**Rule of thumb:**

- **Local dev:** No `--fail-on` (warnings only)
- **Feature branches:** `--fail-on=critical`
- **Main/master:** `--fail-on=critical,high`
- **Production releases:** `--fail-on=critical,high` + manual review

---

## 🧪 Verify Your Installation (Optional but Recommended)

### Why Run Tests?

Before scanning production code, verify the scanner itself works correctly. This builds confidence and helps catch environment issues.

### Step 3: Run the Test Suite

```bash
# From project root
pnpm test

# Or with coverage report
pnpm test:coverage
```

**Expected output:**

```text
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

**What success looks like:**

- [ ] All tests pass (green checkmarks)
- [ ] No "FAIL" messages in output
- [ ] Coverage above 80% (quality signal)

**If tests fail:**

- Clean build: `pnpm clean && pnpm install && pnpm build`
- Check Node version: `node --version` (must be 18+)
- Review error messages for missing dependencies

---

## 🎨 Hands-On Practice: Scan Vulnerable Code

### Step 4: Create a Test Project with Real Security Issues

**Learning goal:** Experience what the scanner detects and understand different vulnerability types.

```bash
# Create a sample project with intentional vulnerabilities
mkdir -p /tmp/test-project/src
cd /tmp/test-project

# Create package.json with outdated dependencies
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

# Create a config file with hardcoded secrets
cat > src/config.ts <<'EOF'
export const config = {
  API_KEY: "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
  DATABASE_URL: "postgres://admin:password123@localhost:5432/db"
};
EOF

# Create a React component with XSS vulnerability
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

**What we just created:**

- 🔴 **CRITICAL**: 2 hardcoded API keys (exposed secrets)
- 🟠 **HIGH**: XSS vulnerability via `dangerouslySetInnerHTML`
- 🟠 **HIGH**: End-of-life package (moment.js)
- 🟡 **MEDIUM**: Outdated packages (react 16, lodash 3)
- 🟡 **MEDIUM**: React hooks dependency issue

---

### Step 5: Scan the Vulnerable Project

```bash
cd /Volumes/2TBSSD/Development/Git/Work/securityscanner/packages/cli
node dist/index.js scan /tmp/test-project --format=terminal,json --output=/tmp/reports
```

**Expected findings:**

The scanner should detect approximately **5-8 security issues**:

| Severity | Issue Type | Location | Why It's Dangerous |
|----------|-----------|----------|-------------------|
| 🔴 CRITICAL | Hardcoded API key | `src/config.ts:2` | Exposed in version control, attackers can steal |
| 🔴 CRITICAL | Hardcoded secret | `src/App.tsx:4` | Credentials in source code |
| 🟠 HIGH | XSS vulnerability | `src/App.tsx:12` | User input rendered as HTML, allows code injection |
| 🟠 HIGH | EOL package | `package.json:6` | Moment.js unmaintained, known vulnerabilities |
| 🟡 MEDIUM | Outdated React | `package.json:5` | React 16 has security patches in v18 |
| 🟡 MEDIUM | Outdated lodash | `package.json:6` | Prototype pollution vulnerabilities |

**Understanding the output:**

```text
🔴 CRITICAL: Hardcoded API Key Detected
  File: src/config.ts:2
  Pattern: sk-proj-*
  Risk: Secret exposed in version control

  ⚠️  If committed to GitHub, this key is compromised
  ✅  Solution: Use environment variables (process.env.API_KEY)

  Learn more: https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password
```

**Check the JSON report:**

```bash
cat /tmp/reports/security-results.json | jq '.findings[] | {severity, title, file}'
```

This shows structured data for automation and tracking.

---

## 🔧 Advanced: Custom Configuration (Wisdom Level)

### When You Need Custom Configuration

**Use the default settings when:**

- ✅ First-time setup
- ✅ Standard project structure
- ✅ No special exclusions needed

**Create a config file when:**

- ✅ You have test fixtures with fake secrets
- ✅ Legacy code with known issues to suppress
- ✅ Custom rules for your tech stack
- ✅ Different fail conditions per environment

---

### Step 6: Create a Configuration File (Optional)

**What this does:** Customizes scanner behavior, excludes false positives, and sets project-specific rules.

```bash
# Create in your project root
cat > .securityrc.json <<'EOF'
{
  "version": "1.0",
  "tools": {
    "truffleHog": {
      "enabled": true,
      "exclude": ["**/fixtures/**", "**/test-data/**"]
    },
    "semgrep": {
      "enabled": true,
      "rules": ["./rules/react/*.yml", "./rules/custom/*.yml"]
    }
  },
  "scan": {
    "target": ".",
    "exclude": [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**",
      "**/.git/**"
    ],
    "includeTests": false
  },
  "falsePositives": {
    "excludeTestFiles": true,
    "patterns": [
      {
        "file": "**/*.example.ts",
        "pattern": "API_KEY",
        "reason": "Example files with placeholder API keys"
      },
      {
        "file": "**/tests/fixtures/**",
        "pattern": "password",
        "reason": "Test fixtures use fake credentials"
      }
    ]
  },
  "severity": {
    "failOn": ["CRITICAL", "HIGH"]
  }
}
EOF
```

**Configuration explained:**

| Section | Purpose | When to Configure |
|---------|---------|-------------------|
| `tools.*.exclude` | Skip specific directories per tool | Test fixtures, generated code |
| `scan.exclude` | Global exclusions | node_modules, build artifacts |
| `scan.includeTests` | Scan test files or skip them | Set `true` if tests handle real secrets |
| `falsePositives.patterns` | Suppress known safe issues | Example files, migration scripts |
| `severity.failOn` | Which severities fail the build | Stricter in prod, lenient in dev |

---

### Use Your Custom Config

```bash
# Explicitly specify config file
node dist/index.js scan . --config=.securityrc.json

# Or place it in project root as .securityrc.json (auto-detected)
node dist/index.js scan .
```

**Config file lookup order:**

1. `--config` flag path
2. `.securityrc.json` in current directory
3. `.securityrc.json` in project root
4. Default built-in configuration

---

### Real-World Configuration Examples

**Startup MVP (move fast, fix critical only):**

```json
{
  "severity": {
    "failOn": ["CRITICAL"]
  }
}
```

**Enterprise Production (strict compliance):**

```json
{
  "severity": {
    "failOn": ["CRITICAL", "HIGH", "MEDIUM"]
  },
  "scan": {
    "includeTests": true
  }
}
```

**Open Source Project (transparent, comprehensive):**

```json
{
  "tools": {
    "truffleHog": { "enabled": true },
    "semgrep": { "enabled": true }
  },
  "severity": {
    "failOn": ["CRITICAL", "HIGH"]
  },
  "falsePositives": {
    "excludeTestFiles": true
  }
}
```

---

## 🚨 Troubleshooting FAQ

Common issues and their solutions, organized by frequency.

---

### Q. "Cannot find module" error when running scan

**Category:** Installation
**Applies to:** All versions

**A. The build artifacts are missing or corrupted.**

This typically happens when:
- You cloned the repo but didn't build it
- Build failed silently
- You updated dependencies without rebuilding

**Solution:**

```bash
# Navigate to project root
cd /Volumes/2TBSSD/Development/Git/Work/securityscanner

# Clean and rebuild everything
pnpm clean
pnpm install
pnpm build

# Verify build succeeded
ls -la packages/cli/dist/index.js
# Should show a file with recent timestamp
```

**Why this works:** Rebuilds TypeScript source to JavaScript in `dist/` directories.

**Still stuck?** Check that:
- Node.js is 18+ (`node --version`)
- pnpm is installed (`pnpm --version`)
- No error messages during `pnpm build`

---

### Q. TruffleHog or Semgrep "command not found"

**Category:** Dependencies
**Applies to:** First-time setup

**A. The scanner requires external security tools to be installed on your system.**

**Why this happens:** The Unified Security Scanner orchestrates multiple tools. TruffleHog detects secrets, Semgrep finds code vulnerabilities.

**Install TruffleHog (secrets detection):**

```bash
# macOS/Linux
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
trufflehog --version
```

**Install Semgrep (code analysis):**

```bash
# macOS
brew install semgrep

# Linux/macOS (Python)
pip3 install semgrep

# Docker (any platform)
docker pull semgrep/semgrep

# Verify installation
semgrep --version
```

**Optional: Disable tools you don't have:**

```json
{
  "tools": {
    "truffleHog": { "enabled": false },
    "semgrep": { "enabled": false }
  }
}
```

**When to use this:** Evaluation/demo without installing dependencies (not recommended for production).

---

### Q. "Permission denied" when running the CLI

**Category:** File Permissions
**Applies to:** Unix-like systems (macOS, Linux)

**A. The JavaScript file needs execute permissions.**

**Solution:**

```bash
# Make CLI executable
chmod +x packages/cli/dist/index.js

# Or run with node explicitly (always works)
node packages/cli/dist/index.js scan .
```

**Why this matters:** The `#!/usr/bin/env node` shebang at the top of the file requires execute permission.

**Best practice:** Always use `node packages/cli/dist/index.js` in scripts for cross-platform compatibility.

---

### Q. Scan takes forever (>5 minutes) or hangs

**Category:** Performance
**Applies to:** Large codebases

**A. The scanner is processing too many files.**

**Why this happens:**
- Scanning `node_modules/` (hundreds of thousands of files)
- Very large files (minified JavaScript, data files)
- Binary files being analyzed

**Solution - Add exclusions:**

```bash
# Quick fix: Exclude common large directories
node dist/index.js scan . --exclude="**/node_modules/**,**/dist/**,**/.git/**"

# Better: Create .securityrc.json
{
  "scan": {
    "exclude": [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**",
      "**/.git/**",
      "**/*.min.js",
      "**/coverage/**"
    ]
  }
}
```

**Performance benchmarks:**
- Small project (< 1k files): 5-15 seconds
- Medium project (1k-10k files): 30-90 seconds
- Large monorepo (10k-50k files): 2-5 minutes

**Still slow?** Enable verbose mode to see what's being scanned: `--verbose`

---

### Q. False positives - Scanner reports issues in test files or examples

**Category:** False Positives
**Applies to:** Projects with test fixtures

**A. Test files often contain fake credentials that the scanner detects.**

**This is expected behavior.** The scanner doesn't know if "test_password_123" is real or fake.

**Solution - Suppress known safe patterns:**

```json
{
  "falsePositives": {
    "excludeTestFiles": true,
    "patterns": [
      {
        "file": "**/*.example.*",
        "pattern": "API_KEY|SECRET|PASSWORD",
        "reason": "Example files use placeholder values"
      },
      {
        "file": "**/fixtures/**",
        "pattern": ".*",
        "reason": "Test fixtures with mock data"
      },
      {
        "file": "**/docs/**",
        "pattern": "sk-.*",
        "reason": "Documentation examples"
      }
    ]
  }
}
```

**Important:** Be specific with patterns to avoid accidentally suppressing real issues.

---

### Q. Exit code is 1 even though scan shows "0 issues"

**Category:** Configuration
**Applies to:** CI/CD pipelines

**A. The `--fail-on` setting might be triggering on warnings or different severity levels.**

**Check your configuration:**

```bash
# See full output including warnings
node dist/index.js scan . --verbose

# Check actual exit code
echo $?
# 0 = success, 1 = issues found, 2 = error
```

**Common causes:**
- Config has `"failOn": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]`
- Medium/Low issues exist but aren't displayed by default
- Tool adapter failures (e.g., Semgrep crashed)

**Solution:**

```bash
# Only fail on critical issues
node dist/index.js scan . --fail-on=critical

# Or in config
{
  "severity": {
    "failOn": ["CRITICAL"]
  }
}
```

---

### Q. How do I scan only changed files (incremental scan)?

**Category:** Performance, CI/CD
**Applies to:** Git-based projects

**A. Use git diff to target only modified files.**

**For pull requests:**

```bash
# Get changed files in current branch
CHANGED_FILES=$(git diff --name-only main...HEAD)

# Scan only those files
node dist/index.js scan $CHANGED_FILES
```

**For CI/CD (GitHub Actions example):**

```yaml
- name: Get changed files
  id: changes
  run: |
    echo "files=$(git diff --name-only ${{ github.event.before }}..${{ github.sha }} | tr '\n' ',')" >> $GITHUB_OUTPUT

- name: Scan changed files
  run: |
    node packages/cli/dist/index.js scan ${{ steps.changes.outputs.files }}
```

**Trade-off:** Faster scans but might miss context-dependent issues in unchanged files.

**Recommendation:**
- PR scans: Incremental (fast feedback)
- Nightly scans: Full scan (comprehensive)
- Production: Full scan (don't skip anything)

---

### Q. Can I use this in a monorepo with multiple projects?

**Category:** Architecture
**Applies to:** Monorepos, workspaces

**A. Yes, scan each workspace separately or all at once.**

**Option 1: Scan entire monorepo**

```bash
node dist/index.js scan . --output=./reports/monorepo
```

**Option 2: Scan each project individually**

```bash
# Scan API project
node dist/index.js scan ./apps/api --output=./reports/api

# Scan Web project
node dist/index.js scan ./apps/web --output=./reports/web

# Combine in CI
for dir in apps/*; do
  node dist/index.js scan "$dir" --output="./reports/$(basename $dir)"
done
```

**Benefits of separate scans:**
- Isolated fail conditions per project
- Team-specific security policies
- Faster parallel execution
- Clearer ownership of issues

**Use case:** Different teams own different apps with different security requirements.

---

## 📚 What's Next? Your Learning Path

You've completed the Quick Start! Here's how to continue based on your goals:

### Path 1: Individual Developer (Secure Your Code)

**Immediate actions:**

1. **Scan your current project**

   ```bash
   cd /path/to/your/project
   /path/to/securityscanner/packages/cli/dist/index.js scan .
   ```

2. **Add pre-commit hook** (catch secrets before committing)

   ```bash
   # .git/hooks/pre-commit
   #!/bin/bash
   node /path/to/scanner scan . --fail-on=critical
   ```

3. **Review and fix critical issues** first, then high, then medium

**Next:** Learn about [custom security rules](docs/RULES.md) for your tech stack

---

### Path 2: Team Lead (Implement Team Standards)

**Immediate actions:**

1. **Create team configuration** (`.securityrc.json` in repo root)

   ```json
   {
     "severity": { "failOn": ["CRITICAL", "HIGH"] },
     "falsePositives": { "excludeTestFiles": true }
   }
   ```

2. **Add to CI/CD pipeline** (see Pattern 2 above for GitHub Actions example)

3. **Document security workflow** for your team

**Next:** Set up [GitHub Security integration](docs/GITHUB_INTEGRATION.md) for automated PR checks

---

### Path 3: Security Team (Enterprise Deployment)

**Immediate actions:**

1. **Audit current security posture**

   ```bash
   # Baseline scan across all repos
   for repo in ~/projects/*; do
     node dist/index.js scan "$repo" --output="./audit-$(basename $repo)"
   done
   ```

2. **Define organizational policies** (fail conditions, required tools, exemption process)

3. **Create custom rules** for company-specific patterns

**Next:** Review [Enterprise Deployment Guide](docs/ENTERPRISE.md) and [Custom Rules](docs/CUSTOM_RULES.md)

---

### Path 4: Open Source Maintainer (Protect Contributors)

**Immediate actions:**

1. **Add GitHub Action workflow** (`.github/workflows/security.yml`)

   ```yaml
   name: Security Scan
   on: [pull_request, push]
   jobs:
     security:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Security Scan
           run: |
             npm install -g pnpm
             git clone https://github.com/yourusername/securityscanner
             cd securityscanner && pnpm install && pnpm build
             node packages/cli/dist/index.js scan ../.. --format=sarif --output=../reports
         - uses: github/codeql-action/upload-sarif@v2
           with:
             sarif_file: reports/security-results.sarif
   ```

2. **Add security badge** to README

3. **Document security policy** (`SECURITY.md`)

**Next:** Set up [automated security reporting](docs/OSS_SECURITY.md)

---

## 🆘 Getting Help & Resources

### Documentation

- 📖 **[README.md](README.md)** - Complete project overview
- 📊 **[PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md)** - Architecture and design decisions
- 🔧 **[Configuration Reference](docs/CONFIGURATION.md)** - All config options explained
- 📝 **[Custom Rules Guide](docs/CUSTOM_RULES.md)** - Write your own security rules

### Common Questions

**Q: How do I scan before every commit automatically?**
A: See "Path 1: Individual Developer" above for pre-commit hook setup.

**Q: Can I integrate this with my existing security tools?**
A: Yes! The scanner outputs SARIF and JSON formats compatible with most security platforms.

**Q: How do I contribute new rules?**
A: See [CONTRIBUTING.md](CONTRIBUTING.md) for rule contribution guidelines.

**Q: Is there a hosted/SaaS version?**
A: Currently self-hosted only. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for deployment options.

### Support Channels

- 🐛 **Bug reports:** [GitHub Issues](https://github.com/yourusername/securityscanner/issues)
- 💡 **Feature requests:** [GitHub Discussions](https://github.com/yourusername/securityscanner/discussions)
- 💬 **Community chat:** [Discord](https://discord.gg/securityscanner)
- 📧 **Security issues:** security@yourproject.com (private disclosure)

### Performance Optimization Guide

If scans are slower than expected, optimize in this order:

| Optimization | Impact | Effort | When to Apply |
|--------------|--------|--------|---------------|
| Exclude node_modules | 🚀🚀🚀 High | Low | Always |
| Exclude build artifacts | 🚀🚀 Medium | Low | If >1 min scan time |
| Incremental scans (git diff) | 🚀🚀🚀 High | Medium | CI/CD only |
| Enable caching | 🚀 Low | Low | Repeated scans |
| Adjust parallel workers | 🚀 Low | Low | CPU-bound scans |

**Benchmark your setup:**

```bash
# See what's being scanned
node dist/index.js scan . --verbose | grep "Scanning"

# Time the scan
time node dist/index.js scan .
```

**Target performance:**

- Local dev: <10 seconds (for fast feedback)
- CI/CD PR: <60 seconds (acceptable wait)
- Nightly audits: <5 minutes (comprehensive)

---

## ✅ Quick Start Complete!

**You now know:**

- ✅ How to install and run the scanner (Knowledge)
- ✅ How to interpret results and configure scans (Skills)
- ✅ When to use different scan patterns for your context (Wisdom)

**Your security journey continues:**

1. Scan your real projects today
2. Fix critical and high issues this week
3. Integrate into CI/CD this month
4. Contribute rules back to the community

---

**Thank you for improving software security! 🔒**

*Questions? See the [Troubleshooting FAQ](#-troubleshooting-faq) above or [open an issue](https://github.com/yourusername/securityscanner/issues).*
