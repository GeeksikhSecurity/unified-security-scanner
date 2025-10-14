# Unified Security Scanner - Project Structure

## Directory Organization

### Root Structure
```
unified-scanner/
├── packages/           # Monorepo packages (core engine + CLI)
├── rules/             # Security scanning rules
├── configs/           # Example configurations
├── test-repos/        # Test repositories for validation
├── test-results/      # Scan results from test runs
├── reports/           # Generated scan reports
├── docs/              # Project documentation
├── ml-models/         # Machine learning models for FP reduction
└── .github/workflows/ # CI/CD automation
```

### Core Packages (Monorepo Architecture)

#### packages/core/
**Purpose**: Core scanning engine and orchestration logic
- `src/orchestrator/` - Multi-tool coordination and workflow management
- `src/adapters/` - Tool-specific adapters (TruffleHog, Semgrep, custom)
- `src/analyzers/` - Code analysis and pattern detection
- `src/reporters/` - Output formatting (SARIF, JSON, HTML, terminal)
- `src/fp-reducer/` - False positive reduction algorithms
- `tests/` - Comprehensive test suite with 95%+ coverage

#### packages/cli/
**Purpose**: Command-line interface and user interaction
- `src/` - CLI commands, argument parsing, user interface
- `tests/` - CLI-specific testing

### Security Rules & Configuration

#### rules/
**Purpose**: Security detection patterns and rules
- `react/` - React-specific vulnerability patterns (hooks.yml)
- `npm/` - npm package security rules (security.yml)
- Custom Semgrep rules in YAML format

#### configs/
**Purpose**: Example and default configurations
- `default.json` - Default scanner configuration
- Example configurations for different project types

### Testing & Validation

#### test-repos/
**Purpose**: Real-world repositories for testing scanner accuracy
- `axios/`, `chalk/`, `express/`, `got/`, `lodash/` - Popular npm packages
- `next.js/`, `react/`, `vscode/`, `webpack/` - Large-scale projects
- `node/` - Node.js core for comprehensive testing

#### test-results/ & test-results-v*/
**Purpose**: Historical scan results for regression testing
- Organized by repository and scanner version
- JSON format results for automated comparison

### Build & Development

#### Workspace Configuration
- **pnpm workspace**: Monorepo management with `pnpm-workspace.yaml`
- **Turbo**: Build system orchestration with `turbo.json`
- **TypeScript**: Shared configuration with project-specific overrides

#### Development Tools
- **ESLint**: Code quality and consistency
- **Prettier**: Code formatting
- **Jest**: Testing framework with coverage reporting
- **tsup**: TypeScript bundling for packages

## Architectural Patterns

### Monorepo Structure
- **Shared Dependencies**: Common tooling and configuration across packages
- **Workspace References**: Core package consumed by CLI using `workspace:*`
- **Independent Versioning**: Packages can be versioned and released independently

### Plugin Architecture
- **Adapter Pattern**: Tool-specific adapters for TruffleHog, Semgrep, custom scanners
- **Reporter Pattern**: Multiple output formats through pluggable reporters
- **Scanner Modules**: Extensible custom scanner system

### Configuration Management
- **Hierarchical Config**: Project-level `.securityrc.json` with sensible defaults
- **Rule-based Exclusions**: Pattern-based false positive filtering
- **Environment-specific**: Different configurations for CI/CD vs local development

### Data Flow Architecture
1. **Input Processing**: File discovery and filtering based on configuration
2. **Multi-tool Orchestration**: Parallel execution of security scanners
3. **Result Aggregation**: Combine and normalize findings from all tools
4. **False Positive Reduction**: ML and rule-based filtering
5. **Output Generation**: Format results for multiple output targets

## Core Components & Relationships

### Orchestrator (Central Coordinator)
- Manages scanner lifecycle and execution
- Coordinates parallel tool execution
- Handles configuration and rule loading

### Adapters (Tool Integration)
- **TruffleHogAdapter**: Secrets detection integration
- **SemgrepAdapter**: Pattern-based vulnerability scanning
- **CustomScannerAdapter**: Extensible custom scanner support

### Analyzers (Code Analysis)
- **ReactAnalyzer**: React-specific vulnerability detection
- **NpmAnalyzer**: Package security and dependency analysis
- **SecretsAnalyzer**: Credential and sensitive data detection

### Reporters (Output Generation)
- **SarifReporter**: GitHub Security integration
- **JsonReporter**: Machine-readable output for CI/CD
- **HtmlReporter**: Interactive dashboard
- **TerminalReporter**: Developer-friendly console output

### False Positive Reducer
- **RuleEngine**: Pattern-based exclusion rules
- **MLClassifier**: Machine learning-based filtering
- **ContextAnalyzer**: Code context awareness for better accuracy