# Unified Security Scanner - Technology Stack

## Programming Languages & Versions

### Primary Languages
- **TypeScript 5.3.0**: Main development language for type safety and modern JavaScript features
- **JavaScript (ES Modules)**: Runtime execution with native ES module support
- **YAML**: Security rules and configuration files (Semgrep rules)
- **JSON**: Configuration files and output formats

### Language Requirements
- **Node.js**: >=18.0.0 (specified in package.json engines)
- **pnpm**: >=8.0.0 (package manager requirement)
- **Package Manager**: pnpm@8.12.0 (locked version)

## Build System & Dependencies

### Monorepo Management
- **pnpm Workspaces**: Multi-package repository management
- **Turbo**: Build system orchestration and caching
- **Workspace Protocol**: Internal package dependencies using `workspace:*`

### Build Tools
- **tsup**: TypeScript bundling and compilation
- **TypeScript Compiler**: Type checking and declaration generation
- **ES Modules**: Native module system (type: "module" in package.json)

### Core Dependencies

#### @unified-scanner/core
- **@babel/parser**: JavaScript/TypeScript AST parsing
- **@babel/traverse**: AST traversal for code analysis
- **@babel/types**: AST node type definitions
- **glob**: File pattern matching and discovery
- **micromatch**: Advanced glob pattern matching
- **p-limit**: Concurrency control for parallel processing
- **picomatch**: Fast glob matching

#### @unified-scanner/cli
- **commander**: Command-line argument parsing and CLI framework
- **chalk**: Terminal color and styling
- **ora**: Terminal spinners and progress indicators
- **cli-table3**: Formatted table output for terminal

### Development Dependencies
- **@types/jest**: TypeScript definitions for Jest
- **@types/node**: Node.js TypeScript definitions
- **@typescript-eslint/eslint-plugin**: TypeScript-specific ESLint rules
- **@typescript-eslint/parser**: TypeScript parser for ESLint
- **eslint**: Code linting and quality enforcement
- **jest**: Testing framework
- **prettier**: Code formatting
- **ts-jest**: Jest TypeScript integration

## Development Commands

### Build Commands
```bash
pnpm build          # Build all packages using Turbo
pnpm dev            # Development mode with watch (parallel)
pnpm clean          # Clean build artifacts and node_modules
```

### Testing Commands
```bash
pnpm test           # Run all tests across packages
pnpm test:coverage  # Run tests with coverage reporting
pnpm test:watch     # Watch mode for continuous testing
```

### Code Quality Commands
```bash
pnpm lint           # ESLint across all packages
pnpm format         # Prettier code formatting
```

### Package-Specific Commands
```bash
# Core package
cd packages/core
pnpm build          # Build core engine
pnpm dev            # Watch mode development
pnpm test           # Run core tests

# CLI package
cd packages/cli
pnpm build          # Build CLI
pnpm dev            # Watch mode development
pnpm test           # Run CLI tests
```

## Configuration Files

### TypeScript Configuration
- **Root tsconfig.json**: Base TypeScript configuration
- **Package-specific tsconfig.json**: Extends root config with package-specific settings
- **ES Module Target**: Modern JavaScript output with ES2022 target

### Build Configuration
- **tsup.config.ts**: TypeScript bundling configuration per package
- **turbo.json**: Build pipeline and caching configuration
- **pnpm-workspace.yaml**: Workspace package definitions

### Code Quality Configuration
- **.eslintrc.json**: ESLint rules and TypeScript integration
- **.prettierrc.json**: Code formatting rules
- **jest.config.js**: Testing framework configuration

### Security Configuration
- **.securityrc.json**: Scanner configuration and rules
- **rules/**: Security detection patterns in YAML format

## Runtime Environment

### Module System
- **ES Modules**: Native module system (type: "module")
- **Dynamic Imports**: Runtime module loading for extensibility
- **Top-level Await**: Modern async/await support

### Performance Optimizations
- **Parallel Processing**: Multi-worker scanning with p-limit
- **Caching**: Turbo build caching and incremental builds
- **Tree Shaking**: Dead code elimination in bundled output

### External Tool Integration
- **TruffleHog**: External binary execution for secrets detection
- **Semgrep**: External tool integration for pattern matching
- **Child Process**: Secure external tool execution

## Development Workflow

### Package Development
1. **Monorepo Setup**: Single repository with multiple packages
2. **Shared Tooling**: Common ESLint, Prettier, TypeScript configuration
3. **Independent Building**: Each package builds independently
4. **Cross-package Dependencies**: Core package consumed by CLI

### Testing Strategy
- **Unit Tests**: Jest with TypeScript support
- **Integration Tests**: Real repository scanning validation
- **Coverage Targets**: 95%+ for core, 90%+ for adapters, 100% for reporters
- **Test Repositories**: Real-world projects for accuracy validation

### CI/CD Integration
- **GitHub Actions**: Automated testing and building
- **Turbo Caching**: Build artifact caching for faster CI
- **Multi-platform**: Support for Linux, macOS, Windows environments