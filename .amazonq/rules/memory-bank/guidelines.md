# Unified Security Scanner - Development Guidelines

## Code Quality Standards

### TypeScript/JavaScript Patterns
- **Strict Type Safety**: Use TypeScript with strict mode enabled, explicit type annotations for function parameters and return values
- **ES Module Syntax**: Consistent use of `import`/`export` statements, avoid CommonJS `require()` in new code
- **Async/Await**: Prefer async/await over Promise chains for better readability and error handling
- **Error Handling**: Comprehensive error handling with descriptive error messages and proper error propagation
- **Null Safety**: Explicit null/undefined checks, use optional chaining (`?.`) and nullish coalescing (`??`)

### Testing Standards
- **Comprehensive Test Coverage**: Target 95%+ coverage for core engine, 90%+ for adapters, 100% for reporters
- **Descriptive Test Names**: Use clear, descriptive test names that explain the expected behavior
- **Test Structure**: Follow Arrange-Act-Assert pattern with clear separation of setup, execution, and verification
- **Mock Strategy**: Use Jest mocks for external dependencies, avoid testing implementation details
- **Snapshot Testing**: Use inline snapshots for expected output validation (e.g., `toMatchInlineSnapshot()`)

### Documentation Patterns
- **JSDoc Comments**: Comprehensive function and class documentation with parameter types and return values
- **Inline Comments**: Explain complex logic, business rules, and non-obvious implementation decisions
- **README Structure**: Consistent README format with installation, usage, configuration, and examples
- **Code Examples**: Include working code examples in documentation and comments

## Structural Conventions

### File Organization
- **Monorepo Structure**: Separate packages for core engine and CLI with independent versioning
- **Directory Naming**: Use kebab-case for directories, PascalCase for component directories
- **File Naming**: Use camelCase for TypeScript files, kebab-case for configuration files
- **Index Files**: Use index.ts files for clean package exports and module organization

### Import/Export Patterns
- **Barrel Exports**: Use index.ts files to create clean public APIs for packages
- **Named Exports**: Prefer named exports over default exports for better tree-shaking
- **Import Organization**: Group imports by type (external libraries, internal modules, types)
- **Relative Imports**: Use relative imports for local modules, absolute imports for external packages

### Configuration Management
- **JSON Configuration**: Use JSON for configuration files with schema validation
- **Environment Variables**: Support environment variable overrides for configuration
- **Default Values**: Provide sensible defaults for all configuration options
- **Validation**: Validate configuration at startup with clear error messages

## Semantic Patterns

### Error Handling Architecture
- **Custom Error Classes**: Create specific error types for different failure scenarios
- **Error Context**: Include relevant context (file paths, line numbers, configuration) in error messages
- **Graceful Degradation**: Handle partial failures gracefully, continue processing when possible
- **Error Aggregation**: Collect multiple errors and report them together rather than failing fast

### Async Processing Patterns
- **Concurrency Control**: Use `p-limit` for controlling parallel processing and resource usage
- **Promise Handling**: Proper Promise.all() usage for parallel operations, sequential for dependent operations
- **Timeout Management**: Implement timeouts for external tool execution and network requests
- **Resource Cleanup**: Ensure proper cleanup of resources (file handles, child processes) in finally blocks

### Data Transformation Patterns
- **Immutable Operations**: Prefer immutable data transformations, avoid mutating input parameters
- **Pipeline Architecture**: Chain data transformations through clear pipeline stages
- **Type Guards**: Use TypeScript type guards for runtime type checking and validation
- **Serialization**: Consistent JSON serialization for data persistence and API responses

## Internal API Usage Patterns

### Scanner Integration
```typescript
// Adapter pattern for tool integration
interface ScannerAdapter {
  scan(config: ScanConfig): Promise<ScanResult[]>
  isAvailable(): Promise<boolean>
  getVersion(): Promise<string>
}

// Consistent result format across all scanners
interface ScanResult {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  type: string
  file: string
  line: number
  description: string
  rule?: string
}
```

### Configuration Handling
```typescript
// Hierarchical configuration merging
const config = mergeConfigs(
  defaultConfig,
  projectConfig,
  environmentConfig,
  cliOptions
)

// Validation with clear error messages
validateConfig(config, {
  onError: (field, message) => {
    throw new ConfigurationError(`Invalid ${field}: ${message}`)
  }
})
```

### File Processing
```typescript
// Consistent file discovery pattern
const files = await glob(patterns, {
  ignore: config.exclude,
  absolute: true,
  followSymbolicLinks: false
})

// Parallel processing with concurrency control
const limit = pLimit(config.parallelWorkers)
const results = await Promise.all(
  files.map(file => limit(() => processFile(file)))
)
```

## Frequently Used Code Idioms

### Result Aggregation
```typescript
// Flatten and filter results from multiple scanners
const allResults = scannerResults
  .flat()
  .filter(result => result.severity !== 'INFO')
  .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
```

### Path Handling
```typescript
// Consistent path normalization
import { resolve, relative } from 'path'
const normalizedPath = resolve(process.cwd(), inputPath)
const relativePath = relative(process.cwd(), normalizedPath)
```

### External Tool Execution
```typescript
// Safe external tool execution with timeout
const { stdout, stderr } = await execFile(toolPath, args, {
  timeout: config.toolTimeout,
  maxBuffer: config.maxOutputBuffer,
  cwd: workingDirectory
})
```

### Progress Reporting
```typescript
// Consistent progress reporting pattern
const spinner = ora('Scanning files...').start()
try {
  const results = await performScan()
  spinner.succeed(`Scanned ${fileCount} files`)
  return results
} catch (error) {
  spinner.fail(`Scan failed: ${error.message}`)
  throw error
}
```

## Popular Annotations & Patterns

### JSDoc Annotations
```typescript
/**
 * Scans files for security vulnerabilities using multiple tools
 * @param config - Scanner configuration options
 * @param files - Array of file paths to scan
 * @returns Promise resolving to scan results
 * @throws {ScannerError} When scanner execution fails
 * @example
 * ```typescript
 * const results = await scanFiles(config, ['src/**/*.ts'])
 * ```
 */
```

### Type Definitions
```typescript
// Utility types for configuration
type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P]
}

// Union types for enums
type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
type OutputFormat = 'sarif' | 'json' | 'html' | 'terminal'
```

### Validation Patterns
```typescript
// Runtime type validation
function isScanResult(obj: unknown): obj is ScanResult {
  return typeof obj === 'object' && 
         obj !== null &&
         'severity' in obj &&
         'file' in obj &&
         'line' in obj
}
```

### Performance Patterns
```typescript
// Memoization for expensive operations
const memoizedParser = new Map<string, ParseResult>()
function parseFile(filePath: string): ParseResult {
  if (memoizedParser.has(filePath)) {
    return memoizedParser.get(filePath)!
  }
  const result = expensiveParseOperation(filePath)
  memoizedParser.set(filePath, result)
  return result
}
```