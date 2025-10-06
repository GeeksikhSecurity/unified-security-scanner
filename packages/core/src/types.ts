/**
 * Core type definitions for the Unified Security Scanner
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Category = 'secrets' | 'injection' | 'auth' | 'crypto' | 'dependency' | 'other';
export type ScanSource = 'truffleHog' | 'semgrep' | 'custom-npm' | 'custom-react';

export interface Finding {
  // Identification
  id: string;
  ruleId: string;
  source: ScanSource;

  // Classification
  severity: Severity;
  category: Category;
  cwe?: string;
  owasp?: string;

  // Location
  file: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;

  // Content
  title: string;
  description: string;
  snippet: string;

  // Remediation
  remediation: {
    summary: string;
    code?: string;
    references: string[];
    effort: 'low' | 'medium' | 'high';
  };

  // Metadata
  confidence: number;
  falsePositiveProbability?: number;
  suppressedBy?: string;

  // Timestamps
  detectedAt: string;
  firstSeenAt?: string;
}

export interface ScanResult {
  // Metadata
  scanId: string;
  version: string;
  startedAt: string;
  completedAt: string;
  duration: number;

  // Scan info
  target: string;
  filesScanned: number;
  linesOfCode: number;

  // Tool execution
  toolsRun: Array<{
    name: string;
    version: string;
    duration: number;
    exitCode: number;
    error?: string;
  }>;

  // Findings
  findings: Finding[];
  suppressed: Finding[];

  // Statistics
  stats: {
    total: number;
    bySeverity: Record<Severity, number>;
    byCategory: Record<Category, number>;
    bySource: Record<ScanSource, number>;
    suppressedCount: number;
  };

  // Performance
  performance: {
    parallelWorkers: number;
    cacheHitRate: number;
    incrementalScan: boolean;
  };

  // Policy compliance
  policy?: {
    passed: boolean;
    violations: string[];
    recommendations: string[];
  };
}

export interface ScanConfig {
  version: string;

  // Tool orchestration
  tools: {
    truffleHog?: {
      enabled: boolean;
      version?: string;
      args?: string[];
      exclude?: string[];
    };
    semgrep?: {
      enabled: boolean;
      rules: string[];
      config?: string;
    };
    customScanners?: {
      enabled: boolean;
      modules: string[];
    };
  };

  // Scan configuration
  scan: {
    target: string;
    exclude: string[];
    includeTests: boolean;
    maxFileSize: number;
    maxDepth: number;
    followSymlinks: boolean;
  };

  // False positive reduction
  falsePositives: {
    mlModel?: {
      enabled: boolean;
      modelPath?: string;
      confidenceThreshold: number;
    };
    patterns: Array<{
      file: string;
      pattern: string;
      reason: string;
    }>;
    excludeTestFiles: boolean;
    excludeStorybook: boolean;
    excludeDocumentation: boolean;
    excludeScannerRules: boolean;
  };

  // Output configuration
  output: {
    formats: Array<'terminal' | 'json' | 'sarif' | 'html' | 'markdown'>;
    dir: string;
    verbose: boolean;
    quiet: boolean;
  };

  // Severity configuration
  severity: {
    threshold: Severity;
    failOn: Severity[];
  };

  // Security policy
  policy?: {
    enforceSecurityBaseline: boolean;
    allowedLicenses: string[];
    blockedPackages: string[];
    maxCriticalFindings: number;
    maxHighFindings: number;
    requireSecurityReview: boolean;
  };

  // Performance tuning
  performance: {
    parallelWorkers: number;
    cacheEnabled: boolean;
    cacheDir?: string;
    incrementalScan: boolean;
  };
}

export interface ScannerAdapter {
  name: string;
  scan(config: ScanConfig): Promise<Finding[]>;
  isAvailable(): Promise<boolean>;
}

export interface Reporter {
  name: string;
  generate(result: ScanResult): Promise<string>;
  write(content: string, outputPath: string): Promise<void>;
}
