/**
 * Simple tests for scanner components without ESM dependencies
 */

import { FalsePositiveRuleEngine } from '../src/fp-reducer/rule-engine';
import { SarifReporter } from '../src/reporters/sarif';
import { JsonReporter } from '../src/reporters/json';
import type { ScanConfig, ScanResult, Finding } from '../src/types';

// Mock finding helper
const createMockFinding = (overrides: Partial<Finding> = {}): Finding => ({
  id: 'test-1',
  ruleId: 'test-rule',
  source: 'custom-npm',
  severity: 'HIGH',
  category: 'secrets',
  title: 'Test finding',
  description: 'Test description',
  snippet: 'const API_KEY = "test"',
  file: '/test/file.ts',
  line: 10,
  confidence: 0.9,
  detectedAt: new Date().toISOString(),
  remediation: {
    summary: 'Fix the issue',
    references: ['https://example.com'],
    effort: 'low',
  },
  ...overrides,
});

// Mock scan config
const createMockConfig = (overrides: Partial<ScanConfig> = {}): ScanConfig => ({
  version: '1.0',
  tools: {
    truffleHog: { enabled: true },
    semgrep: { enabled: true, rules: [] },
    customScanners: { enabled: true, modules: [] },
  },
  scan: {
    target: '.',
    exclude: [],
    includeTests: false,
    maxFileSize: 10485760,
    maxDepth: 50,
    followSymlinks: false,
  },
  falsePositives: {
    patterns: [],
    excludeTestFiles: true,
    excludeStorybook: true,
  },
  output: {
    formats: ['terminal'],
    dir: './reports',
    verbose: false,
    quiet: false,
  },
  severity: {
    threshold: 'LOW',
    failOn: ['CRITICAL', 'HIGH'],
  },
  performance: {
    parallelWorkers: 4,
    cacheEnabled: true,
    incrementalScan: false,
  },
  ...overrides,
});

describe('FalsePositiveRuleEngine', () => {
  it('should create instance with config', () => {
    const config = createMockConfig();
    const engine = new FalsePositiveRuleEngine(config);
    expect(engine).toBeDefined();
  });

  it('should detect test file patterns', async () => {
    const config = createMockConfig({
      falsePositives: {
        patterns: [],
        excludeTestFiles: true,
        excludeStorybook: true,
      },
    });
    const engine = new FalsePositiveRuleEngine(config);

    const finding = createMockFinding({
      file: '/test/component.test.ts',
      snippet: 'const MOCK_API_KEY = "test-key"',
    });

    const result = await engine.shouldSuppress(finding, config);
    expect(result.suppress).toBe(true);
    expect(result.reason).toContain('test');
  });

  it('should detect mock variable prefixes', async () => {
    const config = createMockConfig();
    const engine = new FalsePositiveRuleEngine(config);

    const finding = createMockFinding({
      snippet: 'const MOCK_SECRET = "test"',
    });

    const result = await engine.shouldSuppress(finding, config);
    expect(result.suppress).toBe(true);
    expect(result.reason).toContain('MOCK_');
  });

  it('should not suppress real findings', async () => {
    const config = createMockConfig();
    const engine = new FalsePositiveRuleEngine(config);

    const finding = createMockFinding({
      file: '/src/config.ts',
      snippet: 'const API_KEY = "sk-real-key-12345"',
    });

    const result = await engine.shouldSuppress(finding, config);
    expect(result.suppress).toBe(false);
  });

  it('should apply custom patterns', async () => {
    const config = createMockConfig({
      falsePositives: {
        patterns: [
          {
            file: '**/*.example.ts',
            pattern: 'API_KEY',
            reason: 'Example files',
          },
        ],
        excludeTestFiles: true,
        excludeStorybook: true,
      },
    });
    const engine = new FalsePositiveRuleEngine(config);

    const finding = createMockFinding({
      file: '/src/config.example.ts',
      snippet: 'const API_KEY = "placeholder"',
    });

    const result = await engine.shouldSuppress(finding, config);
    expect(result.suppress).toBe(true);
    expect(result.reason).toBe('Example files');
  });
});

describe('SarifReporter', () => {
  const mockScanResult: ScanResult = {
    scanId: 'test-scan-1',
    version: '1.0.0',
    startedAt: '2025-01-01T00:00:00Z',
    completedAt: '2025-01-01T00:01:00Z',
    duration: 60,
    target: '/test',
    filesScanned: 10,
    linesOfCode: 1000,
    toolsRun: [],
    findings: [createMockFinding()],
    suppressed: [],
    stats: {
      total: 1,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { secrets: 1, injection: 0, auth: 0, crypto: 0, dependency: 0, other: 0 },
      bySource: { truffleHog: 0, semgrep: 0, 'custom-npm': 1, 'custom-react': 0 },
      suppressedCount: 0,
    },
    performance: {
      parallelWorkers: 4,
      cacheHitRate: 0,
      incrementalScan: false,
    },
  };

  it('should create instance', () => {
    const reporter = new SarifReporter();
    expect(reporter).toBeDefined();
    expect(reporter.name).toBe('sarif');
  });

  it('should generate valid SARIF output', async () => {
    const reporter = new SarifReporter();
    const output = await reporter.generate(mockScanResult);

    expect(output).toBeDefined();
    const sarif = JSON.parse(output);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-2.1.0.json');
    expect(sarif.runs).toHaveLength(1);
  });

  it('should include tool driver information', async () => {
    const reporter = new SarifReporter();
    const output = await reporter.generate(mockScanResult);
    const sarif = JSON.parse(output);

    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe('Unified Security Scanner');
    expect(driver.version).toBe('1.0.0');
    expect(driver.rules).toHaveLength(1);
  });

  it('should include results with correct structure', async () => {
    const reporter = new SarifReporter();
    const output = await reporter.generate(mockScanResult);
    const sarif = JSON.parse(output);

    const results = sarif.runs[0].results;
    expect(results).toHaveLength(1);
    expect(results[0].ruleId).toBe('test-rule');
    expect(results[0].level).toBe('error');
    expect(results[0].message.text).toBe('Test finding');
  });

  it('should map severity correctly', async () => {
    const criticalResult: ScanResult = {
      ...mockScanResult,
      findings: [createMockFinding({ severity: 'CRITICAL' })],
    };

    const reporter = new SarifReporter();
    const output = await reporter.generate(criticalResult);
    const sarif = JSON.parse(output);

    expect(sarif.runs[0].results[0].level).toBe('error');
  });
});

describe('JsonReporter', () => {
  const mockScanResult: ScanResult = {
    scanId: 'test-scan-1',
    version: '1.0.0',
    startedAt: '2025-01-01T00:00:00Z',
    completedAt: '2025-01-01T00:01:00Z',
    duration: 60,
    target: '/test',
    filesScanned: 10,
    linesOfCode: 1000,
    toolsRun: [],
    findings: [createMockFinding()],
    suppressed: [],
    stats: {
      total: 1,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { secrets: 1, injection: 0, auth: 0, crypto: 0, dependency: 0, other: 0 },
      bySource: { truffleHog: 0, semgrep: 0, 'custom-npm': 1, 'custom-react': 0 },
      suppressedCount: 0,
    },
    performance: {
      parallelWorkers: 4,
      cacheHitRate: 0,
      incrementalScan: false,
    },
  };

  it('should create instance', () => {
    const reporter = new JsonReporter();
    expect(reporter).toBeDefined();
    expect(reporter.name).toBe('json');
  });

  it('should generate valid JSON output', async () => {
    const reporter = new JsonReporter();
    const output = await reporter.generate(mockScanResult);

    expect(output).toBeDefined();
    const json = JSON.parse(output);

    expect(json.scanId).toBe('test-scan-1');
    expect(json.version).toBe('1.0.0');
    expect(json.findings).toHaveLength(1);
  });

  it('should preserve all scan result fields', async () => {
    const reporter = new JsonReporter();
    const output = await reporter.generate(mockScanResult);
    const json = JSON.parse(output);

    expect(json.target).toBe('/test');
    expect(json.filesScanned).toBe(10);
    expect(json.linesOfCode).toBe(1000);
    expect(json.duration).toBe(60);
    expect(json.stats.total).toBe(1);
  });
});
