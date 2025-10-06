/**
 * Test suite for ScanOrchestrator
 */

import { ScanOrchestrator } from '../src/orchestrator/scanner';
import type { ScannerAdapter, ScanConfig, Finding } from '../src/types';

class MockAdapter implements ScannerAdapter {
  name = 'mock-adapter';
  private mockFindings: Finding[];

  constructor(findings: Finding[] = []) {
    this.mockFindings = findings;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async scan(_config: ScanConfig): Promise<Finding[]> {
    return this.mockFindings;
  }
}

describe('ScanOrchestrator', () => {
  const mockConfig: ScanConfig = {
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
  };

  it('should initialize with adapters', () => {
    const adapter = new MockAdapter();
    const orchestrator = new ScanOrchestrator([adapter]);
    expect(orchestrator).toBeDefined();
  });

  it('should run scan and return results', async () => {
    const mockFinding: Finding = {
      id: 'test-1',
      ruleId: 'test-rule',
      source: 'custom-npm',
      severity: 'HIGH',
      category: 'secrets',
      title: 'Test finding',
      description: 'Test description',
      snippet: 'const API_KEY = "test"',
      file: 'test.ts',
      line: 1,
      confidence: 0.9,
      detectedAt: new Date().toISOString(),
      remediation: {
        summary: 'Fix it',
        references: [],
        effort: 'low',
      },
    };

    const adapter = new MockAdapter([mockFinding]);
    const orchestrator = new ScanOrchestrator([adapter]);

    const result = await orchestrator.scan(mockConfig);

    expect(result).toBeDefined();
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe('test-1');
    expect(result.stats.total).toBe(1);
    expect(result.stats.bySeverity.HIGH).toBe(1);
  });

  it('should deduplicate findings with same file, line, and rule', async () => {
    const finding1: Finding = {
      id: 'test-1',
      ruleId: 'duplicate-rule',
      source: 'truffleHog',
      severity: 'HIGH',
      category: 'secrets',
      title: 'Duplicate finding',
      description: 'First',
      snippet: 'test',
      file: 'test.ts',
      line: 10,
      confidence: 0.8,
      detectedAt: new Date().toISOString(),
      remediation: {
        summary: 'Fix',
        references: [],
        effort: 'low',
      },
    };

    const finding2: Finding = {
      ...finding1,
      id: 'test-2',
      confidence: 0.95, // Higher confidence
    };

    const adapter1 = new MockAdapter([finding1]);
    const adapter2 = new MockAdapter([finding2]);
    const orchestrator = new ScanOrchestrator([adapter1, adapter2]);

    const result = await orchestrator.scan(mockConfig);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].confidence).toBe(0.95); // Should keep higher confidence
  });

  it('should handle adapter errors gracefully', async () => {
    class ErrorAdapter implements ScannerAdapter {
      name = 'error-adapter';

      async isAvailable(): Promise<boolean> {
        return true;
      }

      async scan(): Promise<Finding[]> {
        throw new Error('Scan failed');
      }
    }

    const errorAdapter = new ErrorAdapter();
    const orchestrator = new ScanOrchestrator([errorAdapter]);

    const result = await orchestrator.scan(mockConfig);

    expect(result).toBeDefined();
    expect(result.toolsRun).toHaveLength(1);
    expect(result.toolsRun[0].exitCode).toBe(1);
    expect(result.toolsRun[0].error).toBe('Scan failed');
  });

  it('should calculate statistics correctly', async () => {
    const findings: Finding[] = [
      {
        id: '1',
        ruleId: 'r1',
        source: 'truffleHog',
        severity: 'CRITICAL',
        category: 'secrets',
        title: 'Critical',
        description: 'desc',
        snippet: 'snip',
        file: 'f1.ts',
        line: 1,
        confidence: 0.9,
        detectedAt: new Date().toISOString(),
        remediation: { summary: 's', references: [], effort: 'low' },
      },
      {
        id: '2',
        ruleId: 'r2',
        source: 'semgrep',
        severity: 'HIGH',
        category: 'injection',
        title: 'High',
        description: 'desc',
        snippet: 'snip',
        file: 'f2.ts',
        line: 2,
        confidence: 0.8,
        detectedAt: new Date().toISOString(),
        remediation: { summary: 's', references: [], effort: 'medium' },
      },
      {
        id: '3',
        ruleId: 'r3',
        source: 'custom-npm',
        severity: 'MEDIUM',
        category: 'dependency',
        title: 'Medium',
        description: 'desc',
        snippet: 'snip',
        file: 'f3.ts',
        line: 3,
        confidence: 0.7,
        detectedAt: new Date().toISOString(),
        remediation: { summary: 's', references: [], effort: 'high' },
      },
    ];

    const adapter = new MockAdapter(findings);
    const orchestrator = new ScanOrchestrator([adapter]);

    const result = await orchestrator.scan(mockConfig);

    expect(result.stats.total).toBe(3);
    expect(result.stats.bySeverity.CRITICAL).toBe(1);
    expect(result.stats.bySeverity.HIGH).toBe(1);
    expect(result.stats.bySeverity.MEDIUM).toBe(1);
    expect(result.stats.byCategory.secrets).toBe(1);
    expect(result.stats.byCategory.injection).toBe(1);
    expect(result.stats.byCategory.dependency).toBe(1);
    expect(result.stats.bySource.truffleHog).toBe(1);
    expect(result.stats.bySource.semgrep).toBe(1);
    expect(result.stats.bySource['custom-npm']).toBe(1);
  });
});
