/**
 * Tests for malicious package and technical debt analyzers
 */

import { MaliciousPackageScanner } from '../src/analyzers/malicious-packages';
import type { ScanConfig } from '../src/types';

const createMockConfig = (): ScanConfig => ({
  version: '1.0',
  tools: {
    truffleHog: { enabled: true },
    semgrep: { enabled: true, rules: [] },
    customScanners: { enabled: true, modules: [] },
  },
  scan: {
    target: '/tmp/test',
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
});

describe('MaliciousPackageScanner', () => {
  let scanner: MaliciousPackageScanner;

  beforeEach(() => {
    scanner = new MaliciousPackageScanner();
  });

  it('should be available', async () => {
    const available = await scanner.isAvailable();
    expect(available).toBe(true);
  });

  it('should have correct name', () => {
    expect(scanner.name).toBe('malicious-package-scanner');
  });

  it('should return empty array when package.json not found', async () => {
    const config = createMockConfig();
    config.scan.target = '/nonexistent/path';

    const findings = await scanner.scan(config);
    expect(findings).toEqual([]);
  });

  it('should detect typosquatting with Levenshtein distance', () => {
    // @ts-ignore - accessing private method for testing
    const distance = scanner['levenshteinDistance']('react', 'reactt');
    expect(distance).toBe(1);
  });

  it('should calculate Levenshtein distance correctly', () => {
    // @ts-ignore
    expect(scanner['levenshteinDistance']('kitten', 'sitting')).toBe(3);
    // @ts-ignore
    expect(scanner['levenshteinDistance']('saturday', 'sunday')).toBe(3);
    // @ts-ignore
    expect(scanner['levenshteinDistance']('', '')).toBe(0);
    // @ts-ignore
    expect(scanner['levenshteinDistance']('abc', 'abc')).toBe(0);
  });
});

describe('Levenshtein Distance Algorithm', () => {
  const scanner = new MaliciousPackageScanner();

  it('should handle identical strings', () => {
    // @ts-ignore
    expect(scanner['levenshteinDistance']('test', 'test')).toBe(0);
  });

  it('should handle empty strings', () => {
    // @ts-ignore
    expect(scanner['levenshteinDistance']('', 'test')).toBe(4);
    // @ts-ignore
    expect(scanner['levenshteinDistance']('test', '')).toBe(4);
  });

  it('should handle single character difference', () => {
    // @ts-ignore
    expect(scanner['levenshteinDistance']('cat', 'bat')).toBe(1);
  });

  it('should handle insertion', () => {
    // @ts-ignore
    expect(scanner['levenshteinDistance']('cat', 'cats')).toBe(1);
  });

  it('should handle deletion', () => {
    // @ts-ignore
    expect(scanner['levenshteinDistance']('cats', 'cat')).toBe(1);
  });

  it('should detect common typosquatting patterns', () => {
    const popularPackages = [
      { real: 'react', typo: 'reactt', distance: 1 },
      { real: 'lodash', typo: 'lodahs', distance: 2 },
      { real: 'express', typo: 'expres', distance: 1 },
      { real: 'webpack', typo: 'webpak', distance: 2 },
    ];

    popularPackages.forEach(({ real, typo, distance }) => {
      // @ts-ignore
      const calculated = scanner['levenshteinDistance'](real, typo);
      expect(calculated).toBeLessThanOrEqual(distance + 1);
    });
  });
});
