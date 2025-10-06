/**
 * Rule-based false positive reduction engine
 */

import { readFile } from 'fs/promises';
import micromatch from 'micromatch';
import type { Finding, ScanConfig } from '../types.js';

const DEFAULT_EXCLUSIONS = [
  // Test files
  '**/*.test.{ts,tsx,js,jsx}',
  '**/*.spec.{ts,tsx,js,jsx}',
  '**/__tests__/**',
  '**/__mocks__/**',

  // Documentation
  '**/*.md',
  '**/*.mdx',
  '**/docs/**',
  '**/.storybook/**',

  // Dependencies
  '**/node_modules/**',
  '**/vendor/**',
  '**/dist/**',
  '**/build/**',

  // Config examples
  '**/*.example.{json,yml,yaml}',
  '**/*.sample.{json,yml,yaml}',
  '**/example.config.*',
];

const TEST_PREFIXES = ['MOCK_', 'TEST_', 'EXAMPLE_', 'SAMPLE_', 'FIXTURE_', 'DEMO_'];
const TEST_KEYWORDS = /describe|it\(|test\(|expect\(|jest\.|vitest\.|mocha\./i;

export class FalsePositiveRuleEngine {
  private exclusionPatterns: string[] = [];
  private customPatterns: ScanConfig['falsePositives']['patterns'] = [];

  constructor(config: ScanConfig) {
    this.exclusionPatterns = config.falsePositives.excludeTestFiles
      ? DEFAULT_EXCLUSIONS
      : [];

    this.customPatterns = config.falsePositives.patterns || [];
  }

  async shouldSuppress(finding: Finding, config: ScanConfig): Promise<{
    suppress: boolean;
    reason?: string;
  }> {
    // Check if file matches exclusion patterns
    if (this.matchesExclusionPattern(finding.file)) {
      return {
        suppress: true,
        reason: 'File matches exclusion pattern (test/docs/dependencies)',
      };
    }

    // Check custom patterns
    for (const pattern of this.customPatterns) {
      if (micromatch.isMatch(finding.file, pattern.file)) {
        if (new RegExp(pattern.pattern).test(finding.snippet)) {
          return {
            suppress: true,
            reason: pattern.reason,
          };
        }
      }
    }

    // Check for test variable naming
    if (this.hasTestPrefix(finding.snippet)) {
      return {
        suppress: true,
        reason: 'Variable has test/mock prefix (MOCK_, TEST_, etc.)',
      };
    }

    // Check surrounding code context
    const context = await this.getContext(finding);
    if (context && this.isTestContext(context)) {
      return {
        suppress: true,
        reason: 'Found in test context (describe/it/test/expect)',
      };
    }

    // Check for nosec comments
    if (context && this.hasNoSecComment(context, finding.line)) {
      return {
        suppress: true,
        reason: 'Suppressed by nosec comment',
      };
    }

    return { suppress: false };
  }

  private matchesExclusionPattern(file: string): boolean {
    return micromatch.isMatch(file, this.exclusionPatterns);
  }

  private hasTestPrefix(snippet: string): boolean {
    return TEST_PREFIXES.some((prefix) => snippet.includes(prefix));
  }

  private isTestContext(context: string): boolean {
    return TEST_KEYWORDS.test(context);
  }

  private hasNoSecComment(context: string, lineNumber: number): boolean {
    const lines = context.split('\n');
    const relevantLine = lines[Math.min(lineNumber - 1, lines.length - 1)];
    const prevLine = lines[Math.max(0, lineNumber - 2)];

    return (
      relevantLine?.includes('nosec') ||
      relevantLine?.includes('noqa') ||
      prevLine?.includes('nosec') ||
      prevLine?.includes('noqa')
    );
  }

  private async getContext(finding: Finding): Promise<string | null> {
    try {
      const content = await readFile(finding.file, 'utf-8');
      const lines = content.split('\n');
      const startLine = Math.max(0, finding.line - 6);
      const endLine = Math.min(lines.length, finding.line + 5);

      return lines.slice(startLine, endLine).join('\n');
    } catch {
      return null;
    }
  }

  async filterFindings(findings: Finding[], config: ScanConfig): Promise<{
    findings: Finding[];
    suppressed: Finding[];
  }> {
    const filtered: Finding[] = [];
    const suppressed: Finding[] = [];

    for (const finding of findings) {
      const result = await this.shouldSuppress(finding, config);

      if (result.suppress) {
        suppressed.push({
          ...finding,
          suppressedBy: result.reason,
        });
      } else {
        filtered.push(finding);
      }
    }

    return { findings: filtered, suppressed };
  }
}
