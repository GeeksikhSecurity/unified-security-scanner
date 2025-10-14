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
  '**/fixtures/**',
  '**/examples/**',
  '**/demo/**',
  '**/*.stories.{ts,tsx,js,jsx}',

  // Documentation
  '**/*.md',
  '**/*.mdx',
  '**/docs/**',
  '**/.storybook/**',
  '**/README*',
  '**/CHANGELOG*',
  '**/CONTRIBUTING*',
  '**/SECURITY*',
  '**/LICENSE*',

  // Dependencies
  '**/node_modules/**',
  '**/vendor/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/reports/**',

  // Package manager files (contain integrity hashes)
  '**/yarn.lock',
  '**/package-lock.json',
  '**/pnpm-lock.yaml',
  '**/composer.lock',

  // Config examples
  '**/*.example.{json,yml,yaml}',
  '**/*.sample.{json,yml,yaml}',
  '**/example.config.*',
  '**/.env.example',
  '**/.env.template',

  // Scanner rules (contain security patterns by design)
  '**/rules/**/*.{yml,yaml}',
  '**/patterns/**/*.{yml,yaml}',
];

const TEST_PREFIXES = ['MOCK_', 'TEST_', 'EXAMPLE_', 'SAMPLE_', 'FIXTURE_', 'DEMO_', 'PLACEHOLDER_', 'YOUR_', 'REPLACE_'];
const TEST_KEYWORDS = /describe|it\(|test\(|expect\(|jest\.|vitest\.|mocha\.|beforeEach|afterEach|beforeAll|afterAll/i;
const CLI_PATTERNS = /commands?|cli|bin|scan|orchestrator|adapters?|analyzers?/;
const DOC_MARKERS = /<[^>]+>|\[[^\]]+\]|\{\{[^}]+\}\}|example|sample|demo|placeholder|your_|replace_/i;

export class FalsePositiveRuleEngine {
  private exclusionPatterns: string[] = [];
  private customPatterns: ScanConfig['falsePositives']['patterns'] = [];

  constructor(config: ScanConfig) {
    this.exclusionPatterns = config.falsePositives.excludeTestFiles
      ? DEFAULT_EXCLUSIONS
      : [];

    this.customPatterns = config.falsePositives.patterns || [];
  }

  async shouldSuppress(finding: Finding, _config: ScanConfig): Promise<{
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

    // CLI tool path traversal false positives
    if (this.isCliPathTraversal(finding)) {
      return {
        suppress: true,
        reason: 'CLI tool legitimate path operations',
      };
    }

    // Documentation false positives
    if (this.isDocumentationFalsePositive(finding)) {
      return {
        suppress: true,
        reason: 'Documentation with example credentials',
      };
    }

    // Scanner rule false positives
    if (this.isScannerRuleFalsePositive(finding)) {
      return {
        suppress: true,
        reason: 'Security scanner rule definitions',
      };
    }

    // Package manager integrity hashes
    if (this.isPackageManagerHash(finding)) {
      return {
        suppress: true,
        reason: 'Package manager integrity hash',
      };
    }

    // Legitimate public API keys (read-only)
    if (await this.isLegitimatePublicApiKey(finding, context)) {
      return {
        suppress: true,
        reason: 'Legitimate public/read-only API key',
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

  private isCliPathTraversal(finding: Finding): boolean {
    const isCliFile = CLI_PATTERNS.test(finding.file);
    const isPathOp = /path\.(join|resolve|normalize)/.test(finding.snippet || '');
    const hasValidation = /validate|sanitize|normalize|resolve/.test(finding.snippet || '');
    
    return isCliFile && isPathOp && (hasValidation || finding.ruleId?.includes('path-traversal'));
  }

  private isDocumentationFalsePositive(finding: Finding): boolean {
    const isDocFile = /\.(md|rst|txt)$|docs?\//i.test(finding.file);
    const hasDocMarkers = DOC_MARKERS.test(finding.snippet || '');
    
    return isDocFile && (hasDocMarkers || finding.category === 'secrets');
  }

  private isScannerRuleFalsePositive(finding: Finding): boolean {
    const isRuleFile = /rules?\//i.test(finding.file) && /\.(yml|yaml)$/.test(finding.file);
    const isSecretRule = finding.category === 'secrets' || finding.ruleId?.includes('hardcoded');
    
    return isRuleFile && isSecretRule;
  }

  private isPackageManagerHash(finding: Finding): boolean {
    const isLockFile = /\/(yarn\.lock|package-lock\.json|pnpm-lock\.yaml|composer\.lock)$/.test(finding.file);
    const isIntegrityHash = /resolved.*\.tgz#[a-f0-9]{40}/.test(finding.snippet || '') ||
                           /integrity.*sha[0-9]+-[A-Za-z0-9+/=]+/.test(finding.snippet || '') ||
                           /"[a-f0-9]{40,64}"/.test(finding.snippet || '');
    
    return isLockFile && isIntegrityHash && finding.category === 'secrets';
  }

  private async isLegitimatePublicApiKey(finding: Finding, context: string | null): Promise<boolean> {
    if (!context || finding.category !== 'secrets') return false;

    // Known public/read-only API key patterns
    const publicKeyPatterns = [
      // Algolia public search keys (read-only)
      { pattern: /algolia.*appId.*['"]([A-Z0-9]{10})['"].*apiKey.*['"]([a-f0-9]{32})['"]/, readOnly: true },
      { pattern: /ALGOLIA.*APP_ID.*API_KEY/, readOnly: true },
      
      // Google Maps API (if restricted properly)
      { pattern: /google.*maps.*api.*key/i, readOnly: false },
      
      // Stripe publishable keys (pk_)
      { pattern: /pk_[a-zA-Z0-9]{24,}/, readOnly: true },
      
      // Firebase config (public)
      { pattern: /firebase.*config.*apiKey/i, readOnly: true },
    ];

    // Check if this matches known public key patterns
    for (const keyPattern of publicKeyPatterns) {
      if (keyPattern.pattern.test(context) || keyPattern.pattern.test(finding.snippet)) {
        // Additional context checks for legitimacy
        const hasPublicMarkers = /public|client|frontend|browser|read.?only/i.test(context);
        const hasConfigStructure = /const.*config|export.*config|\{[^}]*appId[^}]*apiKey[^}]*\}/i.test(context);
        const isInPublicFile = /config|constants|settings/i.test(finding.file);
        
        // Algolia-specific validation
        if (keyPattern.readOnly && (
          hasPublicMarkers || 
          hasConfigStructure || 
          isInPublicFile ||
          this.isAlgoliaSearchOnlyKey(finding.snippet, context)
        )) {
          return true;
        }
      }
    }

    return false;
  }

  private isAlgoliaSearchOnlyKey(_snippet: string, context: string): boolean {
    // Algolia search-only keys are safe for client-side use
    const hasSearchOnlyUsage = /search|query|index/i.test(context) && 
                              !/admin|write|delete|update/i.test(context);
    const isClientConfig = /client|frontend|public/i.test(context);
    const hasAppIdPattern = /appId.*['"]([A-Z0-9]{10})['"]/.test(context);
    
    return hasSearchOnlyUsage && (isClientConfig || hasAppIdPattern);
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
