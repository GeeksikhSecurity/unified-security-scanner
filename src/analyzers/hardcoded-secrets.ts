/**
 * Enhanced hardcoded secrets analyzer with context-aware detection
 */

import { readFile } from 'fs/promises';
import { randomUUID } from 'crypto';
import type { Finding, ScanConfig, ScannerAdapter } from '../types.js';

interface ApiKeyPattern {
  name: string;
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  isPublicKey?: boolean;
  contextValidation?: (context: string, snippet: string) => boolean;
}

const API_KEY_PATTERNS: ApiKeyPattern[] = [
  {
    name: 'Algolia API Key',
    pattern: /['"]([a-f0-9]{32})['"].*algolia|algolia.*['"]([a-f0-9]{32})['"]|apiKey\s*:\s*['"]([a-f0-9]{32})['"].*algolia/i,
    severity: 'HIGH',
    isPublicKey: true,
    contextValidation: (context: string, _snippet: string) => {
      const hasSearchOnlyUsage = /search|query|client/i.test(context) && 
                                !/admin|write|delete|update|secret/i.test(context);
      const hasPublicMarkers = /public|frontend|client|browser/i.test(context);
      const isConfigObject = /const.*config|export.*config/i.test(context);
      
      return !(hasSearchOnlyUsage && (hasPublicMarkers || isConfigObject));
    }
  },
  {
    name: 'Generic API Key',
    pattern: /api[_-]?key\s*[:=]\s*['"]([A-Za-z0-9_-]{20,})['"]|['"]([A-Za-z0-9_-]{32,})['"].*api[_-]?key/i,
    severity: 'HIGH',
    contextValidation: (context: string, snippet: string) => {
      const isPlaceholder = /your|example|sample|placeholder|xxx|test|demo/i.test(snippet);
      const hasEnvReference = /process\.env|env\.|getenv/i.test(context);
      
      return !isPlaceholder && !hasEnvReference;
    }
  },
];

export class HardcodedSecretsAnalyzer implements ScannerAdapter {
  name = 'hardcoded-secrets-analyzer';

  async scan(config: ScanConfig): Promise<Finding[]> {
    const findings: Finding[] = [];
    const targetFiles = await this.getJavaScriptFiles(config.scan.target);

    for (const file of targetFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const fileFindings = await this.analyzeFile(file, content);
        findings.push(...fileFindings);
      } catch (error) {
        continue;
      }
    }

    return findings;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  private async getJavaScriptFiles(target: string): Promise<string[]> {
    const { glob } = await import('glob');
    return glob('**/*.{js,jsx,ts,tsx,mjs,cjs}', {
      cwd: target,
      absolute: true,
      ignore: [
        '**/node_modules/**',
        '**/dist/**',
        '**/build/**',
        '**/*.min.js',
        '**/*.test.*',
        '**/*.spec.*',
      ],
    });
  }

  private async analyzeFile(filePath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      const lineNumber = lineIndex + 1;

      for (const keyPattern of API_KEY_PATTERNS) {
        const matches = line.matchAll(new RegExp(keyPattern.pattern, 'gi'));

        for (const match of matches) {
          const snippet = match[0];
          const context = this.getContext(lines, lineIndex, 5);
          
          if (keyPattern.contextValidation) {
            const shouldFlag = keyPattern.contextValidation(context, snippet);
            if (!shouldFlag) {
              continue;
            }
          }

          if (this.isFalsePositive(snippet, context)) {
            continue;
          }

          findings.push({
            id: randomUUID(),
            ruleId: `hardcoded-${keyPattern.name.toLowerCase().replace(/\s+/g, '-')}`,
            source: 'custom-secrets',
            severity: keyPattern.severity,
            category: 'secrets',
            title: `Hardcoded ${keyPattern.name} detected`,
            description: `Found a hardcoded ${keyPattern.name} in the source code. ${keyPattern.isPublicKey ? 'Verify this is a public/read-only key.' : 'This should be moved to environment variables.'}`,
            snippet,
            file: filePath,
            line: lineNumber,
            confidence: keyPattern.isPublicKey ? 0.6 : 0.9,
            detectedAt: new Date().toISOString(),
            remediation: {
              summary: keyPattern.isPublicKey 
                ? 'Verify key permissions and consider environment variables'
                : 'Move to environment variables immediately',
              code: keyPattern.isPublicKey
                ? '// For public keys, ensure proper restrictions\nconst apiKey = process.env.PUBLIC_API_KEY;'
                : '// Move to environment variables\nconst apiKey = process.env.API_KEY;',
              references: [
                'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
                'https://cwe.mitre.org/data/definitions/798.html',
              ],
              effort: 'low',
            },
          });
        }
      }
    }

    return findings;
  }

  private getContext(lines: string[], currentLine: number, contextSize: number): string {
    const start = Math.max(0, currentLine - contextSize);
    const end = Math.min(lines.length, currentLine + contextSize + 1);
    return lines.slice(start, end).join('\n');
  }

  private isFalsePositive(snippet: string, context: string): boolean {
    const falsePositivePatterns = [
      /your[_-]?api[_-]?key/i,
      /example[_-]?key/i,
      /test[_-]?key/i,
      /sample[_-]?key/i,
      /placeholder/i,
      /xxx+/i,
      /000+/i,
    ];

    if (falsePositivePatterns.some(pattern => pattern.test(snippet))) {
      return true;
    }

    if (/\/\/.*|\/\*[\s\S]*?\*\//g.test(context)) {
      return true;
    }

    if (/process\.env|env\.|getenv|ENV/i.test(context)) {
      return true;
    }

    return false;
  }
}