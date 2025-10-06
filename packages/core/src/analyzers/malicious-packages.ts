/**
 * Malicious package detection for npm dependencies
 * Detects typosquatting, dependency confusion, and malicious scripts
 */

import { readFile } from 'fs/promises';
import { join } from 'path';
import { randomUUID } from 'crypto';
import type { ScannerAdapter, ScanConfig, Finding } from '../types.js';

interface PackageJson {
  name: string;
  version: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

// Popular packages for typosquatting detection
const POPULAR_PACKAGES = [
  'react',
  'react-dom',
  'next',
  'express',
  'lodash',
  'axios',
  'typescript',
  'webpack',
  'eslint',
  'prettier',
  'jest',
  'vitest',
  '@testing-library/react',
  '@types/node',
  '@types/react',
];

// Suspicious script patterns
const SUSPICIOUS_SCRIPT_PATTERNS = [
  /curl\s+.*\|\s*sh/i, // Pipe to shell
  /wget\s+.*\|\s*sh/i, // Pipe to shell
  /eval\s*\(/i, // Eval usage
  /child_process/i, // Child process spawn
  /\.exec\s*\(/i, // Direct exec
  /base64/i, // Base64 encoding (potential obfuscation)
  /atob\s*\(/i, // Base64 decoding
  /fetch\s*\(.*http/i, // Network requests in scripts
  /axios\.get\s*\(.*http/i, // Network requests
  /process\.env\.npm_/i, // Accessing npm environment vars
];

// Internal package patterns (for dependency confusion)
const INTERNAL_PACKAGE_PREFIXES = ['@internal/', '@company/', '@org/'];

export class MaliciousPackageScanner implements ScannerAdapter {
  name = 'malicious-package-scanner';

  async isAvailable(): Promise<boolean> {
    return true; // Always available
  }

  async scan(config: ScanConfig): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const packageJsonPath = join(config.scan.target, 'package.json');
      const content = await readFile(packageJsonPath, 'utf-8');
      const packageJson: PackageJson = JSON.parse(content);

      // Check for typosquatting
      findings.push(...this.detectTyposquatting(packageJson, packageJsonPath));

      // Check for malicious scripts
      findings.push(...this.detectMaliciousScripts(packageJson, packageJsonPath));

      // Check for dependency confusion
      findings.push(...this.detectDependencyConfusion(packageJson, packageJsonPath));

      // Check for suspicious package names
      findings.push(...this.detectSuspiciousNames(packageJson, packageJsonPath));
    } catch (error) {
      // package.json not found or invalid - not an error
    }

    return findings;
  }

  private detectTyposquatting(pkg: PackageJson, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    for (const [depName, version] of Object.entries(allDeps || {})) {
      for (const popularPkg of POPULAR_PACKAGES) {
        const distance = this.levenshteinDistance(depName, popularPkg);

        // If names are similar but not exact (distance 1-2), flag as potential typosquatting
        if (distance > 0 && distance <= 2) {
          findings.push({
            id: randomUUID(),
            ruleId: 'malicious-typosquatting',
            source: 'custom-npm',
            severity: 'HIGH',
            category: 'dependency',
            title: `Potential typosquatting: ${depName} → ${popularPkg}`,
            description: `The package "${depName}" is very similar to the popular package "${popularPkg}" (Levenshtein distance: ${distance}). This could be a typosquatting attack.`,
            snippet: `"${depName}": "${version}"`,
            file: filePath,
            line: 0,
            confidence: distance === 1 ? 0.85 : 0.7,
            detectedAt: new Date().toISOString(),
            remediation: {
              summary: `Verify if you meant to install "${popularPkg}" instead of "${depName}"`,
              code: `// Replace in package.json:\n"${popularPkg}": "${version}"`,
              references: [
                'https://snyk.io/blog/typosquatting-attacks/',
                'https://owasp.org/www-community/attacks/Typosquatting',
              ],
              effort: 'low',
            },
          });
        }
      }
    }

    return findings;
  }

  private detectMaliciousScripts(pkg: PackageJson, filePath: string): Finding[] {
    const findings: Finding[] = [];

    if (!pkg.scripts) return findings;

    for (const [scriptName, scriptContent] of Object.entries(pkg.scripts)) {
      for (const pattern of SUSPICIOUS_SCRIPT_PATTERNS) {
        if (pattern.test(scriptContent)) {
          findings.push({
            id: randomUUID(),
            ruleId: 'malicious-script-pattern',
            source: 'custom-npm',
            severity: 'CRITICAL',
            category: 'dependency',
            title: `Suspicious script in package.json: ${scriptName}`,
            description: `The script "${scriptName}" contains potentially malicious patterns. Pattern matched: ${pattern.source}`,
            snippet: scriptContent,
            file: filePath,
            line: 0,
            confidence: 0.8,
            detectedAt: new Date().toISOString(),
            remediation: {
              summary: 'Review and remove malicious script patterns',
              references: [
                'https://blog.npmjs.org/post/173526807575/reported-malicious-module-eslint-scope',
                'https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream/',
              ],
              effort: 'medium',
            },
          });
        }
      }

      // Check for preinstall/postinstall hooks with network requests
      if (['preinstall', 'postinstall', 'preuninstall'].includes(scriptName)) {
        if (/curl|wget|fetch|axios|http/i.test(scriptContent)) {
          findings.push({
            id: randomUUID(),
            ruleId: 'malicious-install-hook',
            source: 'custom-npm',
            severity: 'CRITICAL',
            category: 'dependency',
            title: `Suspicious ${scriptName} hook with network access`,
            description: `The ${scriptName} hook makes network requests, which could exfiltrate data or download malicious payloads.`,
            snippet: scriptContent,
            file: filePath,
            line: 0,
            confidence: 0.9,
            detectedAt: new Date().toISOString(),
            remediation: {
              summary: 'Remove or review install hooks that make network requests',
              references: [
                'https://docs.npmjs.com/cli/v8/using-npm/scripts#life-cycle-scripts',
              ],
              effort: 'high',
            },
          });
        }
      }
    }

    return findings;
  }

  private detectDependencyConfusion(pkg: PackageJson, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    for (const [depName, version] of Object.entries(allDeps || {})) {
      // Check if package name looks like an internal package
      const isInternalLooking = INTERNAL_PACKAGE_PREFIXES.some((prefix) =>
        depName.startsWith(prefix)
      );

      if (isInternalLooking) {
        findings.push({
          id: randomUUID(),
          ruleId: 'dependency-confusion',
          source: 'custom-npm',
          severity: 'HIGH',
          category: 'dependency',
          title: `Potential dependency confusion: ${depName}`,
          description: `The package "${depName}" appears to be an internal package but might be resolved from public npm registry, leading to dependency confusion attacks.`,
          snippet: `"${depName}": "${version}"`,
          file: filePath,
          line: 0,
          confidence: 0.75,
          detectedAt: new Date().toISOString(),
          remediation: {
            summary: 'Ensure internal packages are resolved from private registry',
            code: `// Add to .npmrc:\n@internal:registry=https://your-private-registry.com`,
            references: [
              'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610',
              'https://docs.npmjs.com/cli/v8/configuring-npm/npmrc',
            ],
            effort: 'medium',
          },
        });
      }
    }

    return findings;
  }

  private detectSuspiciousNames(pkg: PackageJson, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    const suspiciousPatterns = [
      /discord.*token/i,
      /crypto.*miner/i,
      /password.*stealer/i,
      /keylogger/i,
      /backdoor/i,
      /malware/i,
      /trojan/i,
    ];

    for (const [depName, version] of Object.entries(allDeps || {})) {
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(depName)) {
          findings.push({
            id: randomUUID(),
            ruleId: 'suspicious-package-name',
            source: 'custom-npm',
            severity: 'CRITICAL',
            category: 'dependency',
            title: `Highly suspicious package name: ${depName}`,
            description: `The package name "${depName}" contains suspicious keywords that suggest malicious intent.`,
            snippet: `"${depName}": "${version}"`,
            file: filePath,
            line: 0,
            confidence: 0.95,
            detectedAt: new Date().toISOString(),
            remediation: {
              summary: 'Immediately remove this package and investigate',
              code: `npm uninstall ${depName}`,
              references: [
                'https://socket.dev/',
                'https://snyk.io/advisor/',
              ],
              effort: 'low',
            },
          });
        }
      }
    }

    return findings;
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }
}
