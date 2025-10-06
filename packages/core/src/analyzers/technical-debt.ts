/**
 * Technical debt analyzer for outdated packages
 * Detects EOL packages, outdated versions, and provides upgrade paths
 */

import { spawn } from 'child_process';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { randomUUID } from 'crypto';
import type { ScannerAdapter, ScanConfig, Finding } from '../types.js';

interface PackageJson {
  name: string;
  version: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface NpmOutdatedResult {
  [packageName: string]: {
    current: string;
    wanted: string;
    latest: string;
    location: string;
    type: 'dependencies' | 'devDependencies';
  };
}

interface NpmAuditResult {
  vulnerabilities: Record<
    string,
    {
      severity: 'low' | 'moderate' | 'high' | 'critical';
      via: Array<{
        title: string;
        url: string;
        severity: string;
      }>;
      fixAvailable: boolean | { name: string; version: string };
    }
  >;
}

// Known EOL packages and their replacements
const EOL_PACKAGES: Record<
  string,
  { endDate: string; replacement?: string; reason: string }
> = {
  'request': {
    endDate: '2020-02-11',
    replacement: 'axios, node-fetch, or got',
    reason: 'Fully deprecated - use modern HTTP clients',
  },
  'node-sass': {
    endDate: '2022-01-01',
    replacement: 'sass (dart-sass)',
    reason: 'LibSass is deprecated - migrate to Dart Sass',
  },
  '@types/react@<18': {
    endDate: '2024-01-01',
    replacement: '@types/react@18',
    reason: 'React 17 types are outdated',
  },
  'moment': {
    endDate: '2020-09-15',
    replacement: 'date-fns, dayjs, or luxon',
    reason: 'In maintenance mode - consider modern alternatives',
  },
};

export class TechnicalDebtAnalyzer implements ScannerAdapter {
  name = 'technical-debt-analyzer';

  async isAvailable(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('npm', ['--version']);
      proc.on('error', () => resolve(false));
      proc.on('exit', (code) => resolve(code === 0));
    });
  }

  async scan(config: ScanConfig): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const packageJsonPath = join(config.scan.target, 'package.json');
      const content = await readFile(packageJsonPath, 'utf-8');
      const packageJson: PackageJson = JSON.parse(content);

      // Check for EOL packages
      findings.push(...(await this.detectEOLPackages(packageJson, packageJsonPath)));

      // Check for outdated packages
      findings.push(...(await this.detectOutdatedPackages(config.scan.target, packageJsonPath)));

      // Check for vulnerabilities with npm audit
      findings.push(...(await this.detectVulnerabilities(config.scan.target, packageJsonPath)));
    } catch (error) {
      // Ignore if package.json not found
    }

    return findings;
  }

  private async detectEOLPackages(pkg: PackageJson, filePath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    for (const [depName, version] of Object.entries(allDeps || {})) {
      const eolInfo = EOL_PACKAGES[depName];

      if (eolInfo) {
        findings.push({
          id: randomUUID(),
          ruleId: 'technical-debt-eol-package',
          source: 'custom-npm',
          severity: 'HIGH',
          category: 'dependency',
          title: `End-of-life package: ${depName}`,
          description: `The package "${depName}" has reached end-of-life as of ${eolInfo.endDate}. ${eolInfo.reason}`,
          snippet: `"${depName}": "${version}"`,
          file: filePath,
          line: 0,
          confidence: 1.0,
          detectedAt: new Date().toISOString(),
          remediation: {
            summary: eolInfo.replacement
              ? `Replace with ${eolInfo.replacement}`
              : 'Remove or find alternative package',
            code: eolInfo.replacement
              ? `npm uninstall ${depName}\nnpm install ${eolInfo.replacement.split(',')[0].trim()}`
              : `npm uninstall ${depName}`,
            references: [
              'https://endoflife.date/',
              'https://github.com/nodejs/package-maintenance',
            ],
            effort: 'high',
          },
        });
      }
    }

    return findings;
  }

  private async detectOutdatedPackages(targetDir: string, filePath: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    return new Promise((resolve) => {
      const proc = spawn('npm', ['outdated', '--json'], {
        cwd: targetDir,
        shell: true,
      });

      let output = '';

      proc.stdout.on('data', (data) => {
        output += data.toString();
      });

      proc.on('close', () => {
        try {
          if (!output.trim()) {
            resolve([]);
            return;
          }

          const outdated: NpmOutdatedResult = JSON.parse(output);

          for (const [pkgName, info] of Object.entries(outdated)) {
            const majorVersionBehind = this.getMajorVersionDiff(info.current, info.latest);

            if (majorVersionBehind > 0) {
              findings.push({
                id: randomUUID(),
                ruleId: 'technical-debt-outdated-major',
                source: 'custom-npm',
                severity: majorVersionBehind >= 2 ? 'MEDIUM' : 'LOW',
                category: 'dependency',
                title: `Outdated package: ${pkgName} (${majorVersionBehind} major version${majorVersionBehind > 1 ? 's' : ''} behind)`,
                description: `Package "${pkgName}" is ${majorVersionBehind} major version${majorVersionBehind > 1 ? 's' : ''} behind. Current: ${info.current}, Latest: ${info.latest}`,
                snippet: `"${pkgName}": "${info.current}" → "${info.latest}"`,
                file: filePath,
                line: 0,
                confidence: 0.9,
                detectedAt: new Date().toISOString(),
                remediation: {
                  summary: `Update to latest version ${info.latest}`,
                  code: `npm install ${pkgName}@${info.latest}`,
                  references: [
                    `https://www.npmjs.com/package/${pkgName}`,
                    `https://www.npmjs.com/package/${pkgName}?activeTab=versions`,
                  ],
                  effort: majorVersionBehind >= 2 ? 'high' : 'medium',
                },
              });
            }
          }

          resolve(findings);
        } catch (error) {
          // If parsing fails, just return empty findings
          resolve([]);
        }
      });

      proc.on('error', () => {
        resolve([]);
      });
    });
  }

  private async detectVulnerabilities(targetDir: string, filePath: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    return new Promise((resolve) => {
      const proc = spawn('npm', ['audit', '--json'], {
        cwd: targetDir,
        shell: true,
      });

      let output = '';

      proc.stdout.on('data', (data) => {
        output += data.toString();
      });

      proc.on('close', () => {
        try {
          if (!output.trim()) {
            resolve([]);
            return;
          }

          const audit: NpmAuditResult = JSON.parse(output);

          for (const [pkgName, vuln] of Object.entries(audit.vulnerabilities || {})) {
            const firstVia = Array.isArray(vuln.via) ? vuln.via[0] : null;

            if (firstVia && typeof firstVia === 'object') {
              findings.push({
                id: randomUUID(),
                ruleId: 'technical-debt-vulnerability',
                source: 'custom-npm',
                severity: this.mapNpmSeverity(vuln.severity),
                category: 'dependency',
                title: `Vulnerability in ${pkgName}: ${firstVia.title}`,
                description: `Security vulnerability detected in ${pkgName}. ${firstVia.title}`,
                snippet: `"${pkgName}": vulnerable`,
                file: filePath,
                line: 0,
                confidence: 0.95,
                detectedAt: new Date().toISOString(),
                remediation: {
                  summary: vuln.fixAvailable
                    ? typeof vuln.fixAvailable === 'object'
                      ? `Update to ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`
                      : 'Run npm audit fix'
                    : 'No automatic fix available - manual intervention required',
                  code: vuln.fixAvailable ? 'npm audit fix' : '',
                  references: [firstVia.url, `https://www.npmjs.com/package/${pkgName}`],
                  effort: vuln.fixAvailable ? 'low' : 'high',
                },
              });
            }
          }

          resolve(findings);
        } catch (error) {
          resolve([]);
        }
      });

      proc.on('error', () => {
        resolve([]);
      });
    });
  }

  private getMajorVersionDiff(current: string, latest: string): number {
    const currentMajor = parseInt(current.split('.')[0].replace(/\D/g, ''), 10) || 0;
    const latestMajor = parseInt(latest.split('.')[0].replace(/\D/g, ''), 10) || 0;
    return Math.max(0, latestMajor - currentMajor);
  }

  private mapNpmSeverity(
    npmSeverity: 'low' | 'moderate' | 'high' | 'critical'
  ): Finding['severity'] {
    const map: Record<string, Finding['severity']> = {
      critical: 'CRITICAL',
      high: 'HIGH',
      moderate: 'MEDIUM',
      low: 'LOW',
    };
    return map[npmSeverity] || 'MEDIUM';
  }
}
