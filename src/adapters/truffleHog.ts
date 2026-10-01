/**
 * TruffleHog adapter for secrets detection
 */

import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import type { ScannerAdapter, ScanConfig, Finding } from '../types.js';

export class TruffleHogAdapter implements ScannerAdapter {
  name = 'truffleHog';

  async isAvailable(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('trufflehog', ['--version']);
      proc.on('error', () => resolve(false));
      proc.on('exit', (code) => resolve(code === 0));
    });
  }

  async scan(config: ScanConfig): Promise<Finding[]> {
    if (!config.tools.truffleHog?.enabled) {
      return [];
    }

    // Merge the global scan.exclude list with the per-tool one — without
    // this, a default-config scan ignores scan.exclude entirely for
    // TruffleHog and traverses node_modules/dist/.git regardless of it.
    const excludePatterns = [
      ...(config.scan.exclude || []),
      ...(config.tools.truffleHog?.exclude || []),
    ];
    let excludeFile: string | undefined;
    if (excludePatterns.length > 0) {
      excludeFile = path.join(os.tmpdir(), `trufflehog-exclude-${randomUUID()}.txt`);
      // --exclude-paths expects one RE2 regex per line, not glob syntax.
      // Patterns configured as globs (e.g. "**/test-fixtures/**") would
      // either fail to match as intended or, worse, be invalid RE2 (Go's
      // regex engine rejects some malformed repetition operators) and crash
      // TruffleHog outright. Convert the common glob syntax to regex first.
      const regexPatterns = excludePatterns.map((p) => this.globToRegex(p));
      await fs.writeFile(excludeFile, regexPatterns.join('\n'), 'utf-8');
    }

    try {
      return await this.runScan(config, excludeFile);
    } finally {
      if (excludeFile) {
        await fs.unlink(excludeFile).catch(() => {});
      }
    }
  }

  private async runScan(config: ScanConfig, excludeFile: string | undefined): Promise<Finding[]> {
    const findings: Finding[] = [];

    return new Promise((resolve, reject) => {
      const args = [
        'filesystem',
        config.scan.target,
        '--json',
        '--no-verification',
        // Without this, scans traverse excluded directories (e.g.
        // node_modules) regardless of the configured exclusion list.
        ...(excludeFile ? [`--exclude-paths=${excludeFile}`] : []),
        ...(config.tools.truffleHog?.args || []),
      ];

      const proc = spawn('trufflehog', args);
      let output = '';
      let errorOutput = '';

      proc.stdout.on('data', (data) => {
        output += data.toString();
      });

      proc.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      proc.on('close', (code) => {
        if (code !== 0 && code !== 183) {
          // 183 = findings found
          reject(new Error(`TruffleHog exited with code ${code}: ${errorOutput}`));
          return;
        }

        // Parse TruffleHog JSON output
        const lines = output.split('\n').filter(Boolean);
        for (const line of lines) {
          try {
            const result = JSON.parse(line);
            findings.push(this.convertToFinding(result));
          } catch (err) {
            // Skip invalid JSON lines
          }
        }

        resolve(findings);
      });

      proc.on('error', (err) => {
        reject(new Error(`Failed to spawn TruffleHog: ${err.message}`));
      });
    });
  }

  /**
   * Convert a simple glob pattern to the RE2-compatible regex TruffleHog's
   * --exclude-paths expects. Handles the common cases this config's callers
   * actually use (directory names, `*`, `**`); not a full glob implementation.
   */
  private globToRegex(glob: string): string {
    const escaped = glob
      .replace(/[.+^${}()|[\]\\]/g, '\\$&') // escape regex metacharacters
      .replace(/\*\*/g, '\u0000') // placeholder for "**" so the next line doesn't re-match it
      .replace(/\*/g, '[^/]*')
      .replace(/\u0000/g, '.*');
    return escaped;
  }

  private convertToFinding(truffleHogResult: any): Finding {
    const detectorName = truffleHogResult.DetectorName || 'unknown';
    // Never persist the live secret value (`Raw`) into a finding/report.
    // TruffleHog's own `Redacted` field masks the middle of the match; fall
    // back to a fixed placeholder if it's missing rather than the raw value.
    const snippet = truffleHogResult.Redacted || '[secret redacted]';
    const sourceMetadata = truffleHogResult.SourceMetadata?.Data?.Filesystem || {};

    return {
      id: randomUUID(),
      ruleId: `trufflehog-${detectorName.toLowerCase()}`,
      source: 'truffleHog',
      severity: this.mapSeverity(truffleHogResult.Verified),
      category: 'secrets',
      title: `Potential ${detectorName} secret detected`,
      description: `TruffleHog detected a potential ${detectorName} secret in the codebase.`,
      snippet,
      file: sourceMetadata.file || 'unknown',
      line: sourceMetadata.line || 0,
      confidence: truffleHogResult.Verified ? 0.95 : 0.7,
      detectedAt: new Date().toISOString(),
      remediation: {
        summary: 'Move secret to environment variable or secure vault',
        code: `// Use environment variables instead\nconst secret = process.env.${detectorName.toUpperCase()}_SECRET;`,
        references: [
          'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
          'https://cwe.mitre.org/data/definitions/798.html',
        ],
        effort: 'low',
      },
    };
  }

  private mapSeverity(verified: boolean): Finding['severity'] {
    return verified ? 'CRITICAL' : 'HIGH';
  }
}
