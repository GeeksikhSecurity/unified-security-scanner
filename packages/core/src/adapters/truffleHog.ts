/**
 * TruffleHog adapter for secrets detection
 */

import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
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

    const findings: Finding[] = [];

    return new Promise((resolve, reject) => {
      const args = [
        'filesystem',
        config.scan.target,
        '--json',
        '--no-verification',
        ...(config.tools.truffleHog.args || []),
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

  private convertToFinding(truffleHogResult: any): Finding {
    const detectorName = truffleHogResult.DetectorName || 'unknown';
    const raw = truffleHogResult.Raw || '';
    const sourceMetadata = truffleHogResult.SourceMetadata?.Data?.Filesystem || {};

    return {
      id: randomUUID(),
      ruleId: `trufflehog-${detectorName.toLowerCase()}`,
      source: 'truffleHog',
      severity: this.mapSeverity(truffleHogResult.Verified),
      category: 'secrets',
      title: `Potential ${detectorName} secret detected`,
      description: `TruffleHog detected a potential ${detectorName} secret in the codebase.`,
      snippet: raw.substring(0, 100),
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
