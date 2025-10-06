/**
 * Semgrep adapter for pattern-based security scanning
 */

import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import type { ScannerAdapter, ScanConfig, Finding } from '../types.js';

export class SemgrepAdapter implements ScannerAdapter {
  name = 'semgrep';

  async isAvailable(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn('semgrep', ['--version']);
      proc.on('error', () => resolve(false));
      proc.on('exit', (code) => resolve(code === 0));
    });
  }

  async scan(config: ScanConfig): Promise<Finding[]> {
    if (!config.tools.semgrep?.enabled) {
      return [];
    }

    const findings: Finding[] = [];

    return new Promise((resolve, reject) => {
      const args = [
        'scan',
        '--json',
        '--config=auto', // Use Semgrep Registry rules
        config.scan.target,
      ];

      // Add custom config if provided
      if (config.tools.semgrep.config) {
        args.push(`--config=${config.tools.semgrep.config}`);
      }

      // Add custom rules
      for (const rule of config.tools.semgrep.rules || []) {
        args.push(`--config=${rule}`);
      }

      const proc = spawn('semgrep', args);
      let output = '';
      let errorOutput = '';

      proc.stdout.on('data', (data) => {
        output += data.toString();
      });

      proc.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      proc.on('close', (code) => {
        if (code !== 0 && code !== 1) {
          // 1 = findings found
          reject(new Error(`Semgrep exited with code ${code}: ${errorOutput}`));
          return;
        }

        try {
          const result = JSON.parse(output);
          const semgrepFindings = result.results || [];

          for (const finding of semgrepFindings) {
            findings.push(this.convertToFinding(finding));
          }

          resolve(findings);
        } catch (err) {
          reject(new Error(`Failed to parse Semgrep output: ${err}`));
        }
      });

      proc.on('error', (err) => {
        reject(new Error(`Failed to spawn Semgrep: ${err.message}`));
      });
    });
  }

  private convertToFinding(semgrepResult: any): Finding {
    const extra = semgrepResult.extra || {};
    const metadata = extra.metadata || {};

    return {
      id: randomUUID(),
      ruleId: semgrepResult.check_id || 'unknown',
      source: 'semgrep',
      severity: this.mapSeverity(extra.severity || 'WARNING'),
      category: this.mapCategory(metadata),
      cwe: metadata.cwe ? `CWE-${metadata.cwe[0]}` : undefined,
      owasp: metadata.owasp?.[0],
      title: extra.message || 'Security issue detected',
      description: metadata.description || extra.message || 'Semgrep detected a potential security issue.',
      snippet: semgrepResult.extra?.lines || '',
      file: semgrepResult.path || 'unknown',
      line: semgrepResult.start?.line || 0,
      column: semgrepResult.start?.col,
      endLine: semgrepResult.end?.line,
      endColumn: semgrepResult.end?.col,
      confidence: this.mapConfidence(extra.severity),
      detectedAt: new Date().toISOString(),
      remediation: {
        summary: metadata.fix_summary || 'Review and fix the security issue',
        code: semgrepResult.extra?.fix,
        references: [
          ...(metadata.references || []),
          `https://semgrep.dev/r/${semgrepResult.check_id}`,
        ],
        effort: metadata.effort || 'medium',
      },
    };
  }

  private mapSeverity(semgrepSeverity: string): Finding['severity'] {
    const severityMap: Record<string, Finding['severity']> = {
      ERROR: 'CRITICAL',
      WARNING: 'HIGH',
      INFO: 'MEDIUM',
    };
    return severityMap[semgrepSeverity] || 'MEDIUM';
  }

  private mapCategory(metadata: any): Finding['category'] {
    const category = metadata.category;
    if (category?.includes('secret')) return 'secrets';
    if (category?.includes('injection')) return 'injection';
    if (category?.includes('auth')) return 'auth';
    if (category?.includes('crypto')) return 'crypto';
    return 'other';
  }

  private mapConfidence(severity: string): number {
    const confidenceMap: Record<string, number> = {
      ERROR: 0.9,
      WARNING: 0.75,
      INFO: 0.6,
    };
    return confidenceMap[severity] || 0.7;
  }
}
