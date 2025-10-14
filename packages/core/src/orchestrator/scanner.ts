/**
 * Main scanner orchestrator that coordinates multiple security tools
 */

import { randomUUID } from 'crypto';
import pLimit from 'p-limit';
import type {
  ScanConfig,
  ScanResult,
  Finding,
  ScannerAdapter,
  Severity,
  Category,
  ScanSource,
} from '../types.js';

export class ScanOrchestrator {
  private adapters: ScannerAdapter[] = [];
  private version = '1.0.0';

  constructor(adapters: ScannerAdapter[]) {
    this.adapters = adapters;
  }

  async scan(config: ScanConfig): Promise<ScanResult> {
    const scanId = randomUUID();
    const startedAt = new Date().toISOString();
    const startTime = Date.now();

    const toolsRun: ScanResult['toolsRun'] = [];
    const allFindings: Finding[] = [];

    // Limit concurrent scanners based on configuration
    const limit = pLimit(config.performance.parallelWorkers || 4);

    // Run all enabled adapters in parallel
    const scanPromises = this.adapters.map((adapter) =>
      limit(async () => {
        const toolStartTime = Date.now();
        try {
          const isAvailable = await adapter.isAvailable();
          if (!isAvailable) {
            toolsRun.push({
              name: adapter.name,
              version: 'unknown',
              duration: 0,
              exitCode: -1,
              error: 'Tool not available',
            });
            return;
          }

          const findings = await adapter.scan(config);
          allFindings.push(...findings);

          toolsRun.push({
            name: adapter.name,
            version: 'unknown', // TODO: Get version from adapter
            duration: (Date.now() - toolStartTime) / 1000,
            exitCode: 0,
          });
        } catch (error) {
          toolsRun.push({
            name: adapter.name,
            version: 'unknown',
            duration: (Date.now() - toolStartTime) / 1000,
            exitCode: 1,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      })
    );

    await Promise.all(scanPromises);

    // Deduplicate findings
    const uniqueFindings = this.deduplicateFindings(allFindings);

    // Calculate statistics
    const stats = this.calculateStats(uniqueFindings);

    const completedAt = new Date().toISOString();
    const duration = (Date.now() - startTime) / 1000;

    return {
      scanId,
      version: this.version,
      startedAt,
      completedAt,
      duration,
      target: config.scan.target,
      filesScanned: 0, // TODO: Implement file counting
      linesOfCode: 0, // TODO: Implement LOC counting
      toolsRun,
      findings: uniqueFindings,
      suppressed: [],
      stats,
      performance: {
        parallelWorkers: config.performance.parallelWorkers,
        cacheHitRate: 0,
        incrementalScan: config.performance.incrementalScan,
      },
    };
  }

  private deduplicateFindings(findings: Finding[]): Finding[] {
    const seen = new Map<string, Finding>();

    for (const finding of findings) {
      // Create a unique key based on file, line, and rule
      const key = `${finding.file}:${finding.line}:${finding.ruleId}`;

      if (!seen.has(key)) {
        seen.set(key, finding);
      } else {
        // If we've seen this finding before, keep the one with higher confidence
        const existing = seen.get(key)!;
        if (finding.confidence > existing.confidence) {
          seen.set(key, finding);
        }
      }
    }

    return Array.from(seen.values());
  }

  private calculateStats(findings: Finding[]): ScanResult['stats'] {
    const bySeverity: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    const byCategory: Record<Category, number> = {
      secrets: 0,
      injection: 0,
      auth: 0,
      crypto: 0,
      dependency: 0,
      other: 0,
    };

    const bySource: Record<ScanSource, number> = {
      truffleHog: 0,
      semgrep: 0,
      'custom-npm': 0,
      'custom-react': 0,
      'custom-secrets': 0,
    };

    for (const finding of findings) {
      bySeverity[finding.severity]++;
      byCategory[finding.category]++;
      bySource[finding.source]++;
    }

    return {
      total: findings.length,
      bySeverity,
      byCategory,
      bySource,
      suppressedCount: 0,
    };
  }
}
