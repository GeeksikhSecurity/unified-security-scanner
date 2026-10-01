/**
 * SARIF Processing Script for merging multiple SARIF files and deduplicating findings
 * Based on Security Testing Checklist Appendix B
 */

import { promises as fs } from 'fs';
import { randomUUID } from 'crypto';
import type { Finding, ScanResult } from './types.js';

export interface SARIFReport {
  $schema: string;
  version: string;
  runs: SARIFRun[];
}

export interface SARIFRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      rules?: SARIFRule[];
    };
  };
  results: SARIFResult[];
}

export interface SARIFRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  help?: { text: string };
  properties?: {
    tags?: string[];
    precision?: string;
    'security-severity'?: string;
  };
}

export interface SARIFResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'info';
  message: { text: string };
  locations: SARIFLocation[];
  properties?: {
    tags?: string[];
  };
}

export interface SARIFLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region: {
      startLine: number;
      startColumn?: number;
      endLine?: number;
      endColumn?: number;
      snippet?: { text: string };
    };
  };
}

export class SARIFProcessor {
  /**
   * Merge multiple SARIF files into one and deduplicate findings
   */
  static async mergeSARIFFiles(inputFiles: string[], outputFile: string): Promise<void> {
    const merged: SARIFReport = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [],
    };

    const seenResults = new Set<string>();
    let totalFindings = 0;

    for (const inputFile of inputFiles) {
      try {
        const content = await fs.readFile(inputFile, 'utf8');
        const sarif: SARIFReport = JSON.parse(content);

        for (const run of sarif.runs || []) {
          const mergedRun: SARIFRun = {
            tool: run.tool,
            results: [],
          };

          // Deduplicate based on location and rule
          for (const result of run.results || []) {
            const location = result.locations?.[0]?.physicalLocation;
            if (!location) continue;

            const key = this.createResultKey(result.ruleId, location);

            if (!seenResults.has(key)) {
              seenResults.add(key);
              mergedRun.results.push(result);
              totalFindings++;
            }
          }

          if (mergedRun.results.length > 0) {
            merged.runs.push(mergedRun);
          }
        }
      } catch (error) {
        console.warn(`Failed to process SARIF file ${inputFile}:`, error);
      }
    }

    await fs.writeFile(outputFile, JSON.stringify(merged, null, 2));
    
    console.log(`Merged ${inputFiles.length} files into ${outputFile}`);
    console.log(`Total unique findings: ${totalFindings}`);
  }

  /**
   * Convert ScanResult to SARIF format
   */
  static generateSARIF(result: ScanResult, sourceRoot: string = '.'): SARIFReport {
    const rules: SARIFRule[] = this.generateRules(result.findings);
    
    const sarifResults: SARIFResult[] = result.findings.map(finding => ({
      ruleId: finding.ruleId,
      level: this.mapSeverityToLevel(finding.severity),
      message: { text: finding.description },
      locations: [{
        physicalLocation: {
          artifactLocation: { 
            uri: this.relativePath(finding.file, sourceRoot) 
          },
          region: {
            // SARIF requires startLine/endLine >= 1. Some findings (e.g.
            // MaliciousPackageScanner's package.json-level matches) don't
            // have a specific line and report 0 — clamp to 1 rather than
            // emit a region GitHub's SARIF validator rejects outright.
            startLine: Math.max(1, finding.line),
            startColumn: finding.column || 1,
            endLine: Math.max(1, finding.endLine || finding.line),
            endColumn: finding.endColumn,
            snippet: finding.snippet ? { text: finding.snippet } : undefined,
          },
        },
      }],
      properties: {
        tags: [finding.category, finding.severity.toLowerCase()],
      },
    }));

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'Enhanced Security Scanner',
            version: result.version,
            rules,
          },
        },
        results: sarifResults,
      }],
    };
  }

  /**
   * Validate SARIF file against schema
   */
  static async validateSARIF(sarifFile: string): Promise<boolean> {
    try {
      const content = await fs.readFile(sarifFile, 'utf8');
      const sarif = JSON.parse(content);
      
      // Basic validation
      if (!sarif.$schema || !sarif.version || !sarif.runs) {
        return false;
      }
      
      // Validate each run
      for (const run of sarif.runs) {
        if (!run.tool || !run.tool.driver || !run.results) {
          return false;
        }
      }
      
      return true;
    } catch (error) {
      console.error('SARIF validation failed:', error);
      return false;
    }
  }

  /**
   * Extract findings from SARIF file
   */
  static async extractFindings(sarifFile: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      const content = await fs.readFile(sarifFile, 'utf8');
      const sarif: SARIFReport = JSON.parse(content);
      
      for (const run of sarif.runs || []) {
        const toolName = run.tool.driver.name;
        
        for (const result of run.results || []) {
          const location = result.locations?.[0]?.physicalLocation;
          if (!location) continue;
          
          findings.push({
            id: randomUUID(),
            ruleId: result.ruleId,
            source: this.mapToolNameToSource(toolName),
            severity: this.mapLevelToSeverity(result.level, result.properties?.tags),
            category: this.inferCategory(result.ruleId),
            file: location.artifactLocation.uri,
            line: location.region.startLine,
            column: location.region.startColumn,
            endLine: location.region.endLine,
            endColumn: location.region.endColumn,
            title: result.message.text,
            description: result.message.text,
            snippet: location.region.snippet?.text || '',
            remediation: {
              summary: 'Review and fix the identified security issue',
              references: [],
              effort: 'medium',
            },
            confidence: 0.8,
            detectedAt: new Date().toISOString(),
          });
        }
      }
    } catch (error) {
      console.error('Failed to extract findings from SARIF:', error);
    }
    
    return findings;
  }

  /**
   * Generate critical findings report
   */
  static async checkCriticalFindings(sarifFile: string): Promise<{
    hasCritical: boolean;
    criticalCount: number;
    highCount: number;
    findings: Finding[];
  }> {
    const findings = await this.extractFindings(sarifFile);
    
    const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
    const highFindings = findings.filter(f => f.severity === 'HIGH');
    
    return {
      hasCritical: criticalFindings.length > 0,
      criticalCount: criticalFindings.length,
      highCount: highFindings.length,
      findings: [...criticalFindings, ...highFindings],
    };
  }

  /**
   * Generate security summary for PR comments
   */
  static generateSecuritySummary(findings: Finding[]): string {
    const stats = {
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
      HIGH: findings.filter(f => f.severity === 'HIGH').length,
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
      LOW: findings.filter(f => f.severity === 'LOW').length,
    };

    const lines = [
      '## 🛡️ Security Scan Results',
      '',
      `**Total Findings:** ${findings.length}`,
      '',
      '| Severity | Count |',
      '|----------|-------|',
      `| 🔴 Critical | ${stats.CRITICAL} |`,
      `| 🟠 High | ${stats.HIGH} |`,
      `| 🟡 Medium | ${stats.MEDIUM} |`,
      `| ⚪ Low | ${stats.LOW} |`,
      '',
    ];

    if (stats.CRITICAL > 0) {
      lines.push('⚠️ **Critical vulnerabilities found!** Please review and fix before merging.');
    } else if (stats.HIGH > 0) {
      lines.push('⚠️ **High severity issues found.** Consider reviewing before merging.');
    } else {
      lines.push('✅ **No critical or high severity issues found.**');
    }

    return lines.join('\n');
  }

  // Private helper methods
  private static createResultKey(ruleId: string, location: SARIFLocation['physicalLocation']): string {
    return `${ruleId}:${location.artifactLocation.uri}:${location.region.startLine}`;
  }

  private static generateRules(findings: Finding[]): SARIFRule[] {
    const ruleMap = new Map<string, SARIFRule>();

    for (const finding of findings) {
      if (!ruleMap.has(finding.ruleId)) {
        ruleMap.set(finding.ruleId, {
          id: finding.ruleId,
          name: finding.title,
          shortDescription: { text: finding.title },
          fullDescription: { text: finding.description },
          help: { text: finding.remediation.summary },
          properties: {
            tags: [finding.category],
            precision: 'high',
            'security-severity': this.mapSeverityToSecuritySeverity(finding.severity),
          },
        });
      }
    }

    return Array.from(ruleMap.values());
  }

  private static mapSeverityToLevel(severity: string): SARIFResult['level'] {
    switch (severity) {
      case 'CRITICAL': return 'error';
      case 'HIGH': return 'error';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'note';
      default: return 'info';
    }
  }

  private static mapLevelToSeverity(level: string, tags?: string[]): Finding['severity'] {
    // `mapSeverityToLevel` collapses both CRITICAL and HIGH to SARIF's 'error'
    // level (SARIF only has 4 levels for 5 severities), so decoding from
    // `level` alone can never recover HIGH — it always comes back CRITICAL.
    // The encoder also writes the real severity as a lowercase tag
    // (`tags: [finding.category, finding.severity.toLowerCase()]`); read that
    // back first when present, and only fall back to the lossy `level`
    // mapping for SARIF from tools that don't use this tag convention.
    const severities: Finding['severity'][] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const tagSeverity = tags
      ?.map((t) => t.toUpperCase())
      .find((t) => severities.includes(t as Finding['severity']));
    if (tagSeverity) {
      return tagSeverity as Finding['severity'];
    }

    switch (level) {
      case 'error': return 'CRITICAL';
      case 'warning': return 'HIGH';
      case 'note': return 'MEDIUM';
      case 'info': return 'LOW';
      default: return 'LOW';
    }
  }

  private static mapSeverityToSecuritySeverity(severity: string): string {
    switch (severity) {
      case 'CRITICAL': return '9.0';
      case 'HIGH': return '7.0';
      case 'MEDIUM': return '5.0';
      case 'LOW': return '3.0';
      default: return '1.0';
    }
  }

  private static mapToolNameToSource(toolName: string): Finding['source'] {
    const name = toolName.toLowerCase();
    if (name.includes('semgrep')) return 'semgrep';
    if (name.includes('trufflehog')) return 'truffleHog';
    return 'custom-secrets';
  }

  private static inferCategory(ruleId: string): Finding['category'] {
    const id = ruleId.toLowerCase();
    if (id.includes('secret') || id.includes('credential')) return 'secrets';
    if (id.includes('injection') || id.includes('sqli')) return 'injection';
    if (id.includes('auth') || id.includes('login')) return 'auth';
    if (id.includes('crypto') || id.includes('hash')) return 'crypto';
    if (id.includes('dependency') || id.includes('package')) return 'dependency';
    return 'other';
  }

  private static relativePath(filePath: string, sourceRoot: string): string {
    if (filePath.startsWith(sourceRoot)) {
      return filePath.substring(sourceRoot.length + 1);
    }
    return filePath;
  }
}

/**
 * CLI utility functions for SARIF processing
 */
export class SARIFCLIUtils {
  /**
   * Main entry point for SARIF merging
   */
  static async main(args: string[]): Promise<void> {
    if (args.length < 3) {
      console.log('Usage: sarif-processor output.sarif input1.sarif input2.sarif ...');
      process.exit(1);
    }

    const [outputFile, ...inputFiles] = args;
    
    try {
      await SARIFProcessor.mergeSARIFFiles(inputFiles, outputFile);
      
      // Validate the merged file
      const isValid = await SARIFProcessor.validateSARIF(outputFile);
      if (!isValid) {
        console.error('Generated SARIF file is invalid');
        process.exit(1);
      }
      
      // Check for critical/high findings. `hasCritical` alone would let a
      // HIGH-only result set through silently, even though the summary line
      // below reports high-severity findings too.
      const criticalCheck = await SARIFProcessor.checkCriticalFindings(outputFile);
      if (criticalCheck.hasCritical || criticalCheck.highCount > 0) {
        console.log(`⚠️  Found ${criticalCheck.criticalCount} critical and ${criticalCheck.highCount} high severity findings`);
        process.exit(1);
      }
      
      console.log('✅ SARIF processing completed successfully');
    } catch (error) {
      console.error('SARIF processing failed:', error);
      process.exit(1);
    }
  }
}