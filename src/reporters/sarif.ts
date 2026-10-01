/**
 * SARIF 2.1.0 reporter for GitHub Security integration
 */

import { writeFile } from 'fs/promises';
import type { Reporter, ScanResult, Finding } from '../types.js';

interface SarifReport {
  version: '2.1.0';
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri?: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: {
            text: string;
          };
          fullDescription?: {
            text: string;
          };
          help?: {
            text: string;
            markdown?: string;
          };
          properties?: {
            tags?: string[];
            precision?: string;
            'security-severity'?: string;
          };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: 'error' | 'warning' | 'note';
      message: {
        text: string;
      };
      locations: Array<{
        physicalLocation: {
          artifactLocation: {
            uri: string;
          };
          region: {
            startLine: number;
            startColumn?: number;
            endLine?: number;
            endColumn?: number;
            snippet?: {
              text: string;
            };
          };
        };
      }>;
      fixes?: Array<{
        description: {
          text: string;
        };
        artifactChanges: Array<{
          artifactLocation: {
            uri: string;
          };
          replacements: Array<{
            deletedRegion: {
              startLine: number;
              startColumn?: number;
              endLine?: number;
              endColumn?: number;
            };
            insertedContent?: {
              text: string;
            };
          }>;
        }>;
      }>;
    }>;
  }>;
}

export class SarifReporter implements Reporter {
  name = 'sarif';

  async generate(result: ScanResult): Promise<string> {
    const rules = this.extractRules(result.findings);

    const sarifReport: SarifReport = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'Unified Security Scanner',
              version: result.version,
              informationUri: 'https://github.com/yourusername/unified-security-scanner',
              rules,
            },
          },
          results: result.findings.map((finding) => this.convertToSarifResult(finding)),
        },
      ],
    };

    return JSON.stringify(sarifReport, null, 2);
  }

  async write(content: string, outputPath: string): Promise<void> {
    await writeFile(outputPath, content, 'utf-8');
  }

  private extractRules(findings: Finding[]): SarifReport['runs'][0]['tool']['driver']['rules'] {
    const rulesMap = new Map<string, Finding>();

    for (const finding of findings) {
      if (!rulesMap.has(finding.ruleId)) {
        rulesMap.set(finding.ruleId, finding);
      }
    }

    return Array.from(rulesMap.values()).map((finding) => ({
      id: finding.ruleId,
      name: this.toRuleName(finding.ruleId),
      shortDescription: {
        text: finding.title,
      },
      fullDescription: {
        text: finding.description,
      },
      help: {
        text: finding.remediation.summary,
        markdown: this.formatHelpMarkdown(finding),
      },
      properties: {
        tags: [finding.category, 'security'],
        precision: this.mapPrecision(finding.confidence),
        'security-severity': this.mapSecuritySeverity(finding.severity),
      },
    }));
  }

  private convertToSarifResult(finding: Finding): SarifReport['runs'][0]['results'][0] {
    return {
      ruleId: finding.ruleId,
      level: this.mapLevel(finding.severity),
      message: {
        text: finding.title,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.file,
            },
            region: {
              startLine: finding.line,
              startColumn: finding.column,
              endLine: finding.endLine,
              endColumn: finding.endColumn,
              snippet: {
                text: finding.snippet,
              },
            },
          },
        },
      ],
    };
  }

  private toRuleName(ruleId: string): string {
    return ruleId
      .split('-')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join('');
  }

  private formatHelpMarkdown(finding: Finding): string {
    let markdown = `## ${finding.title}\n\n${finding.description}\n\n`;

    if (finding.remediation.code) {
      markdown += `### Remediation\n\n\`\`\`\n${finding.remediation.code}\n\`\`\`\n\n`;
    }

    if (finding.remediation.references.length > 0) {
      markdown += `### References\n\n`;
      for (const ref of finding.remediation.references) {
        markdown += `- ${ref}\n`;
      }
    }

    return markdown;
  }

  private mapLevel(severity: Finding['severity']): 'error' | 'warning' | 'note' {
    const levelMap: Record<Finding['severity'], 'error' | 'warning' | 'note'> = {
      CRITICAL: 'error',
      HIGH: 'error',
      MEDIUM: 'warning',
      LOW: 'warning',
      INFO: 'note',
    };
    return levelMap[severity];
  }

  private mapPrecision(confidence: number): string {
    if (confidence >= 0.9) return 'very-high';
    if (confidence >= 0.75) return 'high';
    if (confidence >= 0.5) return 'medium';
    return 'low';
  }

  private mapSecuritySeverity(severity: Finding['severity']): string {
    const severityMap: Record<Finding['severity'], string> = {
      CRITICAL: '9.0',
      HIGH: '7.0',
      MEDIUM: '5.0',
      LOW: '3.0',
      INFO: '1.0',
    };
    return severityMap[severity];
  }
}
