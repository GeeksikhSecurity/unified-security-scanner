/**
 * Multi-Scan Orchestrator implementing the 3-phase security scanning strategy
 * Based on Security Testing Checklist: Claude Code & AWS Q Developer
 */

import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { randomUUID } from 'crypto';
import type { Finding, ScanConfig, ScanResult, Severity } from './types.js';
import { getAllSecurityRules, type SecurityRule } from './rules/custom-security-rules.js';
import { ScanOrchestrator } from './orchestrator/scanner.js';
import { SemgrepAdapter } from './adapters/semgrep.js';
import { TruffleHogAdapter } from './adapters/truffleHog.js';
import { HardcodedSecretsAnalyzer } from './analyzers/hardcoded-secrets.js';
import { MaliciousPackageScanner } from './analyzers/malicious-packages.js';
import { TechnicalDebtAnalyzer } from './analyzers/technical-debt.js';

const RULE_LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  javascript: ['js', 'jsx', 'mjs', 'cjs'],
  typescript: ['ts', 'tsx'],
  python: ['py'],
  java: ['java'],
  go: ['go'],
};

export interface MultiScanConfig extends ScanConfig {
  phases: {
    traditionalSAST: {
      enabled: boolean;
      semgrep: { permissive: boolean; maxTargetBytes: string };
      codeql: { highNoise: boolean; threads: number; ram: number };
    };
    aiEnhanced: {
      enabled: boolean;
      iterations: number;
      aiProvider: 'openai' | 'anthropic' | 'aws-q';
      customRules: boolean;
    };
    deepDive: {
      enabled: boolean;
      functionLevel: boolean;
      multiFileAnalysis: boolean;
      intentAnalysis: boolean;
    };
  };
}

export interface ScanPhaseResult {
  phase: string;
  duration: number;
  findings: Finding[];
  toolsUsed: string[];
  success: boolean;
  error?: string;
}

export class MultiScanOrchestrator {
  private version = '2.0.0';
  
  /**
   * Execute the complete 3-phase scanning strategy
   */
  async executeScan(config: MultiScanConfig): Promise<ScanResult> {
    const scanId = randomUUID();
    const startTime = Date.now();
    
    console.log('🛡️ Multi-Phase Security Scanner v2.0');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    
    const phaseResults: ScanPhaseResult[] = [];
    let allFindings: Finding[] = [];
    
    // Phase 1: Traditional SAST as First Filter
    if (config.phases.traditionalSAST.enabled) {
      const phase1Result = await this.executePhase1(config);
      phaseResults.push(phase1Result);
      allFindings.push(...phase1Result.findings);
    }
    
    // Phase 2: AI-Enhanced Analysis
    if (config.phases.aiEnhanced.enabled) {
      const phase2Result = await this.executePhase2(config, allFindings);
      phaseResults.push(phase2Result);
      allFindings.push(...phase2Result.findings);
    }
    
    // Phase 3: Targeted Deep Dives
    if (config.phases.deepDive.enabled) {
      const phase3Result = await this.executePhase3(config, allFindings);
      phaseResults.push(phase3Result);
      allFindings.push(...phase3Result.findings);
    }
    
    // Merge and deduplicate results
    const uniqueFindings = this.deduplicateFindings(allFindings);
    
    // Apply severity-based filtering
    const filteredFindings = this.applySeverityFiltering(uniqueFindings, config);
    
    const duration = (Date.now() - startTime) / 1000;
    
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`✅ Scan complete: ${filteredFindings.length} findings in ${duration.toFixed(2)}s`);
    
    return {
      scanId,
      version: this.version,
      startedAt: new Date(startTime).toISOString(),
      completedAt: new Date().toISOString(),
      duration,
      target: config.scan.target,
      filesScanned: 0, // TODO: Implement file counting
      linesOfCode: 0, // TODO: Implement LOC counting
      toolsRun: this.extractToolsRun(phaseResults),
      findings: filteredFindings,
      suppressed: [],
      stats: this.calculateStats(filteredFindings),
      performance: {
        parallelWorkers: config.performance.parallelWorkers,
        cacheHitRate: 0,
        incrementalScan: config.performance.incrementalScan,
      },
    };
  }
  
  /**
   * Phase 1: Traditional SAST as First Filter
   * Purpose: Identify potential sources, sinks, and risky patterns
   */
  private async executePhase1(config: MultiScanConfig): Promise<ScanPhaseResult> {
    console.log('📊 Phase 1: Traditional SAST Analysis');
    const startTime = Date.now();
    const findings: Finding[] = [];
    const toolsUsed: string[] = [];
    const toolErrors: string[] = [];

    // Semgrep, TruffleHog, and the restored static analyzers (hardcoded
    // secrets, malicious packages, technical debt) all implement the same
    // ScannerAdapter interface, so they run through the shared
    // ScanOrchestrator instead of each having their own duplicated
    // spawn/parse logic. ScanOrchestrator already records a per-tool
    // exitCode/error in toolsRun rather than swallowing failures, so a
    // crashed or missing tool is visible here instead of silently looking
    // like "zero findings."
    console.log('  🔍 Running Semgrep, TruffleHog, and static analyzers...');
    const adapterOrchestrator = new ScanOrchestrator([
      new SemgrepAdapter(),
      new TruffleHogAdapter(),
      new HardcodedSecretsAnalyzer(),
      new MaliciousPackageScanner(),
      new TechnicalDebtAnalyzer(),
    ]);
    const adapterResult = await adapterOrchestrator.scan(config);
    findings.push(...adapterResult.findings);
    for (const tool of adapterResult.toolsRun) {
      toolsUsed.push(tool.name);
      if (tool.exitCode !== 0) {
        toolErrors.push(`${tool.name}: ${tool.error || `exited ${tool.exitCode}`}`);
      }
    }

    // CodeQL needs a full database build + query run per scan, so it doesn't
    // fit the lightweight ScannerAdapter pattern above. CI already runs it
    // via github/codeql-action in enhanced-security-scan.yml; this direct
    // CLI invocation is for local/library use when the codeql CLI is present.
    console.log('  🧠 Running CodeQL with high-noise queries...');
    try {
      const codeqlFindings = await this.runCodeQLHighNoise(config);
      findings.push(...codeqlFindings);
      toolsUsed.push('codeql');
    } catch (error) {
      toolErrors.push(`codeql: ${error instanceof Error ? error.message : String(error)}`);
    }

    const duration = (Date.now() - startTime) / 1000;
    console.log(`  ✅ Phase 1 complete: ${findings.length} potential issues found (${duration.toFixed(2)}s)`);

    if (toolErrors.length > 0) {
      return {
        phase: 'Traditional SAST',
        duration,
        findings,
        toolsUsed,
        success: false,
        error: toolErrors.join('; '),
      };
    }

    return {
      phase: 'Traditional SAST',
      duration,
      findings,
      toolsUsed,
      success: true,
    };
  }

  
  /**
   * Phase 2: AI-Enhanced Analysis with Multi-Scan Strategy
   * Purpose: Validate findings and discover complex multi-file vulnerabilities
   */
  private async executePhase2(config: MultiScanConfig, phase1Findings: Finding[]): Promise<ScanPhaseResult> {
    console.log('🤖 Phase 2: AI-Enhanced Analysis');
    const startTime = Date.now();
    const findings: Finding[] = [];
    const toolsUsed: string[] = [];
    
    try {
      // Run multiple iterations to embrace non-determinism
      for (let i = 1; i <= config.phases.aiEnhanced.iterations; i++) {
        console.log(`  🔄 AI Analysis iteration ${i}/${config.phases.aiEnhanced.iterations}`);
        
        // Apply custom natural language rules
        if (config.phases.aiEnhanced.customRules) {
          const customRuleFindings = await this.applyCustomNaturalLanguageRules(config, phase1Findings);
          findings.push(...customRuleFindings);
          toolsUsed.push('custom-rules');
        }
        
        // AI validation of findings
        const aiValidatedFindings = await this.aiValidateFindings(phase1Findings, config);
        findings.push(...aiValidatedFindings);
        toolsUsed.push(config.phases.aiEnhanced.aiProvider);
      }
      
      const duration = (Date.now() - startTime) / 1000;
      console.log(`  ✅ Phase 2 complete: ${findings.length} AI-validated issues found (${duration.toFixed(2)}s)`);
      
      return {
        phase: 'AI-Enhanced Analysis',
        duration,
        findings,
        toolsUsed,
        success: true,
      };
    } catch (error) {
      return {
        phase: 'AI-Enhanced Analysis',
        duration: (Date.now() - startTime) / 1000,
        findings: [],
        toolsUsed,
        success: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
  
  /**
   * Phase 3: Targeted Deep Dives
   * Purpose: Investigate complex issues and validate findings
   */
  private async executePhase3(config: MultiScanConfig, allFindings: Finding[]): Promise<ScanPhaseResult> {
    console.log('🔍 Phase 3: Targeted Deep Dive Analysis');
    const startTime = Date.now();
    const findings: Finding[] = [];
    const toolsUsed: string[] = [];
    
    try {
      // Focus on critical findings for deep analysis
      const criticalFindings = allFindings.filter(f => f.severity === 'CRITICAL');
      
      for (const finding of criticalFindings.slice(0, 10)) { // Limit to top 10 for performance
        console.log(`  🔬 Deep dive: ${finding.title}`);
        
        // Function-by-function analysis
        if (config.phases.deepDive.functionLevel) {
          const functionAnalysis = await this.analyzeFunctionLevel(finding, config);
          findings.push(...functionAnalysis);
          toolsUsed.push('function-analysis');
        }
        
        // Multi-file flow analysis
        if (config.phases.deepDive.multiFileAnalysis) {
          const flowAnalysis = await this.analyzeMultiFileFlow(finding, config);
          findings.push(...flowAnalysis);
          toolsUsed.push('flow-analysis');
        }
        
        // Intent vs implementation analysis
        if (config.phases.deepDive.intentAnalysis) {
          const intentAnalysis = await this.analyzeIntentVsImplementation(finding, config);
          if (intentAnalysis) {
            findings.push(intentAnalysis);
            toolsUsed.push('intent-analysis');
          }
        }
      }
      
      const duration = (Date.now() - startTime) / 1000;
      console.log(`  ✅ Phase 3 complete: ${findings.length} deep analysis issues found (${duration.toFixed(2)}s)`);
      
      return {
        phase: 'Targeted Deep Dive',
        duration,
        findings,
        toolsUsed,
        success: true,
      };
    } catch (error) {
      return {
        phase: 'Targeted Deep Dive',
        duration: (Date.now() - startTime) / 1000,
        findings: [],
        toolsUsed,
        success: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
  
  /**
   * Run CodeQL with high-noise queries
   */
  private async runCodeQLHighNoise(config: MultiScanConfig): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    const codeqlConfig = config.phases.traditionalSAST.codeql;
    // Scan-id-scoped temp dir: fixed /tmp paths meant concurrent scans raced
    // and mixed different targets' CodeQL databases/results together.
    const workDir = path.join(os.tmpdir(), `codeql-${randomUUID()}`);
    const dbPath = path.join(workDir, 'db');
    const resultsPath = path.join(workDir, 'results.sarif');
    await fs.mkdir(workDir, { recursive: true });

    try {
      // Create CodeQL database
      await this.executeCommand('codeql', [
        'database', 'create',
        dbPath,
        '--language=javascript',
        '--source-root', config.scan.target
      ]);

      // Analyze with high-noise queries
      await this.executeCommand('codeql', [
        'database', 'analyze',
        dbPath,
        '--format=sarif-latest',
        `--output=${resultsPath}`,
        `--threads=${codeqlConfig.threads}`,
        `--ram=${codeqlConfig.ram}`
      ]);

      // Parse SARIF results
      const sarifResults = JSON.parse(await fs.readFile(resultsPath, 'utf8'));

      for (const run of sarifResults.runs || []) {
        for (const result of run.results || []) {
          const location = result.locations?.[0]?.physicalLocation;
          if (location) {
            findings.push({
              id: randomUUID(),
              ruleId: result.ruleId,
              source: 'codeql',
              severity: this.mapCodeQLSeverity(result.level),
              category: this.mapCodeQLCategory(result.ruleId),
              file: location.artifactLocation.uri,
              line: location.region.startLine,
              column: location.region.startColumn,
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
      }
    } finally {
      // Don't swallow failures here — the caller (executePhase1) needs to
      // know CodeQL actually failed instead of silently getting zero
      // findings that look like a clean scan. Always clean up the scoped
      // temp dir regardless of outcome.
      await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    }

    return findings;
  }
  
  /**
   * Apply custom natural language rules
   */
  private async applyCustomNaturalLanguageRules(config: MultiScanConfig, existingFindings: Finding[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    const rules = getAllSecurityRules();
    
    // Apply pattern-based rules
    for (const rule of rules) {
      const ruleFindings = await this.applySecurityRule(rule, config);
      findings.push(...ruleFindings);
    }
    
    return findings;
  }
  
  /**
   * AI validation of findings using the configured provider.
   *
   * Only 'anthropic' is actually wired up (via a direct HTTPS call to the
   * Messages API — no new SDK dependency). 'openai'/'aws-q' are explicitly
   * not implemented; they log and no-op rather than silently mislabeling
   * findings as AI-validated the way this method previously did
   * unconditionally for every CRITICAL/HIGH finding without calling anyone.
   */
  private async aiValidateFindings(findings: Finding[], config: MultiScanConfig): Promise<Finding[]> {
    const candidates = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
    if (candidates.length === 0) {
      return [];
    }

    const provider = config.phases.aiEnhanced.aiProvider;
    if (provider !== 'anthropic') {
      console.warn(`  ⚠️  AI validation skipped: provider '${provider}' is not implemented (only 'anthropic' is wired up)`);
      return [];
    }

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      console.warn('  ⚠️  AI validation skipped: ANTHROPIC_API_KEY is not set');
      return [];
    }

    const validatedFindings: Finding[] = [];
    for (const finding of candidates) {
      try {
        const result = await this.callAnthropicValidation(finding, apiKey);
        if (result?.isValid) {
          validatedFindings.push({
            ...finding,
            confidence: typeof result.confidence === 'number'
              ? Math.max(0, Math.min(1, result.confidence))
              : finding.confidence,
            description: result.enhancedDescription || finding.description,
            remediation: {
              ...finding.remediation,
              summary: result.remediation || finding.remediation.summary,
            },
          });
        }
        // isValid === false means the model assessed it as a likely false
        // positive — drop it rather than keep an unvalidated copy.
      } catch (error) {
        console.warn(
          `  ⚠️  AI validation call failed for ${finding.file}:${finding.line}:`,
          error instanceof Error ? error.message : error
        );
        // Keep the original, unenhanced finding on a provider error rather
        // than silently dropping it or fabricating a validated status.
        validatedFindings.push(finding);
      }
    }

    return validatedFindings;
  }

  private async callAnthropicValidation(finding: Finding, apiKey: string): Promise<{
    isValid: boolean;
    confidence?: number;
    enhancedDescription?: string;
    remediation?: string;
  } | null> {
    const prompt = [
      'Analyze this security finding for validity. Respond with ONLY a JSON object',
      '(no markdown fences, no prose) matching exactly:',
      '{"isValid": boolean, "confidence": number between 0 and 1, "enhancedDescription": string, "remediation": string}',
      '',
      'FINDING:',
      `- Type: ${finding.category}`,
      `- Severity: ${finding.severity}`,
      `- File: ${finding.file}:${finding.line}`,
      `- Description: ${finding.description}`,
      `- Code: ${finding.snippet}`,
    ].join('\n');

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 512,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!response.ok) {
      throw new Error(`Anthropic API returned ${response.status}: ${(await response.text()).slice(0, 300)}`);
    }

    const data: any = await response.json();
    const text: string = data.content?.[0]?.text || '';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('Could not find a JSON object in the AI response');
    }

    return JSON.parse(jsonMatch[0]);
  }
  
  // Helper methods
  private async executeCommand(command: string, args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const process = spawn(command, args);
      
      process.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with exit code ${code}`));
        }
      });
      
      process.on('error', reject);
    });
  }
  
  private async applySecurityRule(rule: SecurityRule, config: MultiScanConfig): Promise<Finding[]> {
    const extensions = rule.languages.flatMap((lang) => RULE_LANGUAGE_EXTENSIONS[lang] || []);
    if (extensions.length === 0) {
      return [];
    }

    const { glob } = await import('glob');
    const files = await glob(`**/*.{${extensions.join(',')}}`, {
      cwd: config.scan.target,
      absolute: true,
      ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/*.min.js'],
    });

    const findings: Finding[] = [];

    for (const file of files) {
      let content: string;
      try {
        content = await fs.readFile(file, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const matchedPattern = rule.patterns.find((pattern) => pattern.test(line));
        if (!matchedPattern) {
          continue;
        }
        if (rule.customLogic && !rule.customLogic(line, { file, lineNumber: i + 1 })) {
          continue;
        }

        findings.push({
          id: randomUUID(),
          ruleId: rule.id,
          source: 'custom-rules',
          severity: rule.severity,
          category: this.mapSemgrepCategory(rule.id),
          cwe: rule.cwe,
          file,
          line: i + 1,
          title: rule.name,
          description: rule.description,
          snippet: line.trim().slice(0, 300),
          remediation: {
            summary: `Review and address: ${rule.description}`,
            references: rule.cwe
              ? [`https://cwe.mitre.org/data/definitions/${rule.cwe.replace('CWE-', '')}.html`]
              : [],
            effort: 'medium',
          },
          confidence: 0.7,
          detectedAt: new Date().toISOString(),
        });
      }
    }

    return findings;
  }
  
  // Phase 3's three deep-dive methods below are deliberately NOT implemented,
  // not silently stubbed. Each requires real static-analysis infrastructure
  // (an AST-level control-flow engine, cross-file taint tracking, and a
  // second AI pass comparing comments/specs against implementation,
  // respectively) that would need its own scoped design — faking a shallow
  // version would produce findings that look analyzed but aren't, which is
  // worse than the current honest no-op. Phase 1 (real Semgrep/CodeQL/
  // TruffleHog/custom-rule findings) and Phase 2 (real AI validation) are
  // the implemented, load-bearing phases; Phase 3 remains future scope.

  private async analyzeFunctionLevel(finding: Finding, config: MultiScanConfig): Promise<Finding[]> {
    return [];
  }

  private async analyzeMultiFileFlow(finding: Finding, config: MultiScanConfig): Promise<Finding[]> {
    return [];
  }

  private async analyzeIntentVsImplementation(finding: Finding, config: MultiScanConfig): Promise<Finding | null> {
    return null;
  }
  
  private deduplicateFindings(findings: Finding[]): Finding[] {
    const seen = new Map<string, Finding>();
    
    for (const finding of findings) {
      const key = `${finding.file}:${finding.line}:${finding.ruleId}`;
      
      if (!seen.has(key)) {
        seen.set(key, finding);
      } else {
        const existing = seen.get(key)!;
        if (finding.confidence > existing.confidence) {
          seen.set(key, finding);
        }
      }
    }
    
    return Array.from(seen.values());
  }
  
  private applySeverityFiltering(findings: Finding[], config: MultiScanConfig): Finding[] {
    const threshold = config.severity.threshold;
    const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const thresholdIndex = severityOrder.indexOf(threshold);
    
    return findings.filter(finding => {
      const findingIndex = severityOrder.indexOf(finding.severity);
      return findingIndex <= thresholdIndex;
    });
  }
  
  private extractToolsRun(phaseResults: ScanPhaseResult[]): ScanResult['toolsRun'] {
    return phaseResults.flatMap(phase => 
      phase.toolsUsed.map(tool => ({
        name: tool,
        version: 'unknown',
        duration: phase.duration,
        exitCode: phase.success ? 0 : 1,
        error: phase.error,
      }))
    );
  }
  
  private calculateStats(findings: Finding[]): ScanResult['stats'] {
    const bySeverity: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    
    const byCategory: Record<any, number> = {
      secrets: 0,
      injection: 0,
      auth: 0,
      crypto: 0,
      dependency: 0,
      other: 0,
    };
    
    const bySource: Record<any, number> = {
      truffleHog: 0,
      semgrep: 0,
      codeql: 0,
      'custom-npm': 0,
      'custom-react': 0,
      'custom-secrets': 0,
      'custom-rules': 0,
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
  
  private mapSemgrepSeverity(severity: string): Severity {
    switch (severity?.toLowerCase()) {
      case 'error': return 'CRITICAL';
      case 'warning': return 'HIGH';
      case 'info': return 'MEDIUM';
      default: return 'LOW';
    }
  }
  
  private mapCodeQLSeverity(level: string): Severity {
    switch (level?.toLowerCase()) {
      case 'error': return 'CRITICAL';
      case 'warning': return 'HIGH';
      case 'note': return 'MEDIUM';
      default: return 'LOW';
    }
  }
  
  private mapSemgrepCategory(checkId: string): any {
    if (checkId.includes('secret')) return 'secrets';
    if (checkId.includes('injection')) return 'injection';
    if (checkId.includes('auth')) return 'auth';
    if (checkId.includes('crypto')) return 'crypto';
    return 'other';
  }
  
  private mapCodeQLCategory(ruleId: string): any {
    if (ruleId.includes('secret')) return 'secrets';
    if (ruleId.includes('injection')) return 'injection';
    if (ruleId.includes('auth')) return 'auth';
    if (ruleId.includes('crypto')) return 'crypto';
    return 'other';
  }
}