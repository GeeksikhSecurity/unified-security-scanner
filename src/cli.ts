#!/usr/bin/env node
/**
 * Self-scan CLI entry point. Wired into `npm run scan:self` and invoked from
 * CI (.github/workflows/ci.yml, "security" job) — replaces what used to be
 * `echo '{}' > reports/results.sarif`, a placeholder that never actually
 * invoked a scanner.
 *
 * Usage: scan-self [target-dir] [output-dir]
 */
import { promises as fs } from 'fs';
import path from 'path';
import { MultiScanOrchestrator, type MultiScanConfig } from './multi-scan-orchestrator.js';
import { SARIFProcessor } from './sarif-processor.js';

async function main(): Promise<void> {
  const target = process.argv[2] || '.';
  const outputDir = process.argv[3] || 'reports';

  const config: MultiScanConfig = {
    version: '1.0',
    tools: {
      truffleHog: { enabled: true, exclude: ['node_modules', 'dist', '.git'] },
      semgrep: { enabled: true, rules: [] },
      customScanners: { enabled: true, modules: [] },
    },
    scan: {
      target: path.resolve(target),
      exclude: ['node_modules', 'dist', '.git'],
      includeTests: false,
      maxFileSize: 5_000_000,
      maxDepth: 50,
      followSymlinks: false,
    },
    falsePositives: {
      patterns: [],
      excludeTestFiles: true,
      excludeStorybook: true,
      excludeDocumentation: true,
      excludeScannerRules: true,
    },
    output: {
      formats: ['json', 'sarif'],
      dir: outputDir,
      verbose: true,
      quiet: false,
    },
    severity: {
      threshold: 'LOW',
      failOn: ['CRITICAL', 'HIGH'],
    },
    performance: {
      parallelWorkers: 4,
      cacheEnabled: false,
      incrementalScan: false,
    },
    phases: {
      traditionalSAST: {
        enabled: true,
        semgrep: { permissive: true, maxTargetBytes: '2MB' },
        codeql: { highNoise: true, threads: 4, ram: 4096 },
      },
      aiEnhanced: {
        // Only runs if ANTHROPIC_API_KEY is set — see
        // MultiScanOrchestrator.aiValidateFindings, which warns and no-ops
        // rather than silently faking validation when it isn't.
        enabled: true,
        iterations: 1,
        aiProvider: 'anthropic',
        customRules: true,
      },
      deepDive: {
        // Phase 3 is intentionally unimplemented (see the doc comment above
        // its methods in multi-scan-orchestrator.ts) — leave it off rather
        // than pay for a no-op pass.
        enabled: false,
        functionLevel: false,
        multiFileAnalysis: false,
        intentAnalysis: false,
      },
    },
  };

  await fs.mkdir(outputDir, { recursive: true });

  const orchestrator = new MultiScanOrchestrator();
  const result = await orchestrator.executeScan(config);

  await fs.writeFile(path.join(outputDir, 'results.json'), JSON.stringify(result, null, 2));

  const sarif = SARIFProcessor.generateSARIF(result, config.scan.target);
  await fs.writeFile(path.join(outputDir, 'results.sarif'), JSON.stringify(sarif, null, 2));

  const { CRITICAL, HIGH, MEDIUM, LOW } = result.stats.bySeverity;
  console.log(
    `\nScan complete: ${result.stats.total} findings ` +
      `(${CRITICAL} critical, ${HIGH} high, ${MEDIUM} medium, ${LOW} low)`
  );
  console.log(`Reports written to ${outputDir}/results.json and ${outputDir}/results.sarif`);

  // A tool crashing must not be indistinguishable from "ran clean, found
  // nothing" — executePhase1 records a nonzero exitCode per failed tool
  // instead of swallowing it. But exitCode -1 means "not installed in this
  // environment" (see MultiScanOrchestrator's ToolOutcome.available), which
  // is an environment/config fact, not a scanner bug — some CI jobs
  // legitimately never install Semgrep/TruffleHog/CodeQL before calling
  // this script. Only an actual crash (exitCode 1, a tool that WAS present
  // and failed while running) should fail the build.
  const unavailableTools = result.toolsRun.filter((t) => t.exitCode === -1);
  const crashedTools = result.toolsRun.filter((t) => t.exitCode !== 0 && t.exitCode !== -1);
  if (unavailableTools.length > 0) {
    console.warn(`\nℹ️  ${unavailableTools.length} tool(s) not available in this environment: ${unavailableTools.map((t) => t.name).join(', ')}`);
  }
  if (crashedTools.length > 0) {
    console.warn(
      `\n⚠️  ${crashedTools.length} tool(s) crashed while running: ` +
        crashedTools.map((t) => `${t.name} (${t.error || `exit ${t.exitCode}`})`).join(', ')
    );
  }

  if (CRITICAL > 0 || HIGH > 0 || crashedTools.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error('Self-scan failed:', error);
  process.exitCode = 1;
});
