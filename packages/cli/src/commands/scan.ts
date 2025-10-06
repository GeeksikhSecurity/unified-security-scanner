/**
 * Scan command implementation
 */

import { readFile, mkdir } from 'fs/promises';
import { join, resolve } from 'path';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import {
  ScanOrchestrator,
  TruffleHogAdapter,
  SemgrepAdapter,
  MaliciousPackageScanner,
  TechnicalDebtAnalyzer,
  FalsePositiveRuleEngine,
  SarifReporter,
  JsonReporter,
  type ScanConfig,
  type ScanResult,
} from '@unified-scanner/core';

interface ScanOptions {
  config?: string;
  format: string;
  output: string;
  failOn: string;
  cache: boolean;
  verbose: boolean;
  quiet: boolean;
}

const DEFAULT_CONFIG: ScanConfig = {
  version: '1.0',
  tools: {
    truffleHog: {
      enabled: true,
    },
    semgrep: {
      enabled: true,
      rules: [],
    },
    customScanners: {
      enabled: true,
      modules: [],
    },
  },
  scan: {
    target: '.',
    exclude: [],
    includeTests: false,
    maxFileSize: 10485760, // 10MB
    maxDepth: 50,
    followSymlinks: false,
  },
  falsePositives: {
    patterns: [],
    excludeTestFiles: true,
    excludeStorybook: true,
  },
  output: {
    formats: ['terminal'],
    dir: './reports',
    verbose: false,
    quiet: false,
  },
  severity: {
    threshold: 'LOW',
    failOn: ['CRITICAL', 'HIGH'],
  },
  performance: {
    parallelWorkers: 4,
    cacheEnabled: true,
    incrementalScan: false,
  },
};

export async function scanCommand(target: string, options: ScanOptions) {
  const spinner = ora('Initializing security scan...').start();

  try {
    // Load configuration
    const config = await loadConfig(target, options);

    // Initialize scanners
    const adapters = [
      new TruffleHogAdapter(),
      new SemgrepAdapter(),
      new MaliciousPackageScanner(),
      new TechnicalDebtAnalyzer(),
    ];

    const orchestrator = new ScanOrchestrator(adapters);

    spinner.text = 'Scanning for vulnerabilities...';

    // Run scan
    const rawResult = await orchestrator.scan(config);

    spinner.text = 'Filtering false positives...';

    // Apply false positive reduction
    const fpEngine = new FalsePositiveRuleEngine(config);
    const { findings, suppressed } = await fpEngine.filterFindings(
      rawResult.findings,
      config
    );

    const result: ScanResult = {
      ...rawResult,
      findings,
      suppressed,
    };

    spinner.succeed(
      `Scan completed in ${result.duration.toFixed(2)}s - Found ${findings.length} issues`
    );

    // Display results
    if (!options.quiet) {
      displayResults(result);
    }

    // Generate reports
    await generateReports(result, options);

    // Check if should fail
    const shouldFail = checkFailCondition(result, options.failOn);
    if (shouldFail) {
      console.error(
        chalk.red(
          `\n❌ Scan failed: Found issues matching fail-on criteria (${options.failOn})`
        )
      );
      process.exit(1);
    }

    console.log(chalk.green('\n✅ Security scan passed'));
  } catch (error) {
    spinner.fail('Scan failed');
    console.error(chalk.red(error instanceof Error ? error.message : String(error)));
    process.exit(1);
  }
}

async function loadConfig(target: string, options: ScanOptions): Promise<ScanConfig> {
  let config = { ...DEFAULT_CONFIG };

  // Load from file if specified
  if (options.config) {
    try {
      const configFile = await readFile(options.config, 'utf-8');
      const fileConfig = JSON.parse(configFile);
      config = { ...config, ...fileConfig };
    } catch (error) {
      throw new Error(`Failed to load config from ${options.config}: ${error}`);
    }
  }

  // Override with CLI options
  config.scan.target = resolve(target);
  config.output.dir = resolve(options.output);
  config.output.verbose = options.verbose;
  config.output.quiet = options.quiet;
  config.performance.cacheEnabled = options.cache;

  // Parse fail-on option
  const failOnLevels = options.failOn.split(',').map((s) => s.trim().toUpperCase());
  config.severity.failOn = failOnLevels as any;

  return config;
}

function displayResults(result: ScanResult) {
  // Summary header
  console.log(
    chalk.bold(
      `\n┌─────────────────────────────────────────────────────────────┐`
    )
  );
  console.log(
    chalk.bold(
      `│  Unified Security Scanner v${result.version.padEnd(38)}│`
    )
  );
  console.log(
    chalk.bold(
      `│  Scanned: ${result.filesScanned} files (${result.linesOfCode} LOC) in ${result.duration.toFixed(1)}s`.padEnd(62) +
        '│'
    )
  );
  console.log(
    chalk.bold(
      `└─────────────────────────────────────────────────────────────┘`
    )
  );

  // Severity counts
  const { bySeverity } = result.stats;
  console.log(
    `  ${chalk.red.bold(`CRITICAL: ${bySeverity.CRITICAL}`)}  │  ` +
      `${chalk.yellow.bold(`HIGH: ${bySeverity.HIGH}`)}  │  ` +
      `${chalk.blue.bold(`MEDIUM: ${bySeverity.MEDIUM}`)}  │  ` +
      `${chalk.gray.bold(`LOW: ${bySeverity.LOW}`)}\n`
  );

  // Findings table
  if (result.findings.length > 0) {
    const table = new Table({
      head: ['Severity', 'Type', 'File', 'Line', 'Description'],
      style: { head: ['cyan'] },
      colWidths: [12, 15, 30, 8, 50],
      wordWrap: true,
    });

    for (const finding of result.findings.slice(0, 10)) {
      table.push([
        getSeverityIcon(finding.severity),
        finding.category,
        finding.file,
        finding.line.toString(),
        finding.title,
      ]);
    }

    console.log(table.toString());

    if (result.findings.length > 10) {
      console.log(
        chalk.gray(`\n... and ${result.findings.length - 10} more issues`)
      );
    }
  }

  // Suppressed findings
  if (result.suppressed.length > 0) {
    console.log(
      chalk.gray(
        `\nℹ️  Suppressed ${result.suppressed.length} potential false positives`
      )
    );
  }
}

function getSeverityIcon(severity: string): string {
  const icons: Record<string, string> = {
    CRITICAL: chalk.red('🔴 CRITICAL'),
    HIGH: chalk.yellow('🟠 HIGH'),
    MEDIUM: chalk.blue('🟡 MEDIUM'),
    LOW: chalk.gray('⚪ LOW'),
    INFO: chalk.gray('ℹ️  INFO'),
  };
  return icons[severity] || severity;
}

async function generateReports(result: ScanResult, options: ScanOptions) {
  await mkdir(options.output, { recursive: true });

  const formats = options.format.split(',');

  for (const format of formats) {
    switch (format.trim()) {
      case 'sarif': {
        const reporter = new SarifReporter();
        const content = await reporter.generate(result);
        const outputPath = join(options.output, 'results.sarif');
        await reporter.write(content, outputPath);
        console.log(chalk.gray(`SARIF report: ${outputPath}`));
        break;
      }

      case 'json': {
        const reporter = new JsonReporter();
        const content = await reporter.generate(result);
        const outputPath = join(options.output, 'results.json');
        await reporter.write(content, outputPath);
        console.log(chalk.gray(`JSON report: ${outputPath}`));
        break;
      }
    }
  }
}

function checkFailCondition(result: ScanResult, failOn: string): boolean {
  const failOnLevels = failOn.split(',').map((s) => s.trim().toUpperCase());

  for (const finding of result.findings) {
    if (failOnLevels.includes(finding.severity)) {
      return true;
    }
  }

  return false;
}
