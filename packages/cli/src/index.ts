#!/usr/bin/env node

/**
 * Unified Security Scanner CLI
 */

import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function getVersion(): Promise<string> {
  try {
    const pkgPath = join(__dirname, '../package.json');
    const pkg = JSON.parse(await readFile(pkgPath, 'utf-8'));
    return pkg.version || '1.0.0';
  } catch {
    return '1.0.0';
  }
}

async function main() {
  const version = await getVersion();

  const program = new Command();

  program
    .name('unified-scanner')
    .description('Unified security scanning platform for npm/React projects')
    .version(version);

  program
    .command('scan')
    .description('Scan a project for security vulnerabilities')
    .argument('[target]', 'Target directory to scan', '.')
    .option('-c, --config <path>', 'Path to configuration file')
    .option('-f, --format <format>', 'Output format (terminal, json, sarif, html)', 'terminal')
    .option('-o, --output <path>', 'Output directory for reports', './reports')
    .option('--fail-on <severity>', 'Fail on severity level (critical, high, medium, low)', 'critical,high')
    .option('--no-cache', 'Disable caching')
    .option('--verbose', 'Enable verbose output')
    .option('--quiet', 'Suppress output except errors')
    .action(scanCommand);

  await program.parseAsync(process.argv);
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
