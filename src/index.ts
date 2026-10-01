/**
 * Enhanced Security Scanner v2.0
 * AI-powered multi-phase security analysis
 */

// MultiScanOrchestrator is the maintained scanning engine — see the
// deprecation note on EnhancedSecurityScanner for why.
export { EnhancedSecurityScanner } from './enhanced-scanner.js';
export { MultiScanOrchestrator } from './multi-scan-orchestrator.js';
export { SARIFProcessor } from './sarif-processor.js';
export { FlakyTestManager } from './test-reliability/flaky-test-manager.js';

// Previously restored but unreachable from the package — each exists as a
// real, working ScannerAdapter but had no export, so nothing outside this
// package could construct or use them directly.
export { ScanOrchestrator } from './orchestrator/scanner.js';
export { SemgrepAdapter } from './adapters/semgrep.js';
export { TruffleHogAdapter } from './adapters/truffleHog.js';
export { HardcodedSecretsAnalyzer } from './analyzers/hardcoded-secrets.js';
export { MaliciousPackageScanner } from './analyzers/malicious-packages.js';
export { TechnicalDebtAnalyzer } from './analyzers/technical-debt.js';
export { FalsePositiveRuleEngine } from './fp-reducer/rule-engine.js';
export * from './rules/custom-security-rules.js';
export * from './reporters/json.js';
export * from './reporters/sarif.js';

export * from './types.js';

console.log('🛡️ Enhanced Security Scanner v2.0 - Ready for development');