/**
 * Flaky Test Management for Security Scanner
 * Ensures reliable security test execution and reduces false negatives
 */

export interface FlakyTestConfig {
  detection: {
    enabled: boolean;
    intraRunThreshold: number;
    interRunThreshold: number;
    monitoringWindow: number;
  };
  quarantine: {
    enabled: boolean;
    autoQuarantine: boolean;
    maxQuarantineDays: number;
  };
  retry: {
    enabled: boolean;
    maxRetries: number;
    backoffMs: number;
    selectiveRetry: boolean;
  };
}

export interface TestResult {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'flaky';
  duration: number;
  timestamp: string;
  buildId: string;
  environment: string;
}

export class FlakyTestManager {
  private config: FlakyTestConfig;
  private testHistory: Map<string, TestResult[]> = new Map();
  private quarantinedTests: Set<string> = new Set();

  constructor(config: FlakyTestConfig) {
    this.config = config;
  }

  detectFlakyTests(testResults: TestResult[]): string[] {
    const flakyTests: string[] = [];

    for (const [testName, history] of this.testHistory) {
      if (this.isTestFlaky(history)) {
        flakyTests.push(testName);
        
        if (this.config.quarantine.autoQuarantine) {
          this.quarantineTest(testName);
        }
      }
    }

    return flakyTests;
  }

  async executeWithRetry(testFn: () => Promise<TestResult>): Promise<TestResult> {
    let lastResult: TestResult;
    
    for (let attempt = 1; attempt <= this.config.retry.maxRetries + 1; attempt++) {
      try {
        lastResult = await testFn();
        
        if (lastResult.status === 'pass') {
          return lastResult;
        }
        
        if (attempt <= this.config.retry.maxRetries) {
          await this.delay(this.config.retry.backoffMs * attempt);
        }
      } catch (error) {
        if (attempt > this.config.retry.maxRetries) {
          throw error;
        }
        await this.delay(this.config.retry.backoffMs * attempt);
      }
    }
    
    return lastResult!;
  }

  quarantineTest(testName: string): void {
    this.quarantinedTests.add(testName);
    console.warn(`⚠️ Test quarantined: ${testName}`);
  }

  shouldExecuteTest(testName: string): boolean {
    return !this.quarantinedTests.has(testName);
  }

  private isTestFlaky(history: TestResult[]): boolean {
    if (history.length < 5) return false;

    const recent = history.slice(-10);
    const passCount = recent.filter(r => r.status === 'pass').length;
    const failCount = recent.filter(r => r.status === 'fail').length;
    
    const flakyRatio = Math.min(passCount, failCount) / recent.length;
    return flakyRatio >= 0.2;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}