/**
 * Tests for flaky test management functionality
 */

import { FlakyTestManager, TestResult, FlakyTestConfig } from '../src/test-reliability/flaky-test-manager';

describe('FlakyTestManager', () => {
  let manager: FlakyTestManager;
  let config: FlakyTestConfig;

  beforeEach(() => {
    config = {
      detection: {
        enabled: true,
        intraRunThreshold: 0.1,
        interRunThreshold: 0.2,
        monitoringWindow: 7
      },
      quarantine: {
        enabled: true,
        autoQuarantine: true,
        maxQuarantineDays: 30
      },
      retry: {
        enabled: true,
        maxRetries: 2,
        backoffMs: 100,
        selectiveRetry: true
      }
    };
    manager = new FlakyTestManager(config);
  });

  test('should execute non-quarantined test', () => {
    expect(manager.shouldExecuteTest('security-scan')).toBe(true);
  });

  test('should quarantine flaky test', () => {
    manager.quarantineTest('flaky-test');
    expect(manager.shouldExecuteTest('flaky-test')).toBe(false);
  });

  test('should retry failed test with backoff', async () => {
    let attempts = 0;
    const testFn = async (): Promise<TestResult> => {
      attempts++;
      if (attempts < 3) {
        throw new Error('Test failed');
      }
      return {
        id: 'test-1',
        name: 'retry-test',
        status: 'pass',
        duration: 100,
        timestamp: new Date().toISOString(),
        buildId: 'build-1',
        environment: 'test'
      };
    };

    const result = await manager.executeWithRetry(testFn);
    expect(result.status).toBe('pass');
    expect(attempts).toBe(3);
  });

  test('should detect flaky test from mixed results', () => {
    const testHistory = new Map();
    const mixedResults: TestResult[] = [];
    
    // Create mixed pass/fail results
    for (let i = 0; i < 10; i++) {
      mixedResults.push({
        id: `test-${i}`,
        name: 'mixed-test',
        status: i % 2 === 0 ? 'pass' : 'fail',
        duration: 100,
        timestamp: new Date().toISOString(),
        buildId: `build-${i}`,
        environment: 'test'
      });
    }
    
    testHistory.set('mixed-test', mixedResults);
    (manager as any).testHistory = testHistory;
    
    const flakyTests = manager.detectFlakyTests([]);
    expect(flakyTests).toContain('mixed-test');
  });
});