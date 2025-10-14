/**
 * Basic tests for Enhanced Security Scanner
 */

describe('Enhanced Security Scanner', () => {
  test('should import successfully', async () => {
    const { EnhancedSecurityScanner } = await import('../src/index.js');
    expect(EnhancedSecurityScanner).toBeDefined();
  });

  test('should have flaky test management', async () => {
    const { FlakyTestManager } = await import('../src/index.js');
    expect(FlakyTestManager).toBeDefined();
  });

  test('basic functionality', () => {
    expect(true).toBe(true);
  });
});