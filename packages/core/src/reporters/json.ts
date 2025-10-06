/**
 * JSON reporter for CI/CD pipeline integration
 */

import { writeFile } from 'fs/promises';
import type { Reporter, ScanResult } from '../types.js';

export class JsonReporter implements Reporter {
  name = 'json';

  async generate(result: ScanResult): Promise<string> {
    return JSON.stringify(result, null, 2);
  }

  async write(content: string, outputPath: string): Promise<void> {
    await writeFile(outputPath, content, 'utf-8');
  }
}
