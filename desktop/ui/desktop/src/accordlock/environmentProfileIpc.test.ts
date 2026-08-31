import { describe, expect, it } from 'vitest';

import {
  deploymentPreflightHistoryExportInputSchema,
  deploymentPreflightHistoryListInputSchema,
} from './environmentProfileIpc';

const environmentId = '11111111-1111-4111-8111-111111111111';
const receiptHash = `sha256:${'a'.repeat(64)}`;

describe('deployment preflight history IPC', () => {
  it('accepts only bounded list selectors', () => {
    expect(
      deploymentPreflightHistoryListInputSchema.parse({
        schemaVersion: 1,
        environmentId,
        limit: 50,
      })
    ).toEqual({ schemaVersion: 1, environmentId, limit: 50 });
    expect(() =>
      deploymentPreflightHistoryListInputSchema.parse({
        schemaVersion: 1,
        environmentId,
        limit: 101,
      })
    ).toThrow();
    expect(() =>
      deploymentPreflightHistoryListInputSchema.parse({
        schemaVersion: 1,
        environmentId,
        limit: 50,
        path: 'C:\\secrets',
      })
    ).toThrow();
  });

  it('exports by canonical receipt hash without accepting a path', () => {
    expect(
      deploymentPreflightHistoryExportInputSchema.parse({ schemaVersion: 1, receiptHash })
    ).toEqual({ schemaVersion: 1, receiptHash });
    expect(() =>
      deploymentPreflightHistoryExportInputSchema.parse({
        schemaVersion: 1,
        receiptHash,
        outputPath: 'C:\\receipt.json',
      })
    ).toThrow();
  });
});
