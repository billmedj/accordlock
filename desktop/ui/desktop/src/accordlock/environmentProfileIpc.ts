import { z } from 'zod';
import type { AccordLockEnvironmentProfileSummary } from './environmentProfiles';
import type { DeploymentPreflightCiEnrollmentResult } from './deploymentPreflightCiEnrollmentController';

export const ACCORDLOCK_ENVIRONMENT_PROFILES_LIST = 'accordlock:environment-profiles:list';
export const ACCORDLOCK_ENVIRONMENT_PROFILES_SAVE = 'accordlock:environment-profiles:save';
export const ACCORDLOCK_ENVIRONMENT_PROFILES_REMOVE = 'accordlock:environment-profiles:remove';
export const ACCORDLOCK_DEPLOYMENT_PREFLIGHT_RUN = 'accordlock:deployment-preflight:run';
export const ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_LIST =
  'accordlock:deployment-preflight:history:list';
export const ACCORDLOCK_DEPLOYMENT_PREFLIGHT_HISTORY_EXPORT =
  'accordlock:deployment-preflight:history:export';
export const ACCORDLOCK_DEPLOYMENT_PREFLIGHT_CI_EVIDENCE_IMPORT =
  'accordlock:deployment-preflight:ci-evidence:import';

export const deploymentPreflightCiEvidenceImportInputSchema = z
  .object({ schemaVersion: z.literal(1), environmentId: z.string().uuid() })
  .strict();

export type AccordLockEnvironmentProfileView = AccordLockEnvironmentProfileSummary &
  Readonly<{
    ciTrust:
      | Readonly<{ status: 'UNENROLLED' }>
      | Readonly<{
          status: 'ENROLLED';
          buildAuthorityFingerprint: string;
          artifactAuthorityFingerprint: string;
        }>;
  }>;

export type DeploymentPreflightCiEvidenceImportResult = DeploymentPreflightCiEnrollmentResult;

export const deploymentPreflightHistoryListInputSchema = z
  .object({
    schemaVersion: z.literal(1),
    environmentId: z.string().uuid(),
    limit: z.number().int().min(1).max(100).safe(),
  })
  .strict();

export const deploymentPreflightHistoryExportInputSchema = z
  .object({
    schemaVersion: z.literal(1),
    receiptHash: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  })
  .strict();

export type DeploymentPreflightHistoryExportResult = Readonly<{
  saved: boolean;
  canceled: boolean;
  fileName: string | null;
  packageDigest: string | null;
}>;
