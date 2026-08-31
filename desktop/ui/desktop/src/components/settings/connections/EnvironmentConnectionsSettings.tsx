import { useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  CircleAlert,
  CloudCog,
  Ellipsis,
  FileKey2,
  History,
  LoaderCircle,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import type {
  AccordLockCredentialMaterialUpdate,
  AccordLockEnvironmentProfileInput,
  AccordLockEnvironmentProfileSummary,
} from '../../../accordlock/environmentProfiles';
import type { AccordLockEnvironmentProfileView } from '../../../accordlock/environmentProfileIpc';
import { ACCORDLOCK_DEPLOYMENT_PREFLIGHT_PROTOCOL } from '../../../accordlock/deploymentPreflight';
import {
  DeploymentPreflightDialog,
  type DeploymentPreflightCandidateDefaults,
  type DeploymentPreflightDialogInput,
} from '../../accordlock/DeploymentPreflightDialog';
import type { DeploymentPreflightResultView } from '../../accordlock/DeploymentPreflightResult';
import { DeploymentPreflightHistoryDialog } from '../../accordlock/DeploymentPreflightHistoryDialog';
import { Button } from '../../ui/button';
import { Card, CardContent } from '../../ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../../ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../ui/dropdown-menu';
import { Input } from '../../ui/input';

type EnvironmentForm = {
  name: string;
  githubRepository: string;
  githubWorkflow: string;
  githubToken: string;
  awsAccountId: string;
  awsRegion: string;
  ecrRepository: string;
  awsAccessKeyId: string;
  awsSecretAccessKey: string;
  awsSessionToken: string;
  kubernetesClusterName: string;
  kubernetesNamespace: string;
  kubernetesDeployment: string;
  kubernetesContainer: string;
};

const ENVIRONMENT_STEPS = [
  {
    title: 'Environment',
    description: 'Give this connection a name your team will recognize.',
  },
  {
    title: 'Source & build',
    description: 'Choose the repository and workflow that produce the release.',
  },
  {
    title: 'Image registry',
    description: 'Connect the ECR repository that holds the built image.',
  },
  {
    title: 'Deployment target',
    description: 'Choose the Kubernetes workload AccordLock should verify.',
  },
] as const;

const LAST_ENVIRONMENT_STEP = ENVIRONMENT_STEPS.length - 1;

const EMPTY_FORM: EnvironmentForm = {
  name: '',
  githubRepository: '',
  githubWorkflow: '.github/workflows/release.yml',
  githubToken: '',
  awsAccountId: '',
  awsRegion: '',
  ecrRepository: '',
  awsAccessKeyId: '',
  awsSecretAccessKey: '',
  awsSessionToken: '',
  kubernetesClusterName: '',
  kubernetesNamespace: 'default',
  kubernetesDeployment: '',
  kubernetesContainer: '',
};

function formFor(profile: AccordLockEnvironmentProfileSummary | null): EnvironmentForm {
  if (!profile) return { ...EMPTY_FORM };
  return {
    ...EMPTY_FORM,
    name: profile.name,
    githubRepository: profile.github.repository,
    githubWorkflow: profile.github.workflow,
    awsAccountId: profile.aws.accountId,
    awsRegion: profile.aws.region,
    ecrRepository: profile.aws.ecrRepository,
    kubernetesClusterName: profile.kubernetes.clusterName,
    kubernetesNamespace: profile.kubernetes.namespace,
    kubernetesDeployment: profile.kubernetes.deployment,
    kubernetesContainer: profile.kubernetes.container,
  };
}

function secretUpdate(value: string, existing: boolean): AccordLockCredentialMaterialUpdate {
  const normalized = value.trim();
  if (!normalized && existing) return { mode: 'KEEP' };
  return { mode: 'SET', value: normalized };
}

function environmentInput(
  form: EnvironmentForm,
  existing: AccordLockEnvironmentProfileSummary | null
): AccordLockEnvironmentProfileInput {
  const awsCredential =
    form.awsAccessKeyId.trim() || form.awsSecretAccessKey.trim() || form.awsSessionToken.trim()
      ? JSON.stringify({
          access_key_id: form.awsAccessKeyId.trim(),
          secret_access_key: form.awsSecretAccessKey.trim(),
          ...(form.awsSessionToken.trim() ? { session_token: form.awsSessionToken.trim() } : {}),
        })
      : '';

  return {
    id: existing?.id ?? null,
    name: form.name.trim(),
    runner: { mode: 'LOCAL_BUNDLED' },
    github: {
      repository: form.githubRepository.trim(),
      workflow: form.githubWorkflow.trim(),
    },
    aws: {
      accountId: form.awsAccountId.trim(),
      region: form.awsRegion.trim(),
      ecrRepository: form.ecrRepository.trim(),
    },
    kubernetes: {
      clusterName: form.kubernetesClusterName.trim(),
      namespace: form.kubernetesNamespace.trim(),
      deployment: form.kubernetesDeployment.trim(),
      container: form.kubernetesContainer.trim(),
    },
    credentials: {
      github: {
        reference: 'desktop:github',
        material: secretUpdate(form.githubToken, Boolean(existing)),
      },
      aws: {
        reference: 'desktop:aws',
        material: secretUpdate(awsCredential, Boolean(existing)),
      },
    },
  };
}

function requiredRouteFieldsPresent(form: EnvironmentForm): boolean {
  return [
    form.name,
    form.githubRepository,
    form.githubWorkflow,
    form.awsAccountId,
    form.awsRegion,
    form.ecrRepository,
    form.kubernetesClusterName,
    form.kubernetesNamespace,
    form.kubernetesDeployment,
    form.kubernetesContainer,
  ].every((value) => value.trim().length > 0);
}

function newCredentialsPresent(form: EnvironmentForm): boolean {
  return (
    form.githubToken.trim().length > 0 &&
    form.awsAccessKeyId.trim().length > 0 &&
    form.awsSecretAccessKey.trim().length > 0 &&
    form.awsSessionToken.trim().length > 0
  );
}

function temporaryAwsCredentialsComplete(form: EnvironmentForm): boolean {
  return [form.awsAccessKeyId, form.awsSecretAccessKey, form.awsSessionToken].every(
    (value) => value.trim().length > 0
  );
}

function temporaryAwsCredentialsEmpty(form: EnvironmentForm): boolean {
  return [form.awsAccessKeyId, form.awsSecretAccessKey, form.awsSessionToken].every(
    (value) => value.trim().length === 0
  );
}

function changedProviderRoutes(
  form: EnvironmentForm,
  profile: AccordLockEnvironmentProfileSummary | null
): Readonly<{ github: boolean; aws: boolean }> {
  if (!profile) return { github: false, aws: false };
  return {
    github:
      form.githubRepository.trim() !== profile.github.repository ||
      form.githubWorkflow.trim() !== profile.github.workflow,
    aws:
      form.awsAccountId.trim() !== profile.aws.accountId ||
      form.awsRegion.trim() !== profile.aws.region ||
      form.ecrRepository.trim() !== profile.aws.ecrRepository,
  };
}

function statusCopy(profile: AccordLockEnvironmentProfileSummary): {
  label: string;
  className: string;
} {
  if (profile.status === 'VERIFIED') {
    return { label: 'Last check passed', className: 'text-green-700 dark:text-green-300' };
  }
  if (profile.status === 'FAILED') {
    return { label: 'Needs attention', className: 'text-amber-700 dark:text-amber-300' };
  }
  return { label: 'Not checked', className: 'text-text-tertiary' };
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  secret = false,
  optional = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  secret?: boolean;
  optional?: boolean;
}) {
  return (
    <label className="space-y-1.5 text-xs text-text-secondary">
      <span>
        {label}
        {optional ? <span className="ml-1 text-text-tertiary">Optional</span> : null}
      </span>
      <Input
        type={secret ? 'password' : 'text'}
        autoComplete={secret ? 'off' : undefined}
        spellCheck={false}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

function EnvironmentEditor({
  open,
  profile,
  onOpenChange,
  onSaved,
}: {
  open: boolean;
  profile: AccordLockEnvironmentProfileSummary | null;
  onOpenChange: (open: boolean) => void;
  onSaved: (profile: AccordLockEnvironmentProfileView) => void;
}) {
  const [form, setForm] = useState<EnvironmentForm>(() => formFor(profile));
  const [step, setStep] = useState(0);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setForm(formFor(profile));
    setStep(0);
    setSaving(false);
    setError(null);
  }, [open, profile]);

  const set = (field: keyof EnvironmentForm) => (value: string) =>
    setForm((current) => ({ ...current, [field]: value }));

  const changedRoutes = changedProviderRoutes(form, profile);
  const changedRouteCredentialsPresent =
    (!changedRoutes.github || form.githubToken.trim().length > 0) &&
    (!changedRoutes.aws || temporaryAwsCredentialsComplete(form));
  const awsCredentialsValid =
    temporaryAwsCredentialsEmpty(form) || temporaryAwsCredentialsComplete(form);

  const canSave =
    !saving &&
    requiredRouteFieldsPresent(form) &&
    (Boolean(profile) || newCredentialsPresent(form)) &&
    changedRouteCredentialsPresent &&
    awsCredentialsValid;

  const githubStepValid =
    form.githubRepository.trim().length > 0 &&
    form.githubWorkflow.trim().length > 0 &&
    (Boolean(profile) || form.githubToken.trim().length > 0) &&
    (!changedRoutes.github || form.githubToken.trim().length > 0);
  const registryStepValid =
    form.awsAccountId.trim().length > 0 &&
    form.awsRegion.trim().length > 0 &&
    form.ecrRepository.trim().length > 0 &&
    awsCredentialsValid &&
    (Boolean(profile) || temporaryAwsCredentialsComplete(form)) &&
    (!changedRoutes.aws || temporaryAwsCredentialsComplete(form));
  const deploymentStepValid = [
    form.kubernetesClusterName,
    form.kubernetesNamespace,
    form.kubernetesDeployment,
    form.kubernetesContainer,
  ].every((value) => value.trim().length > 0);
  const currentStepValid = [
    form.name.trim().length > 0,
    githubStepValid,
    registryStepValid,
    deploymentStepValid,
  ][step];

  const continueToNextStep = () => {
    if (!currentStepValid || step === LAST_ENVIRONMENT_STEP) return;
    setError(null);
    setStep((current) => current + 1);
  };

  const returnToPreviousStep = () => {
    setError(null);
    setStep((current) => Math.max(0, current - 1));
  };

  const save = async () => {
    if (!canSave) return;
    if (changedRoutes.github && !form.githubToken.trim()) {
      setError('Enter a GitHub token after changing the GitHub route.');
      return;
    }
    if (changedRoutes.aws && !temporaryAwsCredentialsComplete(form)) {
      setError('Enter new temporary AWS credentials, including the session token.');
      return;
    }
    if (!awsCredentialsValid) {
      setError('Enter all three temporary AWS credential fields.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      onSaved(
        await window.electron.saveAccordLockEnvironmentProfile(environmentInput(form, profile))
      );
      onOpenChange(false);
    } catch (saveError) {
      if (
        !(saveError instanceof Error) ||
        !saveError.message.includes('ACCORDLOCK_EKS_CONNECTION_CANCELLED')
      ) {
        setError('Could not verify this environment. Check the connection details and try again.');
      }
      setSaving(false);
    }
  };

  const secretPlaceholder = profile ? 'Leave blank to keep saved value' : 'Required';
  const currentStep = ENVIRONMENT_STEPS[step];

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => !saving && onOpenChange(nextOpen)}>
      <DialogContent className="sm:max-w-[640px]">
        <DialogHeader>
          <DialogTitle>{profile ? 'Edit environment' : 'Connect environment'}</DialogTitle>
          <DialogDescription>
            Connect the systems AccordLock uses to verify a deployment.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-1">
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-4 text-xs text-text-tertiary">
              <span>
                Step {step + 1} of {ENVIRONMENT_STEPS.length}
              </span>
              <span>{currentStep.title}</span>
            </div>
            <div
              role="progressbar"
              aria-label="Environment setup progress"
              aria-valuemin={1}
              aria-valuemax={ENVIRONMENT_STEPS.length}
              aria-valuenow={step + 1}
              aria-valuetext={`${currentStep.title}, step ${step + 1} of ${ENVIRONMENT_STEPS.length}`}
              className="grid grid-cols-4 gap-1"
            >
              {ENVIRONMENT_STEPS.map((candidate, index) => (
                <span
                  key={candidate.title}
                  aria-hidden="true"
                  className={`h-1 rounded-full ${
                    index <= step ? 'bg-background-inverse' : 'bg-background-tertiary'
                  }`}
                />
              ))}
            </div>
          </div>

          <div className="min-h-[320px] space-y-4 rounded-xl border border-border-secondary p-5">
            <div>
              <h3 className="text-base font-medium text-text-primary">{currentStep.title}</h3>
              <p className="mt-1 text-sm text-text-secondary">{currentStep.description}</p>
            </div>

            {step === 0 ? (
              <Field
                label="Name"
                value={form.name}
                onChange={set('name')}
                placeholder="Production"
              />
            ) : null}

            {step === 1 ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <Field
                  label="Repository"
                  value={form.githubRepository}
                  onChange={set('githubRepository')}
                  placeholder="company/service"
                />
                <Field
                  label="Build workflow"
                  value={form.githubWorkflow}
                  onChange={set('githubWorkflow')}
                  placeholder=".github/workflows/release.yml"
                />
                <div className="space-y-1.5 sm:col-span-2">
                  <Field
                    label="Fine-grained GitHub token"
                    value={form.githubToken}
                    onChange={set('githubToken')}
                    placeholder={secretPlaceholder}
                    secret
                  />
                  {changedRoutes.github && !form.githubToken.trim() ? (
                    <p className="text-xs text-amber-700 dark:text-amber-300">
                      Enter a new token for this repository.
                    </p>
                  ) : null}
                </div>
                <p className="flex items-center gap-2 text-xs text-text-tertiary sm:col-span-2">
                  <ShieldCheck aria-hidden="true" className="h-3.5 w-3.5" />
                  Use a read-only token scoped to this repository. It is stored by your operating
                  system and is not shown again.
                </p>
              </div>
            ) : null}

            {step === 2 ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <Field
                  label="AWS account ID"
                  value={form.awsAccountId}
                  onChange={set('awsAccountId')}
                  placeholder="123456789012"
                />
                <Field
                  label="Region"
                  value={form.awsRegion}
                  onChange={set('awsRegion')}
                  placeholder="eu-west-1"
                />
                <div className="sm:col-span-2">
                  <Field
                    label="ECR repository"
                    value={form.ecrRepository}
                    onChange={set('ecrRepository')}
                    placeholder="services/api"
                  />
                </div>
                <Field
                  label="Temporary access key ID"
                  value={form.awsAccessKeyId}
                  onChange={set('awsAccessKeyId')}
                  placeholder={secretPlaceholder}
                  secret
                />
                <Field
                  label="Temporary secret access key"
                  value={form.awsSecretAccessKey}
                  onChange={set('awsSecretAccessKey')}
                  placeholder={secretPlaceholder}
                  secret
                />
                <div className="sm:col-span-2">
                  <Field
                    label="Session token"
                    value={form.awsSessionToken}
                    onChange={set('awsSessionToken')}
                    placeholder={secretPlaceholder}
                    secret
                  />
                </div>
                {!awsCredentialsValid ? (
                  <p className="text-xs text-amber-700 dark:text-amber-300 sm:col-span-2">
                    Enter the temporary access key, secret key, and session token together.
                  </p>
                ) : changedRoutes.aws && !temporaryAwsCredentialsComplete(form) ? (
                  <p className="text-xs text-amber-700 dark:text-amber-300 sm:col-span-2">
                    Enter new temporary AWS credentials for this registry.
                  </p>
                ) : null}
                <p className="flex items-center gap-2 text-xs text-text-tertiary sm:col-span-2">
                  <ShieldCheck aria-hidden="true" className="h-3.5 w-3.5" />
                  Paste temporary credentials from AWS CLI or SSO. A session token is required.
                </p>
              </div>
            ) : null}

            {step === 3 ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <Field
                  label="Cluster name"
                  value={form.kubernetesClusterName}
                  onChange={set('kubernetesClusterName')}
                  placeholder="production-eks"
                />
                <Field
                  label="Namespace"
                  value={form.kubernetesNamespace}
                  onChange={set('kubernetesNamespace')}
                  placeholder="production"
                />
                <Field
                  label="Deployment"
                  value={form.kubernetesDeployment}
                  onChange={set('kubernetesDeployment')}
                  placeholder="api"
                />
                <Field
                  label="Container"
                  value={form.kubernetesContainer}
                  onChange={set('kubernetesContainer')}
                  placeholder="api"
                />
                <p className="text-xs text-text-tertiary sm:col-span-2">
                  AccordLock verifies the cluster endpoint and certificate before saving.
                </p>
              </div>
            ) : null}
          </div>

          {error && (
            <p role="alert" className="text-sm text-text-danger">
              {error}
            </p>
          )}
        </div>

        <DialogFooter className="sm:justify-between">
          <Button
            type="button"
            variant="outline"
            disabled={saving}
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <div className="flex justify-end gap-2">
            {step > 0 ? (
              <Button
                type="button"
                variant="outline"
                disabled={saving}
                onClick={returnToPreviousStep}
              >
                Back
              </Button>
            ) : null}
            {step < LAST_ENVIRONMENT_STEP ? (
              <Button type="button" disabled={!currentStepValid} onClick={continueToNextStep}>
                Continue
              </Button>
            ) : (
              <Button type="button" disabled={!canSave} onClick={() => void save()}>
                {saving && <LoaderCircle aria-hidden="true" className="h-4 w-4 animate-spin" />}
                {saving ? 'Saving…' : 'Save environment'}
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function EnvironmentConnectionsSettings() {
  const [profiles, setProfiles] = useState<AccordLockEnvironmentProfileView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [canReload, setCanReload] = useState(false);
  const [importingId, setImportingId] = useState<string | null>(null);
  const [candidateDefaults, setCandidateDefaults] = useState<
    Record<string, DeploymentPreflightCandidateDefaults>
  >({});
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<AccordLockEnvironmentProfileSummary | null>(null);
  const [checking, setChecking] = useState<AccordLockEnvironmentProfileSummary | null>(null);
  const [historyEnvironment, setHistoryEnvironment] =
    useState<AccordLockEnvironmentProfileSummary | null>(null);

  const profileById = useMemo(
    () => new Map(profiles.map((profile) => [profile.id, profile])),
    [profiles]
  );

  const load = async () => {
    setLoading(true);
    setError(null);
    setCanReload(false);
    try {
      setProfiles(await window.electron.listAccordLockEnvironmentProfiles());
    } catch {
      setError("Couldn't load environments.");
      setCanReload(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const replace = (profile: AccordLockEnvironmentProfileView) => {
    setProfiles((current) =>
      [...current.filter((candidate) => candidate.id !== profile.id), profile].sort((left, right) =>
        left.name.localeCompare(right.name)
      )
    );
  };

  const importBuildProof = async (profile: AccordLockEnvironmentProfileView) => {
    setError(null);
    setCanReload(false);
    setImportingId(profile.id);
    try {
      const result = await window.electron.importAccordLockDeploymentPreflightCiEvidence(
        profile.id
      );
      if (result.status === 'CANCELED') {
        return;
      }
      const refreshed = await window.electron.listAccordLockEnvironmentProfiles();
      setProfiles(refreshed);
      setCandidateDefaults((current) => ({
        ...current,
        [profile.id]: {
          buildRunUrl: `https://github.com/${result.repository}/actions/runs/${result.runId}`,
          imageDigest: result.imageDigest,
        },
      }));
      setChecking(refreshed.find((candidate) => candidate.id === profile.id) ?? profile);
    } catch {
      setError("Couldn't import this build proof.");
    } finally {
      setImportingId(null);
    }
  };

  const remove = async (profile: AccordLockEnvironmentProfileSummary) => {
    setError(null);
    setCanReload(false);
    try {
      if (await window.electron.removeAccordLockEnvironmentProfile(profile.id)) {
        setProfiles((current) => current.filter((candidate) => candidate.id !== profile.id));
      }
    } catch {
      setError("Couldn't remove this environment.");
    }
  };

  const run = async (input: DeploymentPreflightDialogInput) => {
    const result = await window.electron.runAccordLockDeploymentPreflight({
      protocol: ACCORDLOCK_DEPLOYMENT_PREFLIGHT_PROTOCOL,
      schemaVersion: 1,
      ...input,
    });
    const refreshed = await window.electron.listAccordLockEnvironmentProfiles();
    setProfiles(refreshed);
    return result;
  };

  const exportReceipt = async (result: DeploymentPreflightResultView) => {
    await window.electron.exportAccordLockDeploymentPreflightReceipt(result.receiptHash);
  };

  return (
    <>
      <Card className="rounded-lg">
        <CardContent className="p-0">
          <div className="flex items-center justify-between gap-4 border-b border-border-secondary px-4 py-3.5">
            <div className="flex min-w-0 items-start gap-3">
              <CloudCog aria-hidden="true" className="mt-0.5 h-4 w-4 text-text-secondary" />
              <div>
                <h2 className="text-sm font-medium text-text-primary">Environments</h2>
                <p className="text-xs text-text-secondary">
                  Saved routes and credentials for deployment checks.
                </p>
              </div>
            </div>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => {
                setEditing(null);
                setEditorOpen(true);
              }}
            >
              <Plus aria-hidden="true" className="h-4 w-4" />
              Connect
            </Button>
          </div>

          {loading ? (
            <div className="flex h-24 items-center justify-center text-text-secondary">
              <LoaderCircle aria-label="Loading environments" className="h-4 w-4 animate-spin" />
            </div>
          ) : profiles.length === 0 ? (
            <div className="px-4 py-8 text-center">
              <p className="text-sm text-text-primary">No environments connected</p>
              <p className="mt-1 text-xs text-text-secondary">
                Add one to verify code, builds, images, and deployment state.
              </p>
            </div>
          ) : (
            <div>
              {profiles.map((profile) => {
                const status = statusCopy(profile);
                return (
                  <div
                    key={profile.id}
                    className="flex min-h-[72px] items-center gap-4 border-b border-border-subtle px-4 py-3 last:border-b-0"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className="truncate text-sm font-medium text-text-primary">
                          {profile.name}
                        </span>
                        <span className={`flex items-center gap-1 text-[11px] ${status.className}`}>
                          {profile.status === 'VERIFIED' ? (
                            <CheckCircle2 aria-hidden="true" className="h-3 w-3" />
                          ) : profile.status === 'FAILED' ? (
                            <CircleAlert aria-hidden="true" className="h-3 w-3" />
                          ) : null}
                          {status.label}
                        </span>
                      </div>
                      <p className="mt-0.5 truncate text-xs text-text-secondary">
                        {profile.github.repository} · {profile.aws.region} ·{' '}
                        {profile.kubernetes.namespace}/{profile.kubernetes.deployment}
                      </p>
                    </div>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={importingId === profile.id}
                      onClick={() =>
                        profile.ciTrust.status === 'ENROLLED'
                          ? setChecking(profile)
                          : void importBuildProof(profile)
                      }
                    >
                      {importingId === profile.id ? (
                        <LoaderCircle aria-hidden="true" className="h-4 w-4 animate-spin" />
                      ) : null}
                      {profile.ciTrust.status === 'ENROLLED' ? 'Verify' : 'Add build proof'}
                    </Button>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          type="button"
                          size="sm"
                          shape="round"
                          variant="ghost"
                          aria-label={`More actions for ${profile.name}`}
                        >
                          <Ellipsis aria-hidden="true" className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => void importBuildProof(profile)}>
                          <FileKey2 aria-hidden="true" className="h-4 w-4" />
                          Import build proof…
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => setHistoryEnvironment(profile)}>
                          <History aria-hidden="true" className="h-4 w-4" />
                          Check history
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => {
                            setEditing(profile);
                            setEditorOpen(true);
                          }}
                        >
                          <Pencil aria-hidden="true" className="h-4 w-4" />
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => void remove(profile)}>
                          <Trash2 aria-hidden="true" className="h-4 w-4" />
                          Remove
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                );
              })}
            </div>
          )}
          {error && (
            <div className="border-t border-border-secondary px-4 py-3">
              <p role="alert" className="text-xs text-text-danger">
                {error}{' '}
                {canReload ? (
                  <button type="button" className="underline" onClick={() => void load()}>
                    Try again
                  </button>
                ) : null}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <EnvironmentEditor
        open={editorOpen}
        profile={editing}
        onOpenChange={setEditorOpen}
        onSaved={replace}
      />
      {historyEnvironment ? (
        <DeploymentPreflightHistoryDialog
          open
          environment={{ id: historyEnvironment.id, name: historyEnvironment.name }}
          onOpenChange={(open) => !open && setHistoryEnvironment(null)}
        />
      ) : null}
      {checking && (
        <DeploymentPreflightDialog
          open
          candidateDefaults={candidateDefaults[checking.id]}
          environment={{
            id: checking.id,
            name: profileById.get(checking.id)?.name ?? checking.name,
            repository: checking.github.repository,
            workflow: checking.github.workflow,
            target: `${checking.kubernetes.clusterName} · ${checking.kubernetes.namespace}/${checking.kubernetes.deployment}:${checking.kubernetes.container}`,
            status: profileById.get(checking.id)?.status ?? checking.status,
          }}
          onOpenChange={(open) => !open && setChecking(null)}
          onRun={run}
          onExport={(result) => void exportReceipt(result)}
        />
      )}
    </>
  );
}
