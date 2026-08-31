import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronUp, LoaderCircle } from 'lucide-react';
import type {
  AccordLockApprovalChannelId,
  AccordLockApprovalChannelInput,
  AccordLockApprovalChannelSummary,
} from '../../../accordlockApprovalChannels';
import type { AccordLockRemoteGatewayEnrollmentSummary } from '../../../accordlockRemoteApprovals';
import { Button } from '../../ui/button';
import { Input } from '../../ui/input';
import { Switch } from '../../ui/switch';

type Field = {
  autocomplete?: string;
  key: string;
  label: string;
  placeholder: string;
  secret?: boolean;
};

type ChannelDefinition = {
  channel: AccordLockApprovalChannelId;
  fields: Field[];
  name: string;
};

const CHANNELS: ChannelDefinition[] = [
  {
    channel: 'SLACK',
    name: 'Slack',
    fields: [
      { key: 'destination', label: 'Channel ID', placeholder: 'C0123456789' },
      {
        key: 'accessToken',
        label: 'Bot token',
        placeholder: 'xoxb-…',
        secret: true,
        autocomplete: 'off',
      },
    ],
  },
  {
    channel: 'MICROSOFT_TEAMS',
    name: 'Microsoft Teams',
    fields: [
      { key: 'conversationId', label: 'Conversation ID', placeholder: '19:…@thread.v2' },
      {
        key: 'serviceUrl',
        label: 'Service URL',
        placeholder: 'https://smba.trafficmanager.net/emea/',
      },
      {
        key: 'accessToken',
        label: 'Access token',
        placeholder: 'Paste token',
        secret: true,
        autocomplete: 'off',
      },
    ],
  },
  {
    channel: 'TELEGRAM',
    name: 'Telegram',
    fields: [
      { key: 'chatId', label: 'Chat ID', placeholder: '-1001234567890' },
      {
        key: 'botToken',
        label: 'Bot token',
        placeholder: '123456789:…',
        secret: true,
        autocomplete: 'off',
      },
    ],
  },
  {
    channel: 'WHATSAPP',
    name: 'WhatsApp',
    fields: [
      { key: 'recipient', label: 'Recipient', placeholder: '+14155550123' },
      { key: 'phoneNumberId', label: 'Phone number ID', placeholder: '123456789012345' },
      {
        key: 'accessToken',
        label: 'Access token',
        placeholder: 'Paste token',
        secret: true,
        autocomplete: 'off',
      },
    ],
  },
];

function inputFor(
  definition: ChannelDefinition,
  values: Record<string, string>
): AccordLockApprovalChannelInput {
  if (definition.channel === 'SLACK') {
    return {
      channel: 'SLACK',
      enabled: true,
      accessToken: values.accessToken ?? '',
      destination: values.destination ?? '',
    };
  }
  if (definition.channel === 'MICROSOFT_TEAMS') {
    return {
      channel: 'MICROSOFT_TEAMS',
      enabled: true,
      accessToken: values.accessToken ?? '',
      conversationId: values.conversationId ?? '',
      serviceUrl: values.serviceUrl ?? '',
    };
  }
  if (definition.channel === 'TELEGRAM') {
    return {
      channel: 'TELEGRAM',
      enabled: true,
      botToken: values.botToken ?? '',
      chatId: values.chatId ?? '',
    };
  }
  return {
    channel: 'WHATSAPP',
    enabled: true,
    accessToken: values.accessToken ?? '',
    phoneNumberId: values.phoneNumberId ?? '',
    recipient: values.recipient ?? '',
  };
}

export default function ApprovalChannelsSettings() {
  const [summaries, setSummaries] = useState<AccordLockApprovalChannelSummary[]>([]);
  const [expanded, setExpanded] = useState<AccordLockApprovalChannelId | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<AccordLockApprovalChannelId | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [remoteEnrollment, setRemoteEnrollment] =
    useState<AccordLockRemoteGatewayEnrollmentSummary | null>(null);
  const [remoteBusy, setRemoteBusy] = useState(false);
  const [testedChannel, setTestedChannel] = useState<AccordLockApprovalChannelId | null>(null);

  const byChannel = useMemo(
    () => new Map(summaries.map((summary) => [summary.channel, summary])),
    [summaries]
  );

  useEffect(() => {
    let active = true;
    window.electron
      .listAccordLockApprovalChannels()
      .then((result) => {
        if (active) setSummaries(result);
      })
      .catch(() => {
        if (active) setError("Couldn't load approval alerts.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    window.electron
      .getAccordLockRemoteApprovalEnrollment()
      .then((result) => {
        if (active) setRemoteEnrollment(result);
      })
      .catch(() => {
        if (active) setError("Couldn't load remote approval settings.");
      });
    return () => {
      active = false;
    };
  }, []);

  const replaceSummary = (summary: AccordLockApprovalChannelSummary) => {
    setSummaries((current) => [
      ...current.filter((candidate) => candidate.channel !== summary.channel),
      summary,
    ]);
  };

  const open = (channel: AccordLockApprovalChannelId) => {
    setError(null);
    setValues({});
    setExpanded((current) => (current === channel ? null : channel));
  };

  const save = async (definition: ChannelDefinition) => {
    setBusy(definition.channel);
    setError(null);
    try {
      const summary = await window.electron.saveAccordLockApprovalChannel(
        inputFor(definition, values)
      );
      replaceSummary(summary);
      setValues({});
      setExpanded(null);
    } catch {
      setError(`Check your ${definition.name} settings and try again.`);
    } finally {
      setBusy(null);
    }
  };

  const setEnabled = async (channel: AccordLockApprovalChannelId, enabled: boolean) => {
    setBusy(channel);
    setError(null);
    try {
      replaceSummary(await window.electron.setAccordLockApprovalChannelEnabled(channel, enabled));
    } catch {
      setError("Couldn't update this channel.");
    } finally {
      setBusy(null);
    }
  };

  const sendTest = async (definition: ChannelDefinition) => {
    setBusy(definition.channel);
    setTestedChannel(null);
    setError(null);
    try {
      const report = await window.electron.testAccordLockApprovalChannel(definition.channel);
      if (!report.accepted) throw new Error(report.outcome);
      setTestedChannel(definition.channel);
    } catch {
      setError(`${definition.name} did not accept the test message.`);
    } finally {
      setBusy(null);
    }
  };

  const remove = async (channel: AccordLockApprovalChannelId) => {
    setBusy(channel);
    setError(null);
    try {
      if (await window.electron.removeAccordLockApprovalChannel(channel)) {
        setSummaries((current) => current.filter((summary) => summary.channel !== channel));
        setExpanded(null);
        setValues({});
      }
    } catch {
      setError("Couldn't remove the saved credentials.");
    } finally {
      setBusy(null);
    }
  };

  const pairRemoteGateway = async () => {
    setRemoteBusy(true);
    setError(null);
    try {
      const result = await window.electron.importAccordLockRemoteApprovalEnrollment();
      if (result) setRemoteEnrollment(result);
    } catch {
      setError("Couldn't pair this approval gateway.");
    } finally {
      setRemoteBusy(false);
    }
  };

  const revokeRemoteGateway = async () => {
    if (!remoteEnrollment) return;
    setRemoteBusy(true);
    setError(null);
    try {
      setRemoteEnrollment(
        await window.electron.revokeAccordLockRemoteApprovalEnrollment(
          remoteEnrollment.enrollmentId
        )
      );
    } catch {
      setError("Couldn't revoke this approval gateway.");
    } finally {
      setRemoteBusy(false);
    }
  };

  const importTestReceipt = async () => {
    setRemoteBusy(true);
    setError(null);
    try {
      await window.electron.importAccordLockRemoteApprovalReceipt();
    } catch {
      setError('The signed decision was refused. Check its gateway, action, channel, and expiry.');
    } finally {
      setRemoteBusy(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-16 items-center justify-center text-text-secondary">
        <LoaderCircle className="size-4 animate-spin" aria-label="Loading approval channels" />
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {CHANNELS.map((definition) => {
        const summary = byChannel.get(definition.channel);
        const isExpanded = expanded === definition.channel;
        const isBusy = busy === definition.channel;
        const canSave = definition.fields.every((field) => (values[field.key] ?? '').trim());
        return (
          <div key={definition.channel} className="border-b border-border-subtle last:border-b-0">
            <div className="flex min-h-12 items-center justify-between gap-3 py-2">
              <button
                type="button"
                className="min-w-0 flex-1 text-left"
                aria-expanded={isExpanded}
                onClick={() => open(definition.channel)}
              >
                <span className="flex items-center gap-2 text-xs text-text-primary">
                  {definition.name}
                  {isExpanded ? (
                    <ChevronUp className="size-3 text-text-secondary" aria-hidden="true" />
                  ) : (
                    <ChevronDown className="size-3 text-text-secondary" aria-hidden="true" />
                  )}
                </span>
                <span className="mt-0.5 block text-xs text-text-secondary">
                  {summary ? `Configured · ${summary.destinationHint}` : 'Not configured'}
                </span>
              </button>
              {summary && (
                <div className="flex items-center gap-2">
                  {summary.enabled && (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={isBusy}
                      onClick={() => void sendTest(definition)}
                    >
                      {testedChannel === definition.channel ? 'Sent' : 'Send test'}
                    </Button>
                  )}
                  <Switch
                    aria-label={`Enable ${definition.name}`}
                    checked={summary.enabled}
                    disabled={isBusy}
                    onCheckedChange={(checked) => void setEnabled(definition.channel, checked)}
                    variant="mono"
                  />
                </div>
              )}
            </div>

            {isExpanded && (
              <div className="grid gap-3 pb-4 pt-1 sm:grid-cols-2">
                {definition.fields.map((field) => (
                  <label key={field.key} className="space-y-1 text-xs text-text-secondary">
                    <span>{field.label}</span>
                    <Input
                      autoComplete={field.autocomplete}
                      type={field.secret ? 'password' : 'text'}
                      value={values[field.key] ?? ''}
                      placeholder={field.placeholder}
                      onChange={(event) =>
                        setValues((current) => ({ ...current, [field.key]: event.target.value }))
                      }
                    />
                  </label>
                ))}
                <div className="flex items-center justify-end gap-2 sm:col-span-2">
                  {summary && (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={isBusy}
                      onClick={() => void remove(definition.channel)}
                    >
                      Remove
                    </Button>
                  )}
                  <Button
                    variant="secondary"
                    size="sm"
                    disabled={isBusy || !canSave}
                    onClick={() => void save(definition)}
                  >
                    {isBusy ? 'Saving…' : summary ? 'Replace credentials' : 'Save'}
                  </Button>
                </div>
              </div>
            )}
          </div>
        );
      })}
      <div className="pt-4">
        <div className="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-border-subtle p-3">
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium text-text-primary">Remote approvals</p>
            <p className="mt-1 max-w-xl text-xs text-text-secondary">
              Pair a gateway to accept signed, single-use decisions from your approved channels.
            </p>
            {remoteEnrollment && (
              <p className="mt-2 truncate text-xs text-text-secondary">
                {remoteEnrollment.gatewayName} · {remoteEnrollment.status.toLowerCase()}
              </p>
            )}
            {remoteEnrollment?.status === 'ACTIVE' && (
              <details className="mt-2 text-xs text-text-secondary">
                <summary className="w-fit cursor-pointer select-none">Technical details</summary>
                <p className="mt-2 break-all">Key {remoteEnrollment.fingerprint}</p>
                <Button
                  className="mt-1 px-0"
                  variant="ghost"
                  size="sm"
                  disabled={remoteBusy}
                  onClick={() => void importTestReceipt()}
                >
                  Import a test receipt
                </Button>
              </details>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {remoteEnrollment && remoteEnrollment.status !== 'REVOKED' && (
              <Button
                variant="ghost"
                size="sm"
                disabled={remoteBusy}
                onClick={() => void revokeRemoteGateway()}
              >
                Revoke
              </Button>
            )}
            <Button
              variant="secondary"
              size="sm"
              disabled={remoteBusy}
              onClick={() => void pairRemoteGateway()}
            >
              {remoteBusy ? 'Working…' : remoteEnrollment ? 'Replace gateway' : 'Pair gateway'}
            </Button>
          </div>
        </div>
      </div>
      {error && (
        <p role="alert" className="pt-2 text-xs text-red-500">
          {error}
        </p>
      )}
    </div>
  );
}
