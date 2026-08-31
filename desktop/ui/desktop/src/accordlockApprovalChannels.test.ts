import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  AccordLockApprovalChannelStore,
  parseAccordLockApprovalChannelInput,
  type AccordLockApprovalChannelSafeStorage,
} from './accordlockApprovalChannels';

const safeStorage: AccordLockApprovalChannelSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (plaintext) =>
    Buffer.from(`protected:${Buffer.from(plaintext).toString('base64')}`),
  decryptString: (ciphertext) => {
    const value = ciphertext.toString('utf8');
    if (!value.startsWith('protected:')) throw new Error('invalid fixture ciphertext');
    return Buffer.from(value.slice('protected:'.length), 'base64').toString('utf8');
  },
};

describe('approval channel configuration', () => {
  it('accepts exact provider shapes and normalizes the Teams endpoint', () => {
    expect(
      parseAccordLockApprovalChannelInput({
        channel: 'MICROSOFT_TEAMS',
        enabled: true,
        accessToken: 'fixture-teams-access-token-00000000',
        conversationId: '19:fixture@thread.v2',
        serviceUrl: 'https://smba.trafficmanager.net/emea',
      })
    ).toMatchObject({ serviceUrl: 'https://smba.trafficmanager.net/emea/' });

    expect(
      parseAccordLockApprovalChannelInput({
        channel: 'TELEGRAM',
        enabled: true,
        botToken: '123456789:fixture_telegram_token_123456789012345',
        chatId: '-1001234567890',
      })
    ).toMatchObject({ channel: 'TELEGRAM', chatId: '-1001234567890' });

    expect(
      parseAccordLockApprovalChannelInput({
        channel: 'WHATSAPP',
        enabled: true,
        accessToken: 'fixture-whatsapp-access-token-000000000000',
        phoneNumberId: '123456789012345',
        recipient: '+14155550123',
      })
    ).toMatchObject({ recipient: '14155550123' });
  });

  it('rejects unknown fields, untrusted endpoints, and malformed destinations', () => {
    expect(() =>
      parseAccordLockApprovalChannelInput({
        channel: 'SLACK',
        enabled: true,
        accessToken: 'fixture-slack-access-token-00000000',
        destination: 'C12345678',
        redirect: 'https://attacker.invalid',
      })
    ).toThrow('Slack configuration is invalid');

    expect(() =>
      parseAccordLockApprovalChannelInput({
        channel: 'MICROSOFT_TEAMS',
        enabled: true,
        accessToken: 'fixture-teams-access-token-00000000',
        conversationId: '19:fixture@thread.v2',
        serviceUrl: 'https://attacker.invalid/emea/',
      })
    ).toThrow('not allowed');

    for (const conversationId of ['19:fixture\n@thread.v2', '19:fixture\u202e@thread.v2']) {
      expect(() =>
        parseAccordLockApprovalChannelInput({
          channel: 'MICROSOFT_TEAMS',
          enabled: true,
          accessToken: 'fixture-teams-access-token-00000000',
          conversationId,
          serviceUrl: 'https://smba.trafficmanager.net/emea/',
        })
      ).toThrow('Microsoft Teams configuration is invalid');
    }
  });

  it('persists ciphertext and returns only redacted summaries', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-channels-'));
    const store = new AccordLockApprovalChannelStore({
      directory,
      nowSeconds: () => 1_777_777_777,
      platform: 'win32',
      safeStorage,
    });
    const secret = 'fixture-slack-access-token-00000000';
    const saved = await store.save({
      channel: 'SLACK',
      enabled: true,
      accessToken: secret,
      destination: 'C12345678',
    });

    expect(saved).toEqual({
      channel: 'SLACK',
      configuredAt: 1_777_777_777,
      destinationHint: '•••345678',
      enabled: true,
      updatedAt: 1_777_777_777,
    });
    expect(await store.list()).toEqual([saved]);
    const raw = await fs.readFile(path.join(directory, 'approval-channels.v1.bin'), 'utf8');
    expect(raw).not.toContain(secret);
    expect(JSON.stringify(saved)).not.toContain(secret);

    expect(await store.setEnabled('SLACK', false)).toMatchObject({
      channel: 'SLACK',
      enabled: false,
    });

    expect(await store.remove('SLACK')).toBe(true);
    expect(await store.list()).toEqual([]);
  });

  it('loads enabled credentials and a stable encrypted outbox key only inside the store', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-channels-'));
    const store = new AccordLockApprovalChannelStore({
      directory,
      platform: 'win32',
      safeStorage,
    });
    await store.save({
      channel: 'SLACK',
      enabled: true,
      accessToken: 'fixture-slack-access-token-00000000',
      destination: 'C12345678',
    });
    await store.save({
      channel: 'TELEGRAM',
      enabled: false,
      botToken: '123456789:fixture_telegram_token_123456789012345',
      chatId: '-1001234567890',
    });

    const first = await store.loadNotificationDispatchBundle();
    const second = await store.loadNotificationDispatchBundle();
    expect(first?.channels).toEqual([
      {
        channel: 'SLACK',
        enabled: true,
        accessToken: 'fixture-slack-access-token-00000000',
        destination: 'C12345678',
      },
    ]);
    expect(first?.outboxKeyHex).toMatch(/^(?!0{64}$)[0-9a-f]{64}$/u);
    expect(second?.outboxKeyHex).toBe(first?.outboxKeyHex);
    expect(await store.loadNotificationTestBundle('SLACK')).toEqual({
      channels: first?.channels,
      outboxKeyHex: first?.outboxKeyHex,
    });
    await expect(store.loadNotificationTestBundle('TELEGRAM')).rejects.toThrow('disabled');
    expect(JSON.stringify(await store.list())).not.toContain('accessToken');

    const encryptedKey = await fs.readFile(
      path.join(directory, 'approval-notifications-key.v1.bin'),
      'utf8'
    );
    expect(encryptedKey).not.toContain(first?.outboxKeyHex ?? 'missing-key');
  });

  it('fails closed when secure OS storage is unavailable', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'accordlock-channels-'));
    const store = new AccordLockApprovalChannelStore({
      directory,
      platform: 'linux',
      safeStorage: {
        ...safeStorage,
        getSelectedStorageBackend: () => 'basic_text',
      },
    });

    await expect(store.list()).rejects.toThrow('Secure credential storage is unavailable');
  });
});
