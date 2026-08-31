const path = require('node:path');
const { signStagedWindowsSidecars } = require('./accordlock-windows-signing');

const certificatePassword = process.env.WINDOWS_CERTIFICATE_PASSWORD || '';

function redactedMessage(error) {
  const raw = error instanceof Error ? error.message : String(error);
  return certificatePassword ? raw.split(certificatePassword).join('[REDACTED]') : raw;
}

async function main() {
  const signedDigests = await signStagedWindowsSidecars({
    binDirectory: path.resolve(__dirname, '..', 'src', 'bin'),
    signingOptions: {
      certificateFile: process.env.WINDOWS_CERTIFICATE_FILE || '',
      certificatePassword,
      timestampServer:
        process.env.ACCORDLOCK_WINDOWS_TIMESTAMP_URL || 'https://timestamp.digicert.com',
    },
  });
  console.log(
    `Signed protected AccordLock sidecars (${Object.values(signedDigests)
      .map((digest) => `${digest.slice(0, 12)}...`)
      .join(', ')})`
  );
}

main().catch((error) => {
  console.error(redactedMessage(error));
  process.exitCode = 1;
});
