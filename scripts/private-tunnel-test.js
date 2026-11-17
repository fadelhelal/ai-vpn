'use strict';

// Runs the stored private profile through the production session + guard so the
// protection checks are exercised against a real tunnel. One UAC confirmation is
// required; the tunnel is always disconnected before exit.

const { app } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SettingsStore } = require('../src/store');
const { VpnSession } = require('../src/session');
const { Guard } = require('../src/guard');
const { probeExit } = require('../src/measure');

const ENGINE = 'C:/Program Files/OpenVPN/bin/openvpn.exe';
const userData = path.join(process.env.APPDATA, 'AIVPN');
const outDir = path.join(os.tmpdir(), 'aivpn-private-test');
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const killSwitchEnabled = process.env.AIVPN_TEST_KILL_SWITCH === '1';

app.setName('AIVPN');
app.setPath('userData', userData);

app.whenReady().then(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const store = new SettingsStore(userData);
  await store.detectEncryption();
  const profile = await store.getSecret('privateProfile');
  console.log(
    `store: ${store.file} encryption=${store.encryptionAvailable()} blob=${Boolean(store.secrets.privateProfile)}`
  );
  if (!profile) throw new Error('NO_PRIVATE_PROFILE');

  const session = new VpnSession({
    runDir: path.join(userData, 'run'),
    findEngine: async () => (fs.existsSync(ENGINE) ? ENGINE : null),
    getCredentials: () => ({ username: '', password: '' })
  });
  session.on('state', (state) => console.log(`state: ${state.status} ${state.error || ''}`));
  const guard = new Guard({ storeFile: path.join(userData, 'guard.json') });

  const before = await probeExit();
  console.log(`exit ip before: ${before.ok ? before.exit : before.reason}`);

  let state = null;
  let report = null;
  let after = null;
  try {
    state = await session.connect({
      server: { id: 'private', host: 'Stockholm private server', ip: null, country: 'Sweden', countryCode: 'SE' },
      config: profile,
      isPrivate: true,
      killSwitchEnabled,
      killSwitchStrict: true
    });
    if (state.status === 'CONNECTED') {
      await delay(6000);
      report = await guard.inspect({
        state: session.snapshot(),
        logFile: session.logFile,
        enginePath: ENGINE
      });
      console.log(`gate: ${report.level} ${report.checks.map((check) => `${check.id}:${check.level}:${check.code}`).join(' ')}`);
      after = await probeExit();
      console.log(`exit ip after: ${after.ok ? after.exit : after.reason}`);
    }
  } finally {
    await session.disconnect().catch(() => {});
  }
  await delay(6000);
  const afterDisconnect = await probeExit();

  const result = {
    at: new Date().toISOString(),
    status: state ? state.status : 'ERROR',
    error: state ? state.error || null : null,
    killSwitchEnabled,
    before,
    after,
    afterDisconnect,
    guard: report
  };
  fs.writeFileSync(path.join(outDir, 'result.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
  app.exit(state && state.status === 'CONNECTED' ? 0 : 2);
}).catch((error) => {
  console.error(`FAILED: ${error.message}`);
  app.exit(1);
});

setTimeout(() => {
  console.error('TEST_TIMEOUT');
  app.exit(3);
}, 180000);
