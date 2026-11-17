'use strict';

// One live tunnel run that exercises the production modules (directory +
// session), not a reimplementation. Requires an elevated UAC confirmation per
// attempt. Stops at the first relay whose tunnel actually routes traffic.

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { Directory } = require('../src/directory');
const { VpnSession } = require('../src/session');
const { probeExit, measureDownload } = require('../src/measure');
const { Guard } = require('../src/guard');

const ENGINE = 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe';
const runDir = path.join(os.tmpdir(), 'aivpn-live-test');
const cacheFile = path.join(runDir, 'directory.json');
const resultFile = path.join(runDir, 'result.json');

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchTrace() {
  try {
    const response = await fetch('https://1.1.1.1/cdn-cgi/trace', { signal: AbortSignal.timeout(15000) });
    const text = await response.text();
    const fields = Object.fromEntries(
      text
        .split('\n')
        .filter((line) => line.includes('='))
        .map((line) => line.split('='))
    );
    return { ip: fields.ip, loc: fields.loc };
  } catch {
    return null;
  }
}

async function main() {
  fs.mkdirSync(runDir, { recursive: true });
  const directory = new Directory({ cacheFile });
  let source = 'cache';
  try {
    await directory.refresh({ onProgress: (bytes) => process.stderr.write(`\r${bytes} bytes`) });
    source = 'network';
  } catch (error) {
    process.stderr.write(`\nrefresh failed: ${error.message}\n`);
  }
  if (!directory.configs.size) throw new Error('no configs available');
  await directory.preflight(24);
  console.log(`\ndirectory source: ${source}, servers: ${directory.servers.length}`);

  const tcp = directory.servers.filter(
    (server) => /proto\s+tcp/i.test(directory.configFor(server.id) || '') && server.latencyMs != null
  );
  const udp = directory.servers.filter(
    (server) => !/proto\s+tcp/i.test(directory.configFor(server.id) || '') && server.latencyMs != null
  );
  let candidates = [...tcp, ...udp];
  if (process.env.AIVPN_SERVER) {
    const pinned = candidates.find((server) => server.id.includes(process.env.AIVPN_SERVER));
    if (pinned) candidates = [pinned, ...candidates.filter((server) => server.id !== pinned.id)];
  }
  candidates = candidates.slice(0, Number(process.env.AIVPN_LIMIT || 6));
  console.log('candidates:');
  for (const server of candidates) {
    console.log(`  ${server.id} | ${server.country} | ${server.latencyMs} ms`);
  }

  const baseline = await probeExit();
  console.log(`baseline exit ip: ${baseline.ok ? baseline.exit : baseline.reason}`);

  const session = new VpnSession({
    runDir,
    findEngine: async () => (fs.existsSync(ENGINE) ? ENGINE : null),
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  session.on('state', (state) => console.log(`state: ${state.status} ${state.error || ''}`));

  const extra = process.env.AIVPN_EXTRA ? `\n${process.env.AIVPN_EXTRA}\n` : '';
  const guard = new Guard({ storeFile: path.join(runDir, 'guard.json') });
  const attempts = [];
  let success = null;

  for (const server of candidates) {
    console.log(`\nconnecting to ${server.id} — confirm the UAC prompt`);
    const state = await session.connect({
      server,
      config: `${directory.configFor(server.id)}${extra}`,
      isPrivate: false,
      useCredentials: true,
      allowLegacyTls: true
    });
    if (state.status !== 'CONNECTED') {
      attempts.push({ server, status: state.status, error: state.error || null, routed: false });
      if (state.error === 'ELEVATION_CANCELLED') throw new Error('UAC cancelled');
      continue;
    }

    await delay(6000);
    const report = await guard.inspect({
      state: session.snapshot(),
      logFile: session.logFile,
      enginePath: ENGINE
    });
    console.log(`  guard: ${report.level} ${report.checks.map((check) => `${check.id}:${check.level}`).join(' ')}`);
    const probe = await probeExit();
    const trace = probe.ok ? await fetchTrace() : null;
    const speed = probe.ok ? await measureDownload({ warmupMs: 2500, windowMs: 7000 }) : null;
    const record = {
      server,
      status: state.status,
      guard: report,
      probeOk: probe.ok,
      exitIp: probe.ok ? probe.exit : null,
      trace,
      speed,
      routed: Boolean(probe.ok && baseline.ok && probe.exit !== baseline.exit)
    };
    attempts.push(record);
    console.log(`  probe: ${probe.ok ? probe.exit : probe.reason}, trace: ${trace ? `${trace.ip} ${trace.loc}` : 'failed'}`);
    await session.disconnect();
    if (record.routed) {
      success = record;
      break;
    }
  }

  const result = {
    ok: Boolean(success),
    baseline,
    attempts,
    at: new Date().toISOString()
  };
  console.log(JSON.stringify(result, null, 2));
  fs.writeFileSync(resultFile, JSON.stringify(result, null, 2));

  const after = await probeExit();
  console.log(`exit ip after disconnect: ${after.ok ? after.exit : after.reason}`);
  process.exitCode = success ? 0 : 2;
}

// Electron's CLI can retain runtime handles after the session has cleaned up.
// Exit explicitly once the report and post-disconnect probe have been written,
// so a successful live test does not leave a hidden Electron process running.
main()
  .then(() => process.exit(process.exitCode || 0))
  .catch((error) => {
    console.error(`FAILED: ${error.message}`);
    process.exit(1);
  });
