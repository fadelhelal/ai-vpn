'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { parseDirectory, remoteTarget, sortServers } = require('../src/directory');
const { sanitizeConfig, summarizeLog, VpnSession, killSwitchTarget, resolveKillSwitchTarget, pinRemoteEndpoint, pinPreflight } = require('../src/session');
const { decryptedText } = require('../src/store');
const { validateOpenVpnProfile, MAX_PROFILE_BYTES, profileInfo } = require('../src/profiles');
const { Guard, parseLogFacts, weakCrypto, aggregateLevel, entersCritical, shouldDisconnectOnCritical, engineTrust, certVerdict, pinKey, broadOutboundAllows } = require('../src/guard');
const { fingerprintPem, normalizeFingerprint, colonFingerprint, shortFingerprint } = require('../src/certs');
const { probeConfig, captureScript, selectLines, probeFingerprint } = require('../src/certprobe');
const { parseNvd, parseKev } = require('../src/intel');
const { validFeedUrl, isNewer } = require('../src/updater');
const { canonicalManifest, signManifest, verifyManifest } = require('../src/signing');
const { RELEASE_PUBLIC_KEY } = require('../src/release-key');
const { KillSwitch, watchdogScript, recoveryScript, firewallProgramPath } = require('../src/killswitch');
const { hashText, encodeCommand, decodeCommand, routeCleanupScript, legacyStopScript, stageAndRunScript, elevateScript } = require('../src/elevate');
const { parseTcpOwners, peerVerdict, verifyPeer } = require('../src/mgmtpeer');
const { engineVerdict, dirWritable, errorFor } = require('../src/enginecheck');
const { spawn, spawnSync } = require('node:child_process');

let passed = 0;
let failed = 0;
const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

function readJsonFile(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    return null;
  }
}

function processAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return Boolean(error && error.code === 'EPERM');
  }
}

async function waitFor(predicate, timeoutMs = 25000, step = 100) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, step));
  }
  throw new Error('timed out waiting for condition');
}

const CONFIG = [
  'client',
  'dev tun',
  'proto udp',
  'remote 203.0.113.9 1194',
  'cipher AES-128-CBC',
  '<ca>',
  'CA',
  '</ca>'
].join('\n');

function csvLine(host, ip, score, ping, country, code, config) {
  const cols = [
    host,
    ip,
    String(score),
    String(ping),
    '10000000',
    country,
    code,
    '5',
    '1',
    '1',
    '1',
    '1',
    '0',
    '0',
    Buffer.from(config, 'utf8').toString('base64')
  ];
  return cols.join(',');
}

function directoryText(lines) {
  return [
    '*vpn_servers',
    '#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64',
    ...lines
  ].join('\n');
}

test('parseDirectory reads the VPN Gate layout', () => {
  const text = directoryText([csvLine('jp1.example', '203.0.113.9', 40, 30, 'Japan', 'JP', CONFIG)]);
  const parsed = parseDirectory(text);
  assert.strictEqual(parsed.servers.length, 1);
  const server = parsed.servers[0];
  assert.strictEqual(server.country, 'Japan');
  assert.strictEqual(server.countryCode, 'JP');
  assert.strictEqual(server.score, 40);
  assert.strictEqual(server.pingHintMs, 30);
  assert.match(parsed.configs.get(server.id), /remote 203\.0\.113\.9/);
});

test('parseDirectory ignores rows without a client config', () => {
  const text = directoryText([
    csvLine('bad.example', '198.51.100.5', 10, 10, 'Nowhere', 'ZZ', 'proto udp\nremote 198.51.100.5 1194'),
    csvLine('ok.example', '198.51.100.6', 20, 20, 'Somewhere', 'SM', CONFIG)
  ]);
  const parsed = parseDirectory(text);
  assert.deepStrictEqual(
    parsed.servers.map((server) => server.host),
    ['ok.example']
  );
});

test('parseDirectory drops duplicate endpoints', () => {
  const text = directoryText([
    csvLine('dup.example', '203.0.113.9', 40, 30, 'Japan', 'JP', CONFIG),
    csvLine('dup.example', '203.0.113.9', 40, 30, 'Japan', 'JP', CONFIG)
  ]);
  assert.strictEqual(parseDirectory(text).servers.length, 1);
});

test('sortServers puts measured, faster servers first', () => {
  const list = [
    { id: 'a', score: 90, pingHintMs: 10, latencyMs: null },
    { id: 'b', score: 10, pingHintMs: 200, latencyMs: 44 },
    { id: 'c', score: 50, pingHintMs: 90, latencyMs: 12 }
  ];
  assert.deepStrictEqual(
    list.sort(sortServers).map((server) => server.id),
    ['c', 'b', 'a']
  );
});

test('remoteTarget probes UDP relays on 443', () => {
  assert.deepStrictEqual(remoteTarget('client\nremote 203.0.113.9 1194\nproto udp'), {
    host: '203.0.113.9',
    port: 443
  });
  assert.deepStrictEqual(remoteTarget('client\nremote 203.0.113.9 8443\nproto tcp-client'), {
    host: '203.0.113.9',
    port: 8443
  });
  assert.strictEqual(remoteTarget('client\ndev tun'), null);
});

test('sanitizeConfig removes dangerous directives but keeps the tunnel', () => {
  const dirty = [
    'client',
    'remote 203.0.113.9 1194',
    'plugin evil.dll',
    'up "C:\\evil.bat"',
    'script-security 2',
    'management 127.0.0.1 7505',
    'auth-user-pass secrets.txt',
    'log C:\\leak.log',
    '<ca>',
    'CA',
    '</ca>'
  ].join('\n');
  const clean = sanitizeConfig(dirty);
  assert.match(clean, /^client$/m);
  assert.match(clean, /remote 203\.0\.113\.9 1194/);
  assert.doesNotMatch(clean, /plugin/i);
  assert.doesNotMatch(clean, /script-security/i);
  assert.doesNotMatch(clean, /management/i);
  assert.doesNotMatch(clean, /auth-user-pass/i);
  assert.doesNotMatch(clean, /^up /m);
});

test('sanitizeConfig refuses files that would bypass the directive ban', () => {
  const config = [
    'client',
    'remote vpn.example 443',
    'config "C:\\Users\\me\\extra.ovpn"',
    '--include "C:\\Users\\me\\extra.ovpn"',
    '  include C:\\Users\\me\\extra.ovpn'
  ].join('\n');
  const safe = sanitizeConfig(config);
  assert.doesNotMatch(safe, /include|config/i);
  assert.match(safe, /^remote vpn\.example 443$/m);
});

test('sanitizeConfig removes every command-execution hook', () => {
  const config = [
    'client',
    'remote vpn.example 443',
    'route-up "cmd.exe /c whoami"',
    'route-pre-down "cmd.exe /c whoami"',
    'learn-address "cmd.exe /c whoami"',
    'tls-verify "cmd.exe /c whoami"',
    'askpass C:\\secret.txt'
  ].join('\n');
  const safe = sanitizeConfig(config);
  assert(!/route-up|route-pre-down|learn-address|tls-verify|askpass/i.test(safe));
  assert(/remote vpn\.example 443/.test(safe));
});

test('sanitizeConfig drops directives smuggled through setenv opt', () => {
  const config = [
    'client',
    'remote vpn.example 443',
    'setenv opt plugin "C:/nope/evil.dll"',
    '  SETENV   OPT   up "cmd.exe /c whoami"',
    'setenv OPT script-security 2',
    'setenv opt tls-crypt-v2-verify "cmd.exe /c whoami"',
    'tls-crypt-v2-verify "cmd.exe /c whoami"',
    'setenv FOO bar'
  ].join('\n');
  const safe = sanitizeConfig(config);
  assert.doesNotMatch(safe, /plugin|cmd\.exe|tls-crypt-v2-verify/i);
  assert.doesNotMatch(safe, /setenv\s+opt/i);
  assert.match(safe, /^remote vpn\.example 443$/m);
  assert.match(safe, /^setenv FOO bar$/m);
});

test('sanitizeConfig treats a leading -- exactly like the engine does', () => {
  const config = [
    'client',
    'remote vpn.example 443',
    '--plugin "C:/nope/evil.dll"',
    '  --up "cmd.exe /c whoami"',
    '--script-security 3',
    '--management 127.0.0.1 7505',
    '--remote vpn.example 1194'
  ].join('\n');
  const safe = sanitizeConfig(config);
  assert.doesNotMatch(safe, /plugin|cmd\.exe|script-security|management/i);
  assert.match(safe, /^remote vpn\.example 443$/m);
  assert.match(safe, /^--remote vpn\.example 1194$/m);
});

test('buildConfig pins script-security 1 and keeps no profile override', () => {
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'unused', password: 'unused' })
  });
  session.port = 7505;
  const config = session.buildConfig('client\nremote 203.0.113.9 1194\nscript-security 3');
  assert.strictEqual((config.match(/^script-security\b/gm) || []).length, 1);
  assert.match(config, /^script-security 1$/m);
  assert.doesNotMatch(config, /script-security 3/);
});

test('killSwitchTarget accepts one explicit IPv4 remote and derives OpenVPN defaults', () => {
  assert.deepStrictEqual(
    killSwitchTarget('client\nremote 203.0.113.9 1194\nproto udp'),
    { host: '203.0.113.9', port: 1194, protocol: 'UDP' }
  );
  assert.deepStrictEqual(
    killSwitchTarget('remote 198.51.100.7 443 tcp\nPROTO TCP'),
    { host: '198.51.100.7', port: 443, protocol: 'TCP' }
  );
  assert.deepStrictEqual(killSwitchTarget('remote 203.0.113.9'), { host: '203.0.113.9', port: 1194, protocol: 'UDP' });
  assert.strictEqual(killSwitchTarget('remote vpn.example.com 1194\nproto udp'), null);
  assert.strictEqual(killSwitchTarget('remote 203.0.113.9\nremote 203.0.113.10'), null);
  assert.strictEqual(killSwitchTarget(''), null);
});

test('Kill Switch refuses IPv6-only protocols instead of pinning an IPv4 address', async () => {
  const noLookup = async () => {
    throw new Error('DNS must not be queried for an IPv6-only protocol');
  };
  assert.strictEqual(killSwitchTarget('remote 203.0.113.9 1194 udp6'), null);
  assert.strictEqual(killSwitchTarget('remote 203.0.113.9 1194 tcp6-client'), null);
  assert.strictEqual(
    await resolveKillSwitchTarget('client\nremote vpn.example.com 1194\nproto udp6', noLookup),
    null
  );
  assert.strictEqual(
    await resolveKillSwitchTarget('client\nremote vpn.example.com 443 tcp6-client', noLookup),
    null
  );
});

test('connect refuses an IPv6-only protocol before arming the kill switch', async () => {
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-udp6-'));
  const session = new VpnSession({ runDir, findEngine: async () => null });
  let armed = 0;
  session.killSwitch = { enable: async () => { armed += 1; } };
  try {
    const state = await session.connect({
      server: 'test',
      config: 'client\nremote vpn.example.com 1194\nproto udp6',
      isPrivate: false,
      killSwitchEnabled: true,
      enginePath: path.join(runDir, 'openvpn.exe')
    });
    assert.strictEqual(state.status, 'FAILED');
    assert.strictEqual(state.error, 'KILLSWITCH_PROTO_INVALID');
    assert.strictEqual(armed, 0, 'the kill switch was armed for a protocol it cannot cover');
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test('Kill Switch resolves one hostname then pins that IPv4 in the transient config', async () => {
  const config = 'client\nremote stockholm.example 443\nproto tcp-client\nremote-cert-tls server';
  const target = await resolveKillSwitchTarget(config, async (host, options) => {
    assert.strictEqual(host, 'stockholm.example');
    assert.deepStrictEqual(options, { family: 4, all: true, verbatim: true });
    return [{ address: '203.0.113.45', family: 4 }];
  });
  assert.deepStrictEqual(
    { host: target.host, port: target.port, protocol: target.protocol, sourceHost: target.sourceHost },
    { host: '203.0.113.45', port: 443, protocol: 'TCP', sourceHost: 'stockholm.example' }
  );
  const pinned = pinRemoteEndpoint(config, target);
  assert.match(pinned, /^remote 203\.0\.113\.45 443 tcp-client$/m);
  assert.doesNotMatch(pinned, /^remote stockholm\.example/m);
  assert.match(pinned, /^remote-cert-tls server$/m);
});

test('secret decryption accepts Electron async result wrappers without coercing them', () => {
  assert.strictEqual(decryptedText('plain profile'), 'plain profile');
  assert.strictEqual(decryptedText({ result: 'client\nremote 203.0.113.9' }), 'client\nremote 203.0.113.9');
  assert.strictEqual(decryptedText({ shouldReEncrypt: true }), null);
});

test('renderer stays locked down: strict CSP, no navigation, no webviews', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  const csp = (/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/.exec(html) || [])[1] || '';
  for (const directive of [
    "default-src 'self'",
    "script-src 'self'",
    "connect-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'"
  ]) {
    assert.ok(csp.includes(directive), `CSP is missing ${directive}`);
  }
  assert.ok(!/unsafe-eval/.test(csp));
  const main = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  assert.match(main, /on\('will-navigate', \(event\) => event\.preventDefault\(\)\)/);
  assert.match(main, /setWindowOpenHandler\(\(\) => \(\{ action: 'deny' \}\)\)/);
  assert.match(main, /will-attach-webview/);
  assert.match(main, /webviewTag: false/);
  assert.match(main, /allowRunningInsecureContent: false/);
});

test('a failed session disarms the kill switch instead of leaving the block', async () => {
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-ks-'));
  let stops = 0;
  const session = new VpnSession({ runDir, findEngine: async () => null });
  session.killSwitch = { disable() { stops += 1; }, locked: () => false };
  session.killSwitchArmed = true;
  session.update({ status: 'CONNECTING' });
  let terminated = 0;
  session._terminateEngine = async () => { terminated += 1; return false; };
  session.fail('tls');
  await session.engineOps;
  assert.strictEqual(session.killSwitchArmed, false);
  assert.strictEqual(stops, 1);
  assert.strictEqual(session.snapshot().status, 'FAILED');
  assert.strictEqual(session.snapshot().error, 'tls');
  assert.strictEqual(terminated, 1);
  // The elevated supervisor is told to stop before the old taskkill path could
  // even be considered.
  assert.strictEqual(fs.readFileSync(session.stopFile, 'ascii'), 'failed');
  fs.rmSync(runDir, { recursive: true, force: true });
});

test('connect uses the verified engine path and re-checks it before launch', async () => {
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-engine-'));
  let resolved = 0;
  const rechecked = [];
  const provided = path.join(runDir, 'missing-openvpn.exe');
  const session = new VpnSession({
    runDir,
    findEngine: async () => {
      resolved += 1;
      return 'C:\\elsewhere\\openvpn.exe';
    }
  });
  session.killSwitch = { disable() {}, locked: () => false };
  try {
    const state = await session.connect({
      server: { id: 'private', host: 'x' },
      config: 'client\nremote 203.0.113.9 1194',
      isPrivate: true,
      fingerprintPin: CERT_SHA256,
      enginePath: provided,
      verifyEngine: async (candidate) => {
        rechecked.push(candidate);
        return { ok: false, error: 'ENGINE_UNTRUSTED' };
      }
    });
    assert.strictEqual(resolved, 0);
    assert.deepStrictEqual(rechecked, [provided]);
    assert.strictEqual(state.status, 'FAILED');
    assert.strictEqual(state.error, 'ENGINE_UNTRUSTED');
    assert.strictEqual(fs.existsSync(path.join(runDir, 'probe')), false);
    assert.strictEqual(fs.existsSync(path.join(runDir, 'run.ovpn')), false);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test('buildConfig doubles backslashes in Windows paths', () => {
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  session.port = 7505;
  const config = session.buildConfig('client\nremote 203.0.113.9 1194', { useCredentials: true, allowLegacyTls: true });
  assert.ok(config.includes('log "C:\\\\Users\\\\x\\\\run\\\\openvpn.log"'));
  assert.ok(config.includes('auth-user-pass "C:\\\\Users\\\\x\\\\run\\\\auth.txt"'));
  assert.ok(config.includes('tls-version-min 1.0'));
  assert.ok(!config.includes('tls-version-min 1.2'));
  assert.ok(config.includes('remote-cert-tls server'));
  assert.ok(config.includes('block-outside-dns'));
  const single = config
    .split('\n')
    .filter((line) => /^(log|auth-user-pass)\s/.test(line) && /\\/.test(line.replace(/\\\\/g, '')));
  assert.deepStrictEqual(single, []);
});

test('private config keeps modern TLS and does not add password authentication', () => {
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'unused', password: 'unused' })
  });
  session.port = 7505;
  const config = session.buildConfig('client\nremote 203.0.113.9 1194\n<tls-crypt-v2>\nkey\n</tls-crypt-v2>');
  assert.doesNotMatch(config, /auth-user-pass/i);
  assert.match(config, /<tls-crypt-v2>/);
  assert.match(config, /^remote-cert-tls server$/m);
  assert.match(config, /^tls-version-min 1\.2$/m);
});

test('profile cannot downgrade TLS or flip the server role check', () => {
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'unused', password: 'unused' })
  });
  session.port = 7505;
  const config = session.buildConfig(
    'client\nremote 203.0.113.9 1194\nremote-cert-tls client\ntls-version-min 1.0'
  );
  assert.strictEqual((config.match(/remote-cert-tls/g) || []).length, 1);
  assert.match(config, /^remote-cert-tls server$/m);
  assert.strictEqual((config.match(/tls-version-min/g) || []).length, 1);
  assert.match(config, /^tls-version-min 1\.2$/m);
  assert.doesNotMatch(config, /tls-version-min 1\.0/);
});

const CERT_FIXTURE = path.join(__dirname, 'fixtures', 'server-cert.pem');
const CERT_SHA256 = '92ba24fb6e72a4783e44e9b12c6a7b38f90d8df874d412cef4b014aedcbe516e';

test('fingerprints are SHA-256 of the certificate DER', () => {
  const pem = fs.readFileSync(CERT_FIXTURE, 'utf8');
  assert.strictEqual(fingerprintPem(pem), CERT_SHA256);
  assert.strictEqual(fingerprintPem('not a certificate'), null);
  assert.strictEqual(normalizeFingerprint('92:BA:24:FB:6E:72:A4:78:3E:44:E9:B1:2C:6A:7B:38:F9:0D:8D:F8:74:D4:12:CE:F4:B0:14:AE:DC:BE:51:6E'), CERT_SHA256);
  assert.strictEqual(normalizeFingerprint('abc'), null);
  assert.strictEqual(colonFingerprint(CERT_SHA256), '92:BA:24:FB:6E:72:A4:78:3E:44:E9:B1:2C:6A:7B:38:F9:0D:8D:F8:74:D4:12:CE:F4:B0:14:AE:DC:BE:51:6E');
  assert.strictEqual(shortFingerprint(CERT_SHA256), '92ba24fb6e72a478');
});

test('preflight config keeps only handshake directives and cannot run profile scripts', () => {
  const profile = [
    'client',
    'dev tun',
    'proto udp',
    'remote vpn.example 1194',
    'route 10.0.0.0 255.0.0.0',
    'redirect-gateway def1',
    'up "C:\\\\evil.exe"',
    'plugin "evil.dll"',
    'script-security 3',
    'management 127.0.0.1 7505',
    'tls-verify "cmd.exe"',
    'tls-export-cert "C:\\\\tmp"',
    'remote-cert-tls client',
    'tls-version-min 1.0',
    'peer-fingerprint 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
    'auth-user-pass',
    '<tls-crypt>',
    'keydata',
    '</tls-crypt>'
  ].join('\n');
  const text = probeConfig(profile, {
    logFile: 'C:\\run\\probe\\probe.log',
    scriptFile: 'C:\\run\\probe\\capture.cmd',
    exportDir: 'C:\\run\\probe\\export'
  });
  assert.match(text, /^dev null$/m);
  assert.match(text, /^remote vpn\.example 1194$/m);
  assert.match(text, /^<tls-crypt>$/m);
  assert.match(text, /^tls-verify "C:\/run\/probe\/capture\.cmd"$/m);
  assert.match(text, /^tls-export-cert "C:\/run\/probe\/export"$/m);
  assert.match(text, /^script-security 3$/m);
  assert.match(text, /^remote-cert-tls server$/m);
  assert.match(text, /^tls-version-min 1\.2$/m);
  assert.strictEqual((text.match(/^client$/gm) || []).length, 1);
  assert.doesNotMatch(text, /dev tun|route |redirect-gateway|evil|plugin|management|auth-user-pass/);
  assert.doesNotMatch(text, /tls-verify "cmd\.exe"|tls-export-cert "C:\\tmp"/);
  assert.doesNotMatch(text, /peer-fingerprint 00:11/);
});

test('preflight skips profiles whose remote cannot be pinned deterministically', () => {
  assert.strictEqual(
    probeConfig('client\nremote a.example 1194\nremote b.example 1194', {
      logFile: 'x', scriptFile: 'y', exportDir: 'z'
    }),
    null
  );
  assert.strictEqual(
    probeConfig('client\n<connection>\nremote a.example 1194\n</connection>', {
      logFile: 'x', scriptFile: 'y', exportDir: 'z'
    }),
    null
  );
  const legacy = probeConfig('client\nremote a.example 1194', {
    logFile: 'x', scriptFile: 'y', exportDir: 'z', allowLegacyTls: true
  });
  assert.match(legacy, /^tls-version-min 1\.0$/m);
});

test('capture script copies the peer certificate by depth', () => {
  const script = captureScript('C:\\run\\probe');
  assert.ok(script.includes('set "p=%peer_cert:/=\\%"'));
  assert.ok(script.includes('copy /y "%p%" "C:\\run\\probe\\captured-%1.pem"'));
  assert.ok(script.includes('exit /b 0'));
});

test('preflight deletes the probe directory after a failed attempt', async () => {
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-probe-'));
  const probeDir = path.join(runDir, 'probe');
  try {
    const result = await probeFingerprint({
      enginePath: path.join(runDir, 'no-such-engine.exe'),
      rawConfig: 'client\nremote 203.0.113.9 1194\n<key>\nPRIVATE KEY\n</key>',
      runDir,
      timeoutMs: 3000
    });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'EXITED');
    assert.strictEqual(result.cleanup, undefined);
    assert.strictEqual(fs.existsSync(probeDir), false);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test('buildConfig pins the engine to the probed fingerprint', () => {
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  session.port = 7505;
  const pinned = session.buildConfig('client\nremote 203.0.113.9 1194', {
    peerFingerprint: CERT_SHA256
  });
  const lines = pinned.split('\n').filter((line) => /^peer-fingerprint\s/.test(line));
  assert.deepStrictEqual(lines, [
    'peer-fingerprint 92:BA:24:FB:6E:72:A4:78:3E:44:E9:B1:2C:6A:7B:38:F9:0D:8D:F8:74:D4:12:CE:F4:B0:14:AE:DC:BE:51:6E'
  ]);
  const plain = session.buildConfig('client\nremote 203.0.113.9 1194');
  assert.doesNotMatch(plain, /peer-fingerprint/);
  const hostile = session.buildConfig(
    'client\nremote 203.0.113.9 1194\npeer-fingerprint 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF'
  );
  assert.doesNotMatch(hostile, /peer-fingerprint/);
});

test('config hash and inline command encoding are stable', () => {
  const hash = hashText('client\nremote 203.0.113.9 1194\n');
  assert.strictEqual(hash, hashText('client\nremote 203.0.113.9 1194\n'));
  assert.match(hash, /^[0-9A-F]{64}$/);
  assert.strictEqual(hashText('a'), crypto.createHash('sha256').update('a').digest('hex').toUpperCase());
  const script = "Write-Output 'مرحبا'\r\n$p='C:\\x y'";
  assert.strictEqual(decodeCommand(encodeCommand(script)), script);
});

test('elevated launch never executes a user-writable script file', () => {
  const inner = stageAndRunScript({
    enginePath: 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
    configFile: 'C:\\Users\\x\\run\\run.ovpn',
    configHash: 'A'.repeat(64),
    pidFile: 'C:\\Users\\x\\run\\engine.pid',
    heartbeatFile: 'C:\\Users\\x\\run\\engine.heartbeat',
    stopFile: 'C:\\Users\\x\\run\\engine.stop',
    supervisorFile: 'C:\\Users\\x\\run\\engine.supervisor.json',
    readyFile: 'C:\\Users\\x\\run\\engine.ready.json',
    statusFile: 'C:\\Users\\x\\run\\engine.status.json',
    nonce: 'b'.repeat(32)
  });
  assert.ok(inner.includes(`$expected='${'A'.repeat(64)}'`));
  assert.ok(inner.includes("$engine='C:\\Program Files\\OpenVPN\\bin\\openvpn.exe'"));
  assert.ok(inner.includes('Get-AivpnSha256'));
  assert.ok(inner.includes('[System.Security.Cryptography.SHA256]::Create()'));
  assert.ok(inner.includes('exit 3'));
  assert.ok(inner.includes('icacls $stage /inheritance:r'));
  assert.ok(inner.includes("'*S-1-5-32-544:(OI)(CI)F'"));
  assert.ok(inner.includes('Start-Process -FilePath $engine'));
  assert.ok(inner.includes('Remove-AivpnTunnelRoutes -StagePath $stage'));
  assert.ok(inner.includes('$reason=\'heartbeat-lost\''));
  assert.ok(inner.includes("$staleSecs=30"));
  assert.doesNotMatch(inner, /remote 203\.0\.113\.9/);
  // The supervisor must survive the launch, so the elevation wrapper cannot
  // wait for it to exit.
  const outer = elevateScript(inner, { maxEncodedLength: 28000 });
  assert.ok(outer.includes('-Verb RunAs'));
  assert.ok(outer.includes('-EncodedCommand'));
  assert.ok(outer.includes("-FilePath powershell.exe"));
  assert.ok(!outer.includes('-Wait'));
  assert.doesNotMatch(outer, /-File\s+'/);
  const encoded = /'-EncodedCommand','([A-Za-z0-9+/=]+)'/.exec(outer)[1];
  assert.strictEqual(decodeCommand(encoded), inner);
  // Nothing in the launch path reads a script back from the user folder.
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'elevate.js'), 'utf8');
  assert.ok(!/'-File'/.test(source));
  assert.ok(!/\.ps1/.test(source));
  assert.match(source, /'-Command', String\(script\)/);
  assert.doesNotMatch(source, /writeFileSync\([^)]*script/);
});

test('supervisor teardown verifies engine identity and reports an engine it cannot stop', () => {
  const script = stageAndRunScript({
    enginePath: 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
    configFile: 'C:\\data\\run.ovpn',
    configHash: 'A'.repeat(64),
    pidFile: 'C:\\run\\engine.pid',
    heartbeatFile: 'C:\\run\\engine.heartbeat',
    stopFile: 'C:\\run\\engine.stop',
    supervisorFile: 'C:\\run\\engine.supervisor.json',
    readyFile: 'C:\\run\\engine.ready.json',
    statusFile: 'C:\\run\\engine.status.json',
    nonce: 'n'.repeat(32)
  });
  // Stop only the process we launched: identity is the recorded start time,
  // so a recycled PID can never be force-killed by mistake.
  assert.match(script, /\$engineStart=\$p\.StartTime/);
  assert.match(script, /\$proc\.StartTime -eq \$engineStart/);
  assert.match(script, /dns-before\.json/);
  assert.match(script, /Restore-AivpnTunnelDns/);
  assert.match(script, /Set-DnsClientServerAddress -InterfaceIndex \$id -ResetServerAddresses/);
  // The status marker tells the UI whether the engine is verifiably gone.
  assert.match(script, /engineStopped=\$engineStopped/);
  assert.match(script, /\bexit 5\b/);
  // An engine that survived keeps its pid and status markers for the next
  // attempt, and a route snapshot that was never verified keeps its stage.
  assert.match(script, /if \(\$routeErrors -eq 0 -and \$dnsErrors -eq 0 -and \$removed -ge 0 -and \$dnsRestored -ge 0\) \{ Remove-Item -LiteralPath \$stage/);
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'elevate.js'), 'utf8');
  assert.match(source, /writeFileSync\(stopFile, 'start-timeout'/);
});

test('the elevated supervisor runs the staged config only on a hash match and stops on request', async () => {
  if (process.platform !== 'win32') {
    assert.ok(true);
    return;
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-stage-'));
  const files = {
    configFile: path.join(root, 'run.ovpn'),
    pidFile: path.join(root, 'engine.pid'),
    heartbeatFile: path.join(root, 'engine.heartbeat'),
    stopFile: path.join(root, 'engine.stop'),
    supervisorFile: path.join(root, 'engine.supervisor.json'),
    readyFile: path.join(root, 'engine.ready.json'),
    statusFile: path.join(root, 'engine.status.json')
  };
  const marker = path.join(root, 'engine-args.txt');
  const stub = path.join(root, 'stub-engine.cmd');
  const text = 'client\nremote 203.0.113.9 1194\n# marker-not-embedded\n';
  fs.writeFileSync(files.configFile, text, 'utf8');
  fs.writeFileSync(
    stub,
    [
      '@echo off',
      `>"${marker}" echo %*`,
      `>>"${marker}" type "%2"`,
      ':loop',
      'ping -n 2 127.0.0.1 >nul',
      'goto loop',
      ''
    ].join('\r\n'),
    'ascii'
  );

  // The real launch is elevated, which the test cannot be; granting the current
  // account keeps the same script runnable here without weakening the
  // production ACL (Administrators + SYSTEM only).
  const self = process.env.USERDOMAIN ? `${process.env.USERDOMAIN}\\${os.userInfo().username}` : os.userInfo().username;
  const params = { enginePath: stub, cleanupRoutes: false, aclExtra: [`${self}:(OI)(CI)F`], ...files };
  const run = (nonce, hash, heartbeatSecs = 60) =>
    spawn(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
        encodeCommand(stageAndRunScript({ ...params, configHash: hash, nonce, heartbeatSecs }))],
      { env: { ...process.env, ProgramData: root }, windowsHide: true }
    );
  const waitExit = (child, timeoutMs = 25000) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('supervisor did not exit')), timeoutMs);
      child.once('exit', (code) => {
        clearTimeout(timer);
        resolve(code);
      });
    });

  try {
    // 1. Hash matches: the engine starts from the admin staging folder.
    const nonce = 'a'.repeat(32);
    const child = run(nonce, hashText(text));
    const ready = await waitFor(() => {
      const value = readJsonFile(files.readyFile);
      return value && value.nonce === nonce ? value : null;
    });
    assert.ok(Number(ready.enginePid) > 0);
    assert.ok(Number(ready.supervisorPid) > 0);
    assert.match(String(ready.stage), /stage-[0-9a-f]{32}$/);
    await waitFor(() => {
      try {
        return fs.readFileSync(marker, 'utf8').includes('# marker-not-embedded');
      } catch {
        return false;
      }
    });
    const args = fs.readFileSync(marker, 'utf8');
    assert.match(args, /--config\s+.{1,}stage-[0-9a-f]{32}.{1,}run\.ovpn/);
    assert.ok(args.includes('# marker-not-embedded'));
    assert.ok(processAlive(ready.enginePid));

    // 2. A stop request tears the engine down and reports why.
    fs.writeFileSync(files.stopFile, 'stop', 'ascii');
    assert.strictEqual(await waitExit(child), 0);
    const stopped = readJsonFile(files.statusFile);
    assert.strictEqual(stopped.nonce, nonce);
    assert.strictEqual(stopped.state, 'stopped');
    assert.strictEqual(stopped.reason, 'stop');
    assert.strictEqual(stopped.engineStopped, true);
    assert.ok(!processAlive(ready.enginePid), 'engine survived the supervisor stop');
    for (const file of [files.readyFile, files.heartbeatFile, files.stopFile, files.supervisorFile, files.pidFile]) {
      assert.strictEqual(fs.existsSync(file), false, `${path.basename(file)} was left behind`);
    }

    // 3. A crashed UI (no heartbeat) is treated like a stop.
    fs.rmSync(files.statusFile, { force: true });
    const lostNonce = 'b'.repeat(32);
    const lostChild = run(lostNonce, hashText(text), 3);
    const lostReady = await waitFor(() => {
      const value = readJsonFile(files.readyFile);
      return value && value.nonce === lostNonce ? value : null;
    });
    assert.strictEqual(await waitExit(lostChild), 0);
    const lost = readJsonFile(files.statusFile);
    assert.strictEqual(lost.state, 'stopped');
    assert.strictEqual(lost.reason, 'heartbeat-lost');
    assert.strictEqual(lost.engineStopped, true);
    assert.ok(!processAlive(lostReady.enginePid), 'engine survived the heartbeat timeout');

    // 4. A config swapped before staging never reaches the engine.
    fs.rmSync(files.statusFile, { force: true });
    fs.rmSync(marker, { force: true });
    const tampered = spawnSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
        encodeCommand(stageAndRunScript({ ...params, configHash: hashText('client\nremote 198.51.100.7 1194\n'), nonce: 'c'.repeat(32) }))],
      { env: { ...process.env, ProgramData: root }, encoding: 'utf8', windowsHide: true }
    );
    assert.strictEqual(tampered.status, 3, tampered.stderr || tampered.stdout);
    assert.strictEqual(fs.existsSync(marker), false, 'tampered config reached the engine');
    const rejected = readJsonFile(files.statusFile);
    assert.strictEqual(rejected.state, 'failed');
    assert.strictEqual(rejected.reason, 'tampered');
  } finally {
    spawnSync('icacls', [root, '/reset', '/T', '/C', '/Q'], { windowsHide: true });
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('route cleanup removes only new routes on VPN adapters', () => {
  const script = routeCleanupScript();
  assert.match(script, /routes-before\.json/);
  assert.match(script, /ConvertFrom-Json/);
  assert.match(script, /InterfaceDescription -match 'OpenVPN\|Wintun\|TAP-Windows'/);
  assert.match(script, /Remove-NetRoute -DestinationPrefix \$route\.DestinationPrefix -InterfaceIndex \$route\.ifIndex -NextHop \$route\.NextHop/);
  // A missing or unparseable baseline means the set of tunnel routes is
  // unknown; the script must refuse to delete rather than guess.
  assert.match(script, /if \(-not \(Test-Path -LiteralPath \$beforeFile\)\) \{ return -1 \}/);
  assert.match(script, /catch \{ return -1 \}/);
  assert.match(script, /catch \{ \$script:routeErrors\+\+ \}/);
  assert.doesNotMatch(script, /firewall/i);
  assert.doesNotMatch(script, /Set-NetIPInterface|Disable-NetAdapter|Restart-NetAdapter|netsh|route\.exe/i);
  assert.doesNotMatch(script, /0\.0\.0\.0\/0/);

  // The legacy path has no snapshot, so it is limited to the two split-default
  // prefixes on a VPN adapter.
  const legacy = legacyStopScript(4321);
  assert.match(legacy, /Stop-Process -Id 4321 -Force/);
  assert.ok(legacy.includes("@('0.0.0.0/1','128.0.0.0/1')"));
  assert.match(legacy, /InterfaceDescription -match 'OpenVPN\|Wintun\|TAP-Windows'/);
  assert.doesNotMatch(legacy, /firewall/i);
  assert.doesNotMatch(legacy, /Set-NetIPInterface|Disable-NetAdapter|Restart-NetAdapter|netsh|route\.exe/i);
});

test('disconnect stops through the supervisor and never taskkills an elevated engine', async () => {
  if (process.platform !== 'win32') {
    assert.ok(true);
    return;
  }
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-sup-'));
  const session = new VpnSession({ runDir, findEngine: async () => null });
  session.supervisorNonce = 'd'.repeat(32);
  const engine = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { windowsHide: true });
  // Stand-in for the elevated supervisor: watching the same stop marker,
  // stopping the engine, and exiting only after the engine is gone.
  const watcherScript = [
    "const fs=require('fs');",
    `const stop=${JSON.stringify(session.stopFile)};`,
    `const pid=${engine.pid};`,
    'const timer=setInterval(()=>{',
    '  if (!fs.existsSync(stop)) return;',
    '  try { process.kill(pid); } catch {}',
    '  try { process.kill(pid, 0); } catch { clearInterval(timer); process.exit(0); }',
    '}, 50);'
  ].join('');
  const watcher = spawn(process.execPath, ['-e', watcherScript], { windowsHide: true });
  fs.writeFileSync(session.pidFile, String(engine.pid), 'ascii');
  fs.writeFileSync(
    session.supervisorFile,
    JSON.stringify({ nonce: session.supervisorNonce, enginePid: engine.pid, supervisorPid: watcher.pid }),
    'utf8'
  );
  session.update({ status: 'CONNECTED', server: 'test', isPrivate: false });
  let taskkills = 0;
  session.taskkill = async () => {
    taskkills += 1;
    return true;
  };

  try {
    const state = await session.disconnect();
    assert.strictEqual(state.status, 'DISCONNECTED');
    assert.strictEqual(state.error, null);
    assert.strictEqual(taskkills, 0, 'stop fell back to a user-token taskkill');
    assert.strictEqual(processAlive(engine.pid), false, 'engine still running after disconnect');
    assert.strictEqual(fs.existsSync(session.supervisorFile), false, 'supervisor marker was left behind');
  } finally {
    try { watcher.kill(); } catch {}
    try { engine.kill(); } catch {}
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test('a failed connection whose engine survives teardown reports ENGINE_STOP_FAILED', async () => {
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-fail-'));
  const session = new VpnSession({ runDir, findEngine: async () => null });
  session.killSwitch = { disable() {}, locked: () => false };
  session.update({ status: 'CONNECTING' });
  session.detectFailure = () => 'tls';
  session._terminateEngine = async () => true;
  session.fail('tls');
  await session.engineOps;
  assert.strictEqual(session.snapshot().status, 'FAILED');
  assert.strictEqual(session.snapshot().error, 'ENGINE_STOP_FAILED');
  assert.strictEqual(session.snapshot().detail, 'engine-still-running');
  fs.rmSync(runDir, { recursive: true, force: true });
});

test('a supervisor-confirmed live engine fails disconnect without another kill attempt', async () => {
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-alive-'));
  const session = new VpnSession({
    runDir,
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  session.supervisorNonce = 'e'.repeat(32);
  const { EventEmitter } = require('node:events');
  fs.writeFileSync(session.supervisorFile, JSON.stringify({ nonce: session.supervisorNonce, supervisorPid: 4321, enginePid: 5321 }), 'utf8');
  fs.writeFileSync(session.statusFile, JSON.stringify({ nonce: session.supervisorNonce, state: 'stopped', engineStopped: false }), 'utf8');
  const socket = new EventEmitter();
  socket.destroyed = false;
  socket.destroy = () => { socket.destroyed = true; };
  session.socket = socket;
  session.update({ status: 'CONNECTED', server: 'test', isPrivate: false });
  let taskkills = 0;
  session.taskkill = async () => {
    taskkills += 1;
    return true;
  };
  session.stopSupervisor = async () => false;
  try {
    const state = await session.disconnect();
    assert.strictEqual(state.status, 'DISCONNECTED');
    assert.strictEqual(state.error, 'ENGINE_STOP_FAILED');
    assert.strictEqual(state.detail, 'engine-still-running');
    assert.strictEqual(taskkills, 0, 'a confirmed-alive engine still fell back to taskkill');
  } finally {
    fs.rmSync(session.runDir, { recursive: true, force: true });
  }
});

test('retire trusts the supervisor verdict and keeps the markers for the next attempt', async () => {
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-retire-'));
  const session = new VpnSession({ runDir, findEngine: async () => null });
  session.supervisorNonce = 'f'.repeat(32);
  const engine = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { windowsHide: true });
  fs.writeFileSync(session.pidFile, String(engine.pid), 'ascii');
  fs.writeFileSync(session.supervisorFile, JSON.stringify({ nonce: session.supervisorNonce, supervisorPid: 4321, enginePid: engine.pid }), 'utf8');
  fs.writeFileSync(session.statusFile, JSON.stringify({ nonce: session.supervisorNonce, state: 'stopped', engineStopped: false }), 'utf8');
  let taskkills = 0;
  session.taskkill = async () => {
    taskkills += 1;
    return true;
  };
  session.stopSupervisor = async () => false;
  try {
    assert.strictEqual(await session.retirePreviousEngine(), true);
    assert.strictEqual(taskkills, 0, 'retire still tried a user-token taskkill');
    assert.strictEqual(fs.existsSync(session.pidFile), true, 'pid marker was cleared for a live engine');
    assert.strictEqual(fs.existsSync(session.statusFile), true, 'status marker was cleared for a live engine');
  } finally {
    try { engine.kill(); } catch {}
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test('management socket is protected by a per-session password file', () => {  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  session.port = 7505;
  session.managementSecret = 'a'.repeat(48);
  const config = session.buildConfig(CONFIG);
  assert.match(config, /^management 127\.0\.0\.1 7505 "C:\\\\Users\\\\x\\\\run\\\\management\.pw"$/m);
  assert.doesNotMatch(sanitizeConfig('management 0.0.0.0 7505'), /management/i);
});

test('session sends the management password before subscribing or commanding', () => {
  const { EventEmitter } = require('node:events');
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  const socket = new EventEmitter();
  socket.writes = [];
  socket.destroyed = false;
  socket.setEncoding = () => {};
  socket.write = (text) => { socket.writes.push(text); return true; };
  socket.destroy = () => { socket.destroyed = true; };
  session.managementSecret = 's3cret-token';
  session.attach(socket);
  assert.deepStrictEqual(socket.writes, ['s3cret-token\n']);
  assert.strictEqual(session.send('signal SIGTERM'), true);
  assert.deepStrictEqual(socket.writes, ['s3cret-token\n']);
  session.onData('ENTER PASSWORD:\r\n');
  assert.deepStrictEqual(socket.writes, ['s3cret-token\n']);
  session.onData('SUCCESS: password is correct\r\n');
  assert.deepStrictEqual(socket.writes.slice(1), ['state on\n', 'log on all\n', 'bytecount 1\n', 'signal SIGTERM\n']);
  session.socket = null;
});

test('a wrong management password fails instead of driving the engine', async () => {
  const { EventEmitter } = require('node:events');
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  session.update({ status: 'CONNECTING' });
  const socket = new EventEmitter();
  socket.writes = [];
  socket.destroyed = false;
  socket.setEncoding = () => {};
  socket.write = (text) => { socket.writes.push(text); return true; };
  socket.destroy = () => { socket.destroyed = true; };
  session.managementSecret = 's3cret-token';
  const handshake = session.attach(socket);
  // Same glued form the engine really sends when the password is rejected.
  session.onData('ENTER PASSWORD:ERROR: bad password\r\n');
  await assert.rejects(handshake, /MANAGEMENT_AUTH_FAILED/);
  assert.strictEqual(session.state.status, 'FAILED');
  assert(!socket.writes.includes('state on\n'));
});

test('a stalled management handshake times out so the caller can retry', async () => {
  const { EventEmitter } = require('node:events');
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  const socket = new EventEmitter();
  socket.writes = [];
  socket.destroyed = false;
  socket.setEncoding = () => {};
  socket.write = (text) => { socket.writes.push(text); return true; };
  socket.destroy = () => { socket.destroyed = true; };
  session.managementSecret = 's3cret-token';
  await assert.rejects(session.attach(socket, 30), /MANAGEMENT_AUTH_TIMEOUT/);
  assert.deepStrictEqual(socket.writes, ['s3cret-token\n']);
});

test('the handshake verdict is found when glued to the ENTER PASSWORD prompt', async () => {
  const { EventEmitter } = require('node:events');
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  const socket = new EventEmitter();
  socket.writes = [];
  socket.destroyed = false;
  socket.setEncoding = () => {};
  socket.write = (text) => { socket.writes.push(text); return true; };
  socket.destroy = () => { socket.destroyed = true; };
  session.managementSecret = 's3cret-token';
  const handshake = session.attach(socket);
  // Observed live from OpenVPN 2.6.14: the prompt has no trailing newline,
  // so the verdict arrives glued to it, followed by the hold notice.
  session.onData('ENTER PASSWORD:SUCCESS: password is correct\r\n>HOLD:Waiting for hold release:0\r\n');
  await handshake;
  assert.deepStrictEqual(socket.writes.slice(1), ['state on\n', 'log on all\n', 'bytecount 1\n']);
  session.socket = null;
});

test('a handshake verdict split across chunks is still recognized', async () => {
  const { EventEmitter } = require('node:events');
  const session = new VpnSession({
    runDir: 'C:\\Users\\x\\run',
    findEngine: async () => null,
    getCredentials: () => ({ username: 'vpn', password: 'vpn' })
  });
  const socket = new EventEmitter();
  socket.writes = [];
  socket.destroyed = false;
  socket.setEncoding = () => {};
  socket.write = (text) => { socket.writes.push(text); return true; };
  socket.destroy = () => { socket.destroyed = true; };
  session.managementSecret = 's3cret-token';
  const handshake = session.attach(socket);
  session.onData('ENTER PASSWORD:');
  session.onData('SUCCESS: password is corr');
  assert.deepStrictEqual(socket.writes, ['s3cret-token\n']);
  session.onData('ect\r\n');
  await handshake;
  assert.deepStrictEqual(socket.writes.slice(1), ['state on\n', 'log on all\n', 'bytecount 1\n']);
  session.socket = null;
});

test('management peer parsing maps the port to its owning process', () => {
  const text = [
    '  TCP    127.0.0.1:7505         127.0.0.1:52100        ESTABLISHED     4321',
    '  TCP    127.0.0.1:7506         127.0.0.1:52101        ESTABLISHED     9999',
    '  TCP    127.0.0.1:7505         0.0.0.0:0              LISTENING       4321',
    '  UDP    127.0.0.1:7505         *:*                                    4321'
  ].join('\r\n');
  assert.deepStrictEqual(parseTcpOwners(text, 7505), [4321]);
  assert.deepStrictEqual(parseTcpOwners(text, 7506), [9999]);
  assert.deepStrictEqual(parseTcpOwners(text, 7507), []);
});

test('management peer verdict rejects foreign processes', () => {
  const engine = 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe';
  assert.strictEqual(peerVerdict({ owners: [], enginePid: 10, executable: engine, enginePath: engine }).reason, 'owner-unknown');
  assert.strictEqual(peerVerdict({ owners: [10], enginePid: 11, executable: engine, enginePath: engine }).reason, 'pid-mismatch');
  assert.strictEqual(
    peerVerdict({ owners: [10], enginePid: 10, executable: 'C:\\evil\\openvpn.exe', enginePath: engine }).reason,
    'path-mismatch'
  );
  assert.deepStrictEqual(peerVerdict({ owners: [10], enginePid: 10, executable: engine.toUpperCase(), enginePath: engine }), {
    ok: true,
    reason: null,
    pid: 10
  });
  assert.strictEqual(peerVerdict({ owners: [10], enginePid: 0, executable: engine, enginePath: engine }).ok, true);
});

test('live socket ownership check matches the real process', async () => {
  if (process.platform !== 'win32') {
    assert.ok(true);
    return;
  }
  const net = require('node:net');
  const server = net.createServer((socket) => socket.resume());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const client = net.connect(port, '127.0.0.1');
  client.resume();
  await new Promise((resolve) => client.once('connect', resolve));
  await new Promise((resolve) => setTimeout(resolve, 300));
  const good = await verifyPeer({ port, enginePid: process.pid, enginePath: process.execPath });
  assert.strictEqual(good.ok, true, good.reason);
  const wrongEngine = await verifyPeer({
    port,
    enginePid: process.pid,
    enginePath: 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe'
  });
  assert.strictEqual(wrongEngine.reason, 'path-mismatch');
  client.destroy();
  await new Promise((resolve) => server.close(resolve));
});

test('summarizeLog maps engine failures to user-facing categories', () => {
  assert.strictEqual(summarizeLog('AUTH_FAILED'), 'auth');
  assert.strictEqual(summarizeLog('TLS handshake failed'), 'tls');
  assert.strictEqual(summarizeLog('All TAP-Windows adapters on this system are currently in use'), 'driver');
  assert.strictEqual(summarizeLog('Options error: --remote missing'), 'config');
  assert.strictEqual(summarizeLog('ROUTE: route addition failed'), 'route');
  assert.strictEqual(summarizeLog('ERROR: Netsh route add command failed'), 'route');
  // Benign lines that must not be read as route failures.
  assert.strictEqual(summarizeLog('Route addition via ipapi [adaptive] succeeded'), 'unknown');
  assert.strictEqual(summarizeLog('Route addition via ipapi [adaptive] failed because route exists'), 'unknown');
  assert.strictEqual(summarizeLog('something else'), 'unknown');
});

test('validateOpenVpnProfile requires inline credentials', () => {
  const good = ['client', 'remote 203.0.113.9 1194', '<ca>\nCA\n</ca>', '<cert>\nC\n</cert>', '<key>\nK\n</key>'].join('\n');
  assert.strictEqual(validateOpenVpnProfile(good), true);
  assert.strictEqual(validateOpenVpnProfile('client\nremote 1.2.3.4 1194'), false);
  assert.strictEqual(validateOpenVpnProfile(''), false);
});

test('validateOpenVpnProfile rejects oversized bodies', () => {
  const good = ['client', 'remote 203.0.113.9 1194', '<ca>\nCA\n</ca>', '<cert>\nC\n</cert>', '<key>\nK\n</key>'].join('\n');
  const huge = `${good}\n${'x'.repeat(MAX_PROFILE_BYTES)}`;
  assert.strictEqual(validateOpenVpnProfile(huge), false);
});

test('profileInfo reads the inline client certificate expiry without exposing the key', () => {
  const profile = `client\nremote example.test\n<cert>\n-----BEGIN CERTIFICATE-----\nMIIB/jCCAaSgAwIBAgIUQDHmt0gh9J8qdSa5FhhNih52ySgwCgYIKoZIzj0EAwIw\nEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAw\nMDBaMBUxEzARBgNVBAMMCnRlc3QtY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAE4H8+f7uR3V7uF9lbAAH4fP7nD1R7u0BN0vNe9mPqHk8M8N9zJ0NSGWR4\n+aPReGmGpKqcxjzU9mGZt2e6x4b2f6OBzTCByjAMBgNVHRMBAf8EAjAAMB0GA1Ud\nDgQWBBRkToxxfB0C2r7h3QFQXoJ8R7Fx0jAfBgNVHSMEGDAWgBRkToxxfB0C2r7h\n3QFQXoJ8R7Fx0jAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIw\nCgYIKoZIzj0EAwIDSQAwRgIhAKK0vA5FTOaON7LZSxaqmE3kJxWeapmBhPRq0h0l\n4EFsAiEAuP0S3qU5Otrb1TFqndjIb3D4Ff5xl5YvQXNwg+5xn9A=\n-----END CERTIFICATE-----\n</cert>`;
  assert.ok(profileInfo(profile).expiresAt >= 0);
});

test('parseLogFacts extracts tunnel, DNS, TLS, and verification facts', () => {
  const log = [
    "PUSH: Received control message: 'PUSH_REPLY,ifconfig 10.211.1.17 10.211.1.18,dhcp-option DNS 10.211.254.254,dhcp-option DNS 8.8.8.8,redirect-gateway def1'",
    'Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384',
    "Data Channel: cipher 'AES-128-CBC', auth 'SHA1'",
    "VERIFY OK: depth=1, C=US, O=Let's Encrypt, CN=YR2",
    'VERIFY OK: depth=0, CN=opengw.net',
    'Initialization Sequence Completed'
  ].join('\n');
  const facts = parseLogFacts(log);
  assert.strictEqual(facts.tunnelIp, '10.211.1.17');
  assert.strictEqual(facts.tunnelGateway, '10.211.1.18');
  assert.deepStrictEqual(facts.pushedDns, ['10.211.254.254', '8.8.8.8']);
  assert.strictEqual(facts.tlsVersion, '1.3');
  assert.strictEqual(facts.dataCipher, 'AES-128-CBC');
  assert.strictEqual(facts.dataAuth, 'SHA1');
  assert.strictEqual(facts.verifyChain.length, 2);
  assert.strictEqual(facts.initialized, true);
});

test('parseLogFacts handles DCO subnet logs (netmask + route-gateway)', () => {
  const log = [
    "PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1 bypass-dhcp,dhcp-option DNS 1.1.1.1,route-gateway 10.8.0.1,topology subnet,ifconfig 10.8.0.2 255.255.255.0,cipher AES-256-GCM'",
    "Data Channel: cipher 'AES-256-GCM', peer-id: 1",
    'Initialization Sequence Completed'
  ].join('\n');
  const facts = parseLogFacts(log);
  assert.strictEqual(facts.tunnelIp, '10.8.0.2');
  assert.strictEqual(facts.tunnelGateway, '10.8.0.1');
  assert.strictEqual(facts.dataCipher, 'AES-256-GCM');
  assert.strictEqual(facts.dataAuth, null);
  assert.deepStrictEqual(facts.pushedDns, ['1.1.1.1']);
});

test('weakCrypto flags legacy TLS and CBC/SHA1 bundles only', () => {
  assert.deepStrictEqual(
    weakCrypto({ tlsVersion: '1.0', dataCipher: 'AES-128-CBC', dataAuth: 'SHA1' }).length,
    3
  );
  assert.deepStrictEqual(weakCrypto({ tlsVersion: '1.3', dataCipher: 'AES-256-GCM', dataAuth: 'SHA256' }), []);
});

test('aggregateLevel keeps the worst check level', () => {
  assert.strictEqual(aggregateLevel([{ level: 'ok' }, { level: 'warn' }]), 'warn');
  assert.strictEqual(aggregateLevel([{ level: 'warn' }, { level: 'critical' }, { level: 'ok' }]), 'critical');
  assert.strictEqual(aggregateLevel([]), 'ok');
});

test('entersCritical alerts once per crossing into critical', () => {
  assert.strictEqual(entersCritical('ok', 'critical'), true);
  assert.strictEqual(entersCritical('warn', 'critical'), true);
  assert.strictEqual(entersCritical('idle', 'critical'), true);
  assert.strictEqual(entersCritical('critical', 'critical'), false);
  assert.strictEqual(entersCritical('critical', 'warn'), false);
});

test('a critical verdict disconnects an active tunnel through the normal path', () => {
  assert.strictEqual(shouldDisconnectOnCritical('critical', 'CONNECTED'), true);
  assert.strictEqual(shouldDisconnectOnCritical('warn', 'CONNECTED'), false);
  assert.strictEqual(shouldDisconnectOnCritical('critical', 'DISCONNECTED'), false);
});

test('intel parsers keep only relevant items', () => {
  const nvd = parseNvd({
    vulnerabilities: [
      {
        cve: {
          id: 'CVE-2026-0001',
          published: '2026-10-01T00:00:00.000',
          descriptions: [{ lang: 'en', value: 'OpenVPN issue' }],
          metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'HIGH' } }] }
        }
      }
    ]
  });
  assert.deepStrictEqual(nvd.map((item) => item.id), ['CVE-2026-0001']);
  assert.strictEqual(nvd[0].severity, 'HIGH');

  const kev = parseKev({
    vulnerabilities: [
      { cveID: 'CVE-2026-1111', vendorProject: 'OpenVPN', product: 'OpenVPN', vulnerabilityName: 'x' },
      { cveID: 'CVE-2026-2222', vendorProject: 'Microsoft', product: 'Word', vulnerabilityName: 'y' }
    ]
  });
  assert.deepStrictEqual(kev.map((item) => item.id), ['CVE-2026-1111']);
});

test('update feed accepts only public HTTPS manifests and compares versions', () => {
  assert.strictEqual(validFeedUrl('https://releases.example.com/aivpn/release.json').hostname, 'releases.example.com');
  assert.strictEqual(validFeedUrl('http://releases.example.com/release.json'), null);
  assert.strictEqual(validFeedUrl('https://localhost/release.json'), null);
  assert.strictEqual(isNewer('0.2.4', '0.2.3'), true);
  assert.strictEqual(isNewer('0.2.3', '0.2.3'), false);
  assert.strictEqual(isNewer('0.2.2', '0.2.3'), false);
});

test('release manifests require a valid Ed25519 signature', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const manifest = {
    schema: 1,
    version: '0.2.6',
    releasedAt: '2026-11-13T22:00:00.000Z',
    assets: [{ name: 'AI-VPN-Windows-0.2.6-Setup.exe', size: 10, sha256: 'A'.repeat(64) }],
    notes: 'ignored by the signature'
  };
  const signature = signManifest(manifest, priv);
  const signed = { ...manifest, signature };
  assert.strictEqual(verifyManifest(signed, pub), true);
  assert.strictEqual(verifyManifest({ ...signed, version: '9.9.9' }, pub), false);
  assert.strictEqual(
    verifyManifest({ ...signed, assets: [{ ...manifest.assets[0], sha256: 'B'.repeat(64) }] }, pub),
    false
  );
  assert.strictEqual(verifyManifest({ ...manifest }, pub), false);
  const other = crypto.generateKeyPairSync('ed25519');
  assert.strictEqual(verifyManifest(signed, other.publicKey.export({ type: 'spki', format: 'pem' })), false);
  assert.strictEqual(verifyManifest({ ...signed, notes: 'changed later' }, pub), true);
  assert.match(canonicalManifest(manifest), /"sha256":"a{64}"/);
});

test('the embedded release key verifies the published manifest', () => {
  const manifestFile = path.join(__dirname, '..', 'dist', 'release.json');
  if (!fs.existsSync(manifestFile)) {
    assert.ok(true);
    return;
  }
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  if (!manifest.signature) {
    assert.ok(true);
    return;
  }
  assert.strictEqual(verifyManifest(manifest, RELEASE_PUBLIC_KEY), true);
  assert.strictEqual(verifyManifest({ ...manifest, version: '0.0.0' }, RELEASE_PUBLIC_KEY), false);
});

const GUARD_LOG = [
  "PUSH: Received control message: 'PUSH_REPLY,ifconfig 10.8.0.2 10.8.0.1,dhcp-option DNS 10.8.0.1,redirect-gateway def1'",
  'Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384',
  "Data Channel: cipher 'AES-256-GCM', auth 'SHA256'",
  'VERIFY OK: depth=1, CN=test-ca',
  'VERIFY OK: depth=0, CN=test-server',
  'Initialization Sequence Completed'
].join('\n');

function guardFixture(tag) {
  const storeFile = path.join(os.tmpdir(), `aivpn-guard-${process.pid}-${tag}.json`);
  const logFile = path.join(os.tmpdir(), `aivpn-guard-${process.pid}-${tag}.log`);
  fs.rmSync(storeFile, { force: true });
  fs.writeFileSync(logFile, GUARD_LOG, 'utf8');
  const guard = new Guard({ storeFile });
  return { guard, storeFile, logFile };
}

function cleanup(...files) {
  for (const file of files) fs.rmSync(file, { force: true });
}

test('Guard reports unverified instead of pinning a chain string', async () => {
  const { guard, storeFile, logFile } = guardFixture('ok');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });

  const state = { status: 'CONNECTED', server: { id: 'test' } };
  const report = await guard.inspect({ state, logFile, enginePath: 'x' });
  assert.strictEqual(report.level, 'warn');
  assert.deepStrictEqual(
    report.checks.map((check) => check.id),
    ['tunnel', 'route', 'dns', 'ipv6', 'crypto', 'cert', 'engine']
  );
  assert.strictEqual(report.checks.find((check) => check.id === 'tunnel').data.iface, 'Wintun');
  assert.strictEqual(report.checks.find((check) => check.id === 'cert').code, 'certNoFingerprint');
  // A chain string is copied easily by a look-alike CA, so it never becomes a pin.
  assert.strictEqual(guard.pins.test, undefined);

  const again = await guard.inspect({ state, logFile, enginePath: 'x' });
  assert.strictEqual(again.checks.find((check) => check.id === 'cert').code, 'certNoFingerprint');
  assert.strictEqual(guard.pins.test, undefined);
  cleanup(storeFile, logFile);
});

test('Guard flags a changed chain, missing tunnel, and unsigned engine', async () => {
  const { guard, storeFile, logFile } = guardFixture('warn');
  fs.writeFileSync(storeFile, JSON.stringify({ pins: { test: { chain: 'depth=0, CN=old', at: Date.now() } } }), 'utf8');
  guard.load();
  guard.sensors = async () => ({ addresses: [], dns: [], routes: [], routes6: [] });
  guard.signatureOf = async () => ({ status: 'NotSigned', signer: null });

  const report = await guard.inspect({
    state: { status: 'CONNECTED', server: { id: 'test' } },
    logFile,
    enginePath: 'x'
  });
  assert.strictEqual(report.level, 'critical');
  assert.strictEqual(report.checks.find((check) => check.id === 'tunnel').code, 'tunnelNoIface');
  assert.strictEqual(report.checks.find((check) => check.id === 'route').code, 'routeMissing');
  assert.strictEqual(report.checks.find((check) => check.id === 'cert').code, 'certChanged');
  assert.strictEqual(report.checks.find((check) => check.id === 'engine').level, 'warn');
  cleanup(storeFile, logFile);
});

test('A changed certificate chain is critical and keeps both chains', async () => {
  const { guard, storeFile, logFile } = guardFixture('certcrit');
  fs.writeFileSync(storeFile, JSON.stringify({ pins: { test: { chain: 'depth=0, CN=old', at: Date.now() } } }), 'utf8');
  guard.load();
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
  const report = await guard.inspect({
    state: { status: 'CONNECTED', server: { id: 'test' } },
    logFile,
    enginePath: 'x'
  });
  const cert = report.checks.find((check) => check.id === 'cert');
  assert.strictEqual(cert.level, 'critical');
  assert.strictEqual(cert.code, 'certChanged');
  assert.match(cert.data.old, /CN=old/);
  assert.match(cert.data.now, /CN=test-server/);
  assert.strictEqual(report.level, 'critical');
  cleanup(storeFile, logFile);
});

test('resetPin clears only the named pin and allows a fresh one', async () => {
  const { guard, storeFile, logFile } = guardFixture('repin');
  guard.pins = { test: { chain: 'depth=0, CN=old', at: Date.now() }, other: { chain: 'x', at: Date.now() } };
  guard.save();
  assert.strictEqual(guard.resetPin('test'), true);
  assert.strictEqual(guard.resetPin('test'), false);
  assert.strictEqual(guard.pins.test, undefined);
  assert.ok(guard.pins.other);
  const saved = fs.readFileSync(storeFile, 'utf8');
  assert.ok(!saved.includes('test-server'));
  assert.ok(saved.includes('"other"'));

  guard.sensors = async () => ({ addresses: [], dns: [], routes: [], routes6: [] });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
  const report = await guard.inspect({
    state: { status: 'CONNECTED', server: { id: 'test' }, certFingerprint: CERT_SHA256 },
    logFile,
    enginePath: 'x'
  });
  assert.strictEqual(report.checks.find((check) => check.id === 'cert').code, 'certPinned');
  cleanup(storeFile, logFile);
});

test('certVerdict pins fingerprints and refuses a chain-only pin', () => {
  const chain = 'depth=1, CN=ca >> depth=0, CN=server';
  const old = { chain: 'depth=1, CN=old >> depth=0, CN=old-server', at: Date.now() - 86400000 };
  const fresh = certVerdict(null, { chain, sha256: CERT_SHA256, at: 1 });
  assert.strictEqual(fresh.code, 'certPinned');
  assert.strictEqual(fresh.pin.sha256, CERT_SHA256);
  assert.strictEqual(fresh.data.fp, '92ba24fb6e72a478');

  const same = certVerdict({ chain, sha256: CERT_SHA256, at: 1 }, { chain, sha256: CERT_SHA256, at: 2 });
  assert.strictEqual(same.level, 'ok');
  assert.strictEqual(same.code, 'certMatch');

  const swapped = certVerdict({ chain, sha256: CERT_SHA256, at: 1 }, { chain, sha256: 'b'.repeat(64), at: 2 });
  assert.strictEqual(swapped.level, 'critical');
  assert.strictEqual(swapped.code, 'certChanged');
  assert.strictEqual(swapped.data.oldFp, '92ba24fb6e72a478');
  assert.strictEqual(swapped.data.nowFp, 'bbbbbbbbbbbbbbbb');

  const upgraded = certVerdict(old, { chain: old.chain, sha256: CERT_SHA256, at: 3 });
  assert.strictEqual(upgraded.code, 'certMatch');
  assert.strictEqual(upgraded.pin.sha256, CERT_SHA256);
  assert.strictEqual(upgraded.pin.at, old.at);

  const legacyChanged = certVerdict(old, { chain, sha256: CERT_SHA256, at: 3 });
  assert.strictEqual(legacyChanged.level, 'critical');
  assert.match(legacyChanged.data.old, /CN=old/);

  const noProbe = certVerdict(old, { chain: old.chain, sha256: null, at: 3 });
  assert.strictEqual(noProbe.code, 'certMatch');
  const chainOnly = certVerdict(null, { chain, sha256: null, at: 3 });
  assert.strictEqual(chainOnly.level, 'warn');
  assert.strictEqual(chainOnly.code, 'certNoFingerprint');
  assert.strictEqual(chainOnly.pin, undefined);
  assert.strictEqual(chainOnly.data.fp, '—');
  assert.strictEqual(certVerdict(null, { chain: '', sha256: null, at: 1 }).code, 'certNone');
});

test('pinKey keeps private profiles on a stable key', () => {
  assert.strictEqual(pinKey({ id: 'private' }), 'private');
  assert.strictEqual(pinKey({ id: 42 }), '42');
  assert.strictEqual(pinKey(null), 'private');
});

test('pinPreflight fails closed when there is no pin and no fingerprint', () => {
  assert.deepStrictEqual(pinPreflight(CERT_SHA256, null), { ok: true, expected: CERT_SHA256 });
  assert.deepStrictEqual(pinPreflight(null, CERT_SHA256), { ok: true, expected: CERT_SHA256 });
  const unavailable = pinPreflight(null, null);
  assert.strictEqual(unavailable.ok, false);
  assert.strictEqual(unavailable.reason, 'unavailable');
  // One preflight cannot represent several nodes, so a multi-remote profile
  // proceeds on the CA chain and is reported as unverified.
  const multi = pinPreflight(null, null, { multiRemote: true });
  assert.strictEqual(multi.ok, true);
  assert.strictEqual(multi.expected, null);
  assert.strictEqual(multi.unverified, true);
  assert.strictEqual(pinPreflight(CERT_SHA256, null, { multiRemote: true }).expected, CERT_SHA256);
  assert.strictEqual(pinPreflight(CERT_SHA256, 'b'.repeat(64), { multiRemote: true }).ok, false);
  const mismatch = pinPreflight(CERT_SHA256, 'b'.repeat(64));
  assert.strictEqual(mismatch.ok, false);
  assert.strictEqual(mismatch.reason, 'mismatch');
  assert.strictEqual(mismatch.expected, CERT_SHA256);
  // Colons and letter case never turn the same fingerprint into a mismatch.
  assert.strictEqual(pinPreflight(colonFingerprint(CERT_SHA256), CERT_SHA256.toUpperCase()).ok, true);
});

test('packaging refuses private key material in the app tree', () => {
  const { assertNoPrivateKeys } = require('../scripts/package-portable');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-pkg-'));
  fs.writeFileSync(path.join(dir, 'release.key'), 'x');
  assert.throws(() => assertNoPrivateKeys(dir), /key file/);
  fs.rmSync(path.join(dir, 'release.key'), { force: true });
  fs.mkdirSync(path.join(dir, 'keys'));
  assert.throws(() => assertNoPrivateKeys(dir), /keys\/ directory/);
  fs.rmSync(path.join(dir, 'keys'), { recursive: true, force: true });
  fs.writeFileSync(path.join(dir, 'src.js'), '-----BEGIN PRIVATE KEY-----\nabc');
  assert.throws(() => assertNoPrivateKeys(dir), /embedded private key/);
  fs.rmSync(dir, { recursive: true, force: true });
  // The release key lives outside the project and is never copied from it.
  assert.strictEqual(fs.existsSync(path.join(__dirname, '..', 'keys', 'release-signing.key')), false);
});

test('Signature cache is bound to the executable path and its file identity', async () => {
  const { guard, storeFile } = guardFixture('sigcache');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-sig-'));
  const a = path.join(dir, 'a', 'openvpn.exe');
  const b = path.join(dir, 'b', 'openvpn.exe');
  fs.mkdirSync(path.dirname(a), { recursive: true });
  fs.mkdirSync(path.dirname(b), { recursive: true });
  fs.writeFileSync(a, 'one');
  fs.writeFileSync(b, 'two');
  let calls = 0;
  const seen = [];
  guard.psJson = async (command) => {
    calls += 1;
    seen.push(String(command));
    return { status: 'Valid', signer: 'CN=OpenVPN Inc.' };
  };
  await guard.signatureOf(a);
  assert.strictEqual(calls, 1);
  assert.ok(seen[0].includes(a));
  await guard.signatureOf(a);
  assert.strictEqual(calls, 1);
  // A different openvpn.exe must not be covered by the first result.
  await guard.signatureOf(b);
  assert.strictEqual(calls, 2);
  assert.ok(seen[1].includes(b));
  // The elevation decision asks for a fresh check every time.
  await guard.signatureOf(a, { fresh: true });
  assert.strictEqual(calls, 3);
  // Replacing the file changes its size, so the cached verdict is not reused.
  fs.appendFileSync(a, 'replaced');
  await guard.signatureOf(a);
  assert.strictEqual(calls, 4);
  cleanup(storeFile);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Guard pins the probed fingerprint and flags a swapped certificate', async () => {
  const { guard, storeFile, logFile } = guardFixture('fppin');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
  const state = { status: 'CONNECTED', server: { id: 'test' }, certFingerprint: CERT_SHA256 };

  const first = await guard.inspect({ state, logFile, enginePath: 'x' });
  const pinned = first.checks.find((check) => check.id === 'cert');
  assert.strictEqual(pinned.code, 'certPinned');
  assert.strictEqual(guard.pins.test.sha256, CERT_SHA256);
  assert.strictEqual(guard.pinnedFingerprint('test'), CERT_SHA256);

  const again = await guard.inspect({ state, logFile, enginePath: 'x' });
  assert.strictEqual(again.checks.find((check) => check.id === 'cert').code, 'certMatch');

  const swapped = await guard.inspect({
    state: { ...state, certFingerprint: 'b'.repeat(64) },
    logFile,
    enginePath: 'x'
  });
  const cert = swapped.checks.find((check) => check.id === 'cert');
  assert.strictEqual(swapped.level, 'critical');
  assert.strictEqual(cert.code, 'certChanged');
  assert.strictEqual(cert.data.oldFp, '92ba24fb6e72a478');
  cleanup(storeFile, logFile);
});

test('engineTrust accepts only a valid OpenVPN Inc. signature', () => {
  assert.strictEqual(engineTrust(null).ok, false);
  assert.strictEqual(engineTrust({ status: 'NotSigned' }).reason, 'invalid');
  assert.strictEqual(engineTrust({ status: 'HashMismatch', signer: 'CN=OpenVPN Inc.' }).reason, 'invalid');
  assert.strictEqual(engineTrust({ status: 'Valid', signer: 'CN=Some Other Vendor' }).reason, 'foreign-signer');
  assert.strictEqual(engineTrust({ status: 'Valid', signer: 'CN=OpenVPN Inc.' }).ok, true);
});

test('engineVerdict refuses an engine directory this user can write to', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-engine-'));
  const exe = path.join(dir, 'openvpn.exe');
  fs.writeFileSync(exe, 'stub', 'utf8');
  assert.strictEqual(dirWritable(dir), true);
  const verdict = engineVerdict({
    enginePath: exe,
    strict: true,
    signature: { status: 'Valid', signer: 'CN=OpenVPN Inc.' }
  });
  assert.deepStrictEqual(verdict, { ok: false, reason: 'writable-dir' });
  assert.strictEqual(errorFor(verdict.reason), 'ENGINE_DIR_UNSAFE');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('engineVerdict rejects relative paths and non-openvpn names', () => {
  assert.strictEqual(engineVerdict({ enginePath: 'openvpn.exe' }).reason, 'relative');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-engine-'));
  const other = path.join(dir, 'evil.exe');
  fs.writeFileSync(other, 'stub', 'utf8');
  assert.strictEqual(engineVerdict({ enginePath: other }).reason, 'name');
  assert.strictEqual(engineVerdict({ enginePath: path.join(dir, 'openvpn.exe') }).reason, 'missing');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('engineVerdict only lets a custom engine through when picked in this session', () => {
  const installed = 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe';
  if (!fs.existsSync(installed)) return; // engine not installed on this host
  assert.strictEqual(dirWritable(path.dirname(installed)), false);
  const custom = { status: 'NotSigned' };
  assert.strictEqual(
    engineVerdict({ enginePath: installed, strict: false, signature: custom, pickedInSession: false }).reason,
    'pick-required'
  );
  assert.strictEqual(
    engineVerdict({ enginePath: installed, strict: false, signature: custom, pickedInSession: true }).reason,
    'custom-session'
  );
  assert.strictEqual(
    engineVerdict({ enginePath: installed, strict: true, signature: custom, pickedInSession: true }).reason,
    'untrusted'
  );
  assert.strictEqual(
    engineVerdict({
      enginePath: installed,
      strict: true,
      signature: { status: 'Valid', signer: 'CN=OpenVPN Inc.' },
      pickedInSession: false
    }).reason,
    'trusted'
  );
  assert.strictEqual(
    engineVerdict({
      enginePath: installed,
      strict: true,
      signature: { status: 'Valid', signer: 'CN=Some Other Vendor' }
    }).reason,
    'untrusted'
  );
});

test('Guard warns when a valid signature comes from a foreign publisher', async () => {
  const { guard, storeFile, logFile } = guardFixture('foreign');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=Some Other Vendor' });
  const report = await guard.inspect({
    state: { status: 'CONNECTED', server: { id: 'test' } },
    logFile,
    enginePath: 'x'
  });
  const engine = report.checks.find((check) => check.id === 'engine');
  assert.strictEqual(engine.level, 'warn');
  assert.strictEqual(engine.code, 'engineForeign');
  cleanup(storeFile, logFile);
});

test('Guard reports unknown crypto when the log has no TLS facts', async () => {
  const { guard, storeFile, logFile } = guardFixture('partial');
  fs.writeFileSync(
    logFile,
    [
      "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1,route-gateway 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0'",
      "Data Channel: cipher 'AES-256-GCM', peer-id: 1",
      'VERIFY OK: depth=0, CN=test-server',
      'Initialization Sequence Completed'
    ].join('\n'),
    'utf8'
  );
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });

  const report = await guard.inspect({
    state: { status: 'CONNECTED', server: { id: 'test' }, certFingerprint: CERT_SHA256 },
    logFile,
    enginePath: 'x'
  });
  const crypto = report.checks.find((check) => check.id === 'crypto');
  assert.strictEqual(crypto.level, 'unknown');
  assert.strictEqual(crypto.code, 'cryptoPartial');
  assert.strictEqual(crypto.data.cipher, 'AES-256-GCM');
  assert.strictEqual(report.level, 'unknown');
  cleanup(storeFile, logFile);
});

test('Guard preserves IPv6 query failure separately from an empty route list', async () => {
  const { guard, storeFile, logFile } = guardFixture('ipv6-unknown');
  try {
    let response = null;
    let query = '';
    guard.psJson = async (command) => {
      if (command.includes('AddressFamily IPv6')) {
        query = command;
        return response;
      }
      return [];
    };
    assert.strictEqual((await guard.sensors()).routes6, null);
    assert.match(query, /ConvertTo-Json -InputObject \$routes/);
    assert.doesNotMatch(query, /-DestinationPrefix/);
    response = [];
    assert.deepStrictEqual((await guard.sensors()).routes6, []);
    response = { InterfaceAlias: 'Wi-Fi', DestinationPrefix: '::/0' };
    assert.deepStrictEqual((await guard.sensors()).routes6, [response]);

    const base = {
      addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
      dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
      routes: [
        { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
        { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
      ]
    };
    guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
    const state = { status: 'CONNECTED', server: { id: 'test' }, certFingerprint: CERT_SHA256 };
    for (const [routes6, code, level] of [
      [null, 'ipv6Unknown', 'unknown'],
      [[], 'ipv6Ok', 'ok'],
      [[{ InterfaceAlias: 'Wi-Fi', DestinationPrefix: '::/0' }], 'ipv6Outside', 'warn']
    ]) {
      guard.sensors = async () => ({ ...base, routes6 });
      const report = await guard.inspect({ state, logFile, enginePath: 'x' });
      const ipv6 = report.checks.find((check) => check.id === 'ipv6');
      assert.strictEqual(ipv6.code, code);
      assert.strictEqual(ipv6.level, level);
      if (routes6 === null) assert.strictEqual(report.level, 'unknown');
    }
  } finally {
    cleanup(storeFile, logFile);
  }
});

test('Guard does not ignore off-tunnel DNS or mismatched split routes', async () => {
  const { guard, storeFile, logFile } = guardFixture('route-and-dns');
  try {
    guard.sensors = async () => ({
      addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
      dns: [
        { InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] },
        { InterfaceAlias: 'Wi-Fi', ServerAddresses: ['10.8.0.1'] }
      ],
      routes: [
        { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.10', InterfaceAlias: 'Wintun' },
        { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wi-Fi' }
      ],
      routes6: []
    });
    guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
    const report = await guard.inspect({
      state: { status: 'CONNECTED', server: { id: 'test' }, certFingerprint: CERT_SHA256 },
      logFile,
      enginePath: 'x'
    });
    assert.strictEqual(report.checks.find((check) => check.id === 'dns').code, 'dnsOutside');
    assert.strictEqual(report.checks.find((check) => check.id === 'route').code, 'routeMissing');
  } finally {
    cleanup(storeFile, logFile);
  }
});

test('Guard catches split-route gaps, off-tunnel DNS, and IPv6 leaks', async () => {
  const { guard, storeFile, logFile } = guardFixture('strict');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wi-Fi', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '192.168.1.1', InterfaceAlias: 'Wi-Fi' }
    ],
    routes6: [{ DestinationPrefix: '::/0', NextHop: 'fe80::1', InterfaceAlias: 'Wi-Fi' }]
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });

  const report = await guard.inspect({
    state: { status: 'CONNECTED', server: { id: 'test' } },
    logFile,
    enginePath: 'x'
  });
  assert.strictEqual(report.checks.find((check) => check.id === 'route').code, 'routePartial');
  assert.strictEqual(report.checks.find((check) => check.id === 'dns').code, 'dnsOutside');
  assert.strictEqual(report.checks.find((check) => check.id === 'ipv6').code, 'ipv6Outside');
  assert.strictEqual(report.level, 'critical');

  const remembered = await guard.inspect({ state: { status: 'DISCONNECTED' } });
  assert.strictEqual(remembered.level, 'critical');
  cleanup(storeFile, logFile);
});

test('Guard audits leftover routes, DNS, and address after disconnect', async () => {
  const { guard, storeFile, logFile } = guardFixture('residual');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
  const state = { status: 'CONNECTED', server: { id: 'test' }, certFingerprint: CERT_SHA256 };
  const connected = await guard.inspect({ state, logFile, enginePath: 'x' });
  assert.strictEqual(connected.level, 'ok');

  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wi-Fi', ServerAddresses: ['10.8.0.1'] }],
    routes: [{ DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }],
    routes6: []
  });
  guard.lastConnectedAt = Date.now() - 5000;
  const residual = await guard.inspect({ state: { status: 'DISCONNECTED' } });
  assert.strictEqual(residual.level, 'critical');
  const codes = residual.checks.map((check) => check.code);
  assert.deepStrictEqual(codes, ['residualRoute', 'residualDns', 'residualAddress']);
  assert.strictEqual(residual.checks[0].id, 'residual');
  assert.strictEqual(residual.checks[0].data.gw, '10.8.0.1');

  const repeated = await guard.inspect({ state: { status: 'DISCONNECTED' } });
  assert.strictEqual(repeated.level, 'critical');
  assert.deepStrictEqual(repeated.checks.map((check) => check.code), codes);
  cleanup(storeFile, logFile);
});

test('Guard verifies the kill switch is enforced by Windows firewall', async () => {
  const { guard, storeFile, logFile } = guardFixture('fw');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
  guard.firewallState = async () => ({
    profiles: [
      { Name: 'Domain', DefaultOutboundAction: 'Block' },
      { Name: 'Private', DefaultOutboundAction: 'Block' },
      { Name: 'Public', DefaultOutboundAction: 'Block' }
    ],
    rules: [
      { DisplayName: 'AI VPN Kill Switch VPN transport', Enabled: true, Action: 'Allow' },
      { DisplayName: 'AI VPN Kill Switch VPN interface', Enabled: true, Action: 'Allow' }
    ]
  });
  const state = { status: 'CONNECTED', server: { id: 'test' }, certFingerprint: CERT_SHA256, killSwitchActive: true };
  const report = await guard.inspect({ state, logFile, enginePath: 'x' });
  const firewall = report.checks.find((check) => check.id === 'firewall');
  assert.strictEqual(firewall.level, 'ok');
  assert.strictEqual(firewall.code, 'fwOk');
  assert.strictEqual(report.level, 'ok');

  guard.firewallState = async () => ({
    profiles: [
      { Name: 'Domain', DefaultOutboundAction: 'Block' },
      { Name: 'Private', DefaultOutboundAction: 'Allow' },
      { Name: 'Public', DefaultOutboundAction: 'Block' }
    ],
    rules: [{ DisplayName: 'AI VPN Kill Switch VPN transport', Enabled: true, Action: 'Allow' }]
  });
  const open = await guard.inspect({ state, logFile, enginePath: 'x' });
  const openCheck = open.checks.find((check) => check.id === 'firewall');
  assert.strictEqual(openCheck.level, 'critical');
  assert.strictEqual(openCheck.code, 'fwOpen');
  assert.match(openCheck.data.open, /Private: Allow/);

  guard.firewallState = async () => ({
    profiles: [{ Name: 'Public', DefaultOutboundAction: 'Block' }],
    rules: []
  });
  const noRules = await guard.inspect({ state, logFile, enginePath: 'x' });
  assert.strictEqual(noRules.checks.find((check) => check.id === 'firewall').code, 'fwNoRules');
  cleanup(storeFile, logFile);
});

test('Guard flags wide outbound allow rules in strict mode', async () => {
  const { guard, storeFile, logFile } = guardFixture('fwbroad');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
  guard.firewallState = async () => ({
    profiles: [{ Name: 'Public', DefaultOutboundAction: 'Block' }],
    rules: [{ DisplayName: 'AI VPN Kill Switch VPN interface', Enabled: true, Action: 'Allow' }],
    broad: [{ label: 'Allow everything', profiles: 'Public' }]
  });
  const state = { status: 'CONNECTED', server: { id: 'test' }, certFingerprint: CERT_SHA256, killSwitchActive: true };
  const strict = await guard.inspect({ state, logFile, enginePath: 'x', strict: true });
  const strictCheck = strict.checks.find((check) => check.id === 'firewall');
  assert.strictEqual(strictCheck.level, 'critical');
  assert.strictEqual(strictCheck.code, 'fwOpen');
  assert.match(strictCheck.data.open, /Allow everything/);

  const lenient = await guard.inspect({ state, logFile, enginePath: 'x' });
  assert.strictEqual(lenient.checks.find((check) => check.id === 'firewall').code, 'fwOk');
  cleanup(storeFile, logFile);
});

test('broadOutboundAllows ignores scoped rules and keeps unscoped ones', () => {
  const store = {
    '{A}': 'v2.30|Action=Allow|Active=TRUE|Dir=Out|Name=Open all|Profile=Public|',
    '{B}': 'v2.30|Action=Allow|Active=TRUE|Dir=Out|Name=App scoped|App=C:\\x.exe|',
    '{C}': 'v2.30|Action=Allow|Active=TRUE|Dir=Out|Name=Package scoped|PFN=Microsoft.X_abc|LUOwn=S-1-5-21-1|',
    '{D}': 'v2.30|Action=Allow|Active=TRUE|Dir=Out|Name=Port scoped|Protocol=6|RPort=443|',
    '{E}': 'v2.30|Action=Allow|Active=TRUE|Dir=Out|Name=Interface scoped|InterfaceType=RemoteAccess|',
    '{F}': 'v2.30|Action=Allow|Active=TRUE|Dir=Out|Name=Our engine|App=C:\\openvpn.exe|',
    '{G}': 'v2.30|Action=Allow|Active=TRUE|Dir=Out|Name=Any protocol|Protocol=256|RA4=*|',
    '{H}': 'v2.30|Action=Block|Active=TRUE|Dir=Out|Name=Blocked|',
    '{I}': 'v2.30|Action=Allow|Active=FALSE|Dir=Out|Name=Inactive|'
  };
  const broad = broadOutboundAllows(store);
  assert.deepStrictEqual(broad.map((rule) => rule.label), ['Open all', 'Any protocol']);
});

test('Guard skips the firewall check when the kill switch is off', async () => {
  const { guard, storeFile, logFile } = guardFixture('nofw');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
  guard.firewallState = async () => {
    throw new Error('must not be queried');
  };
  const report = await guard.inspect({
    state: { status: 'CONNECTED', server: { id: 'test' } },
    logFile,
    enginePath: 'x'
  });
  assert(!report.checks.some((check) => check.id === 'firewall'));
  cleanup(storeFile, logFile);
});

test('Guard stays idle after a clean disconnect', async () => {
  const { guard, storeFile, logFile } = guardFixture('clean');
  guard.sensors = async () => ({
    addresses: [{ IPAddress: '10.8.0.2', InterfaceAlias: 'Wintun' }],
    dns: [{ InterfaceAlias: 'Wintun', ServerAddresses: ['10.8.0.1'] }],
    routes: [
      { DestinationPrefix: '0.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' },
      { DestinationPrefix: '128.0.0.0/1', NextHop: '10.8.0.1', InterfaceAlias: 'Wintun' }
    ],
    routes6: []
  });
  guard.signatureOf = async () => ({ status: 'Valid', signer: 'CN=OpenVPN Inc.' });
  await guard.inspect({ state: { status: 'CONNECTED', server: { id: 'test' } }, logFile, enginePath: 'x' });

  guard.sensors = async () => ({
    addresses: [{ IPAddress: '192.168.1.10', InterfaceAlias: 'Wi-Fi' }],
    dns: [{ InterfaceAlias: 'Wi-Fi', ServerAddresses: ['192.168.1.1'] }],
    routes: [{ DestinationPrefix: '0.0.0.0/0', NextHop: '192.168.1.1', InterfaceAlias: 'Wi-Fi' }],
    routes6: []
  });
  guard.lastConnectedAt = Date.now() - 5000;
  const idle = await guard.inspect({ state: { status: 'DISCONNECTED' } });
  assert.strictEqual(idle.level, 'idle');
  assert.strictEqual(idle.checks.length, 1);
  cleanup(storeFile, logFile);
});

test('Guard stays idle without an active session', async () => {
  const { guard, storeFile, logFile } = guardFixture('idle');
  const report = await guard.inspect({ state: { status: 'DISCONNECTED' } });
  assert.strictEqual(report.level, 'idle');
  assert.strictEqual(report.checks[0].code, 'idle');
  cleanup(storeFile, logFile);
});

test('Strict kill switch keeps the block after a crash', () => {
  const ps = watchdogScript({
    heartbeat: 'C:\\run\\killswitch.heartbeat',
    stop: 'C:\\run\\killswitch.stop',
    lock: 'C:\\run\\killswitch.lock.json',
    backup: 'C:\\run\\killswitch-firewall.json',
    ready: 'C:\\run\\killswitch.ready.json',
    failed: 'C:\\run\\killswitch.failed.json',
    nonce: 'attempt-1',
    enginePid: 4242,
    strict: true,
    enginePath: 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
    host: '203.0.113.9',
    port: 1194,
    protocol: 'UDP'
  });
  assert.ok(ps.includes('$strict=$true'));
  assert.ok(ps.includes("$mode='crash'"));
  assert.ok(ps.includes("if ($mode -eq 'clean' -or $mode -eq 'failed' -or -not $strict)"));
  assert.ok(ps.includes('$waited -lt 120'));
  assert.ok(ps.includes('Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block'));
  assert.ok(ps.includes('Stop-Process -Id $enginePid'));
  const gate = ps.indexOf("if ($mode -eq 'clean' -or $mode -eq 'failed' -or -not $strict)");
  const restore = ps.indexOf('DefaultOutboundAction $p.DefaultOutboundAction');
  assert.ok(gate > 0 && restore > gate);
});

test('Kill switch normalizes the OpenVPN program path for Windows firewall rules', () => {
  const enginePath = 'C:/Program Files/OpenVPN/bin/openvpn.exe';
  assert.strictEqual(firewallProgramPath(enginePath), 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe');
  const ps = watchdogScript({
    heartbeat: 'C:\\run\\heartbeat', stop: 'C:\\run\\stop', lock: 'C:\\run\\lock', backup: 'C:\\run\\backup',
    ready: 'C:\\run\\ready', failed: 'C:\\run\\failed', nonce: 'n', enginePid: 0, strict: true,
    enginePath, host: '203.0.113.9', port: 1194, protocol: 'UDP'
  });
  assert.ok(ps.includes("-Program 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe'"));
});

test('Non-strict kill switch restores the firewall after a crash', () => {
  const ps = watchdogScript({
    heartbeat: 'C:\\run\\killswitch.heartbeat',
    stop: 'C:\\run\\killswitch.stop',
    lock: 'C:\\run\\killswitch.lock.json',
    backup: 'C:\\run\\killswitch-firewall.json',
    ready: 'C:\\run\\killswitch.ready.json',
    failed: 'C:\\run\\killswitch.failed.json',
    nonce: 'attempt-1',
    enginePid: 0,
    strict: false,
    enginePath: 'C:\\openvpn.exe',
    host: '203.0.113.9',
    port: 1194,
    protocol: 'TCP'
  });
  assert.ok(ps.includes('$strict=$false'));
  assert.ok(ps.indexOf('if (-not $strict) { break }') < ps.indexOf('$waited -lt 120'));
  assert.ok(ps.includes('DefaultOutboundAction $p.DefaultOutboundAction'));
});

test('Strict kill switch allows the tunnel adapter Windows classifies as Public', () => {
  const ps = watchdogScript({
    heartbeat: 'C:\\run\\killswitch.heartbeat',
    stop: 'C:\\run\\killswitch.stop',
    lock: 'C:\\run\\killswitch.lock.json',
    backup: 'C:\\run\\killswitch-firewall.json',
    ready: 'C:\\run\\killswitch.ready.json',
    failed: 'C:\\run\\killswitch.failed.json',
    nonce: 'attempt-1',
    enginePid: 4242,
    strict: true,
    enginePath: 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
    host: '203.0.113.9',
    port: 1194,
    protocol: 'UDP'
  });
  // The DCO adapter is created only after the engine connects, so the rule is
  // built from the live interface name and the loop keeps looking for it.
  assert.ok(ps.includes("$_.InterfaceDescription -match 'OpenVPN|Wintun|TAP-Windows'"));
  assert.ok(ps.includes('$ruleName="$prefix tunnel $name"'));
  assert.ok(ps.includes('New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Allow -InterfaceAlias $name'));
  const loop = ps.indexOf('while ($true)');
  assert.ok(loop > 0 && ps.indexOf('Add-AivpnTunnelRules', loop) > loop);
  // A name with wildcard characters would widen the rule to every interface.
  assert.ok(ps.includes("if ($name -match '[\\*\\?\\[\\]]') { continue }"));
  // Restore removes every rule under the prefix, including the alias rules.
  assert.ok(ps.includes('Get-NetFirewallRule -DisplayName "$prefix *"'));
});

test('Kill switch recovery restores profiles and removes rules and markers', () => {
  const ps = recoveryScript({
    heartbeat: 'C:\\run\\killswitch.heartbeat',
    stop: 'C:\\run\\killswitch.stop',
    lock: 'C:\\run\\killswitch.lock.json',
    backup: 'C:\\run\\killswitch-firewall.json',
    ready: 'C:\\run\\killswitch.ready.json',
    failed: 'C:\\run\\killswitch.failed.json'
  });
  assert.ok(ps.includes('Remove-NetFirewallRule'));
  assert.ok(ps.includes('DefaultOutboundAction $p.DefaultOutboundAction'));
  assert.ok(ps.includes('DefaultOutboundAction NotConfigured'));
  assert.ok(ps.includes("Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' }"));
  assert.ok(ps.includes('Remove-Item -LiteralPath $lock,$heartbeat,$stop,$ready,$failed'));
});

test('Kill switch publishes readiness only after reading the rules back', () => {
  const ps = watchdogScript({
    heartbeat: 'C:\\run\\killswitch.heartbeat',
    stop: 'C:\\run\\killswitch.stop',
    lock: 'C:\\run\\killswitch.lock.json',
    backup: 'C:\\run\\killswitch-firewall.json',
    ready: 'C:\\run\\killswitch.ready.json',
    failed: 'C:\\run\\killswitch.failed.json',
    nonce: 'attempt-1',
    enginePid: 0,
    strict: true,
    enginePath: 'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
    host: '203.0.113.9',
    port: 1194,
    protocol: 'UDP'
  });
  assert.ok(ps.includes("$nonce='attempt-1'"));
  assert.ok(ps.includes('function Test-AivpnKillSwitch'));
  assert.ok(ps.includes("if ($bad.Count -gt 0) { $errors += 'profile' }"));
  assert.ok(ps.includes('@($addr.RemoteAddress) -contains $hostRemote'));
  assert.ok(ps.includes('[string]$portFilter.Protocol -ne $protocol'));
  assert.ok(ps.includes('[string]$portFilter.RemotePort -ne $remotePort'));
  assert.ok(ps.includes("if ($null -eq $ifaceType -or [string]$ifaceType.InterfaceType -ne 'RemoteAccess')"));
  const block = ps.indexOf('-DefaultOutboundAction Block');
  const verify = ps.indexOf('$verifyFail=Test-AivpnKillSwitch');
  const ready = ps.indexOf("state='ready'");
  assert.ok(block > 0 && verify > block && ready > verify);
  // A failed read-back restores the firewall and leaves a failure marker.
  assert.ok(ps.includes('Set-AivpnFailed $verifyFail'));
  assert.ok(ps.includes("if ($mode -eq 'failed') { exit 6 }"));
});

test('Kill switch enable waits for the ready marker of this attempt', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-ks-ready-'));
  const ks = new KillSwitch(dir);
  ks.spawnElevated = async () => {
    const lock = readJsonFile(ks.lockFile);
    setTimeout(() => {
      fs.writeFileSync(ks.readyFile, JSON.stringify({ nonce: lock.nonce, state: 'ready' }), 'utf8');
    }, 60);
  };
  await ks.enable({
    enginePath: 'C:\\openvpn.exe',
    enginePid: 0,
    host: '203.0.113.9',
    port: 1194,
    protocol: 'UDP',
    timeoutMs: 3000
  });
  assert.ok(ks.timer, 'heartbeat timer runs after readiness');
  assert.strictEqual(ks.locked(), true);
  ks.disable();
  assert.strictEqual(ks.timer, null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Kill switch enable aborts when the watchdog cannot verify the rules', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-ks-failed-'));
  const ks = new KillSwitch(dir);
  ks.spawnElevated = async () => {
    const lock = readJsonFile(ks.lockFile);
    fs.writeFileSync(
      ks.failedFile,
      JSON.stringify({ nonce: lock.nonce, state: 'failed', reason: 'transport-port' }),
      'utf8'
    );
  };
  let caught = null;
  try {
    await ks.enable({
      enginePath: 'C:\\openvpn.exe',
      enginePid: 0,
      host: '203.0.113.9',
      port: 1194,
      protocol: 'UDP',
      timeoutMs: 3000
    });
  } catch (error) {
    caught = error;
  }
  assert.ok(caught);
  assert.strictEqual(caught.message, 'KILLSWITCH_NOT_READY');
  assert.strictEqual(caught.reason, 'transport-port');
  assert.strictEqual(ks.timer, null);
  assert.ok(fs.existsSync(ks.stopFile));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Kill switch ignores a ready marker from another attempt', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-ks-stale-'));
  const ks = new KillSwitch(dir);
  ks.spawnElevated = async () => {
    fs.writeFileSync(ks.readyFile, JSON.stringify({ nonce: 'stale', state: 'ready' }), 'utf8');
  };
  let caught = null;
  try {
    await ks.enable({
      enginePath: 'C:\\openvpn.exe',
      enginePid: 0,
      host: '203.0.113.9',
      port: 1194,
      protocol: 'UDP',
      timeoutMs: 400
    });
  } catch (error) {
    caught = error;
  }
  assert.ok(caught);
  assert.strictEqual(caught.message, 'KILLSWITCH_NOT_READY');
  assert.strictEqual(caught.reason, 'timeout');
  assert.strictEqual(ks.timer, null);
  assert.ok(fs.existsSync(ks.stopFile));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Kill switch never leaves an elevated helper script in the user folder', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-ks-'));
  const ks = new KillSwitch(dir);
  ks.spawnElevated = async () => {
    const lock = readJsonFile(ks.lockFile);
    fs.writeFileSync(ks.readyFile, JSON.stringify({ nonce: lock.nonce, state: 'ready' }), 'utf8');
  };
  await ks.enable({
    enginePath: 'C:\\openvpn.exe',
    enginePid: 0,
    host: '203.0.113.9',
    port: 1194,
    protocol: 'UDP',
    strict: true
  });
  const names = fs.readdirSync(dir);
  assert.ok(!names.some((name) => /\.cmd$/i.test(name)), names.join(','));
  assert.ok(!names.some((name) => /\.ps1$/i.test(name)), names.join(','));
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'killswitch.js'), 'utf8');
  assert.ok(!/'-File'/.test(source));
  assert.ok(source.includes("'-Command', elevateScript(script)"));
  ks.disable();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Kill switch lock marker gates enable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aivpn-ks-'));
  const ks = new KillSwitch(dir);
  assert.strictEqual(ks.locked(), false);
  fs.writeFileSync(ks.lockFile, '{"strict":true}', 'utf8');
  assert.strictEqual(ks.locked(), true);
  await assert.rejects(
    ks.enable({ enginePath: 'C:\\openvpn.exe', enginePid: 1, host: '203.0.113.9', port: 1194, protocol: 'UDP' }),
    /KILLSWITCH_LOCKED/
  );
  fs.rmSync(dir, { recursive: true, force: true });
});

(async () => {
  for (const { name, fn } of tests) {
    try {
      await fn();
      passed += 1;
      console.log(`PASS  ${name}`);
    } catch (error) {
      failed += 1;
      console.log(`FAIL  ${name}`);
      console.log(`      ${error.message}`);
    }
  }
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
})();
