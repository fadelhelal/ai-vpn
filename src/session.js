'use strict';

const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { probeExit, measureDownload } = require('./measure');
const { KillSwitch } = require('./killswitch');
const { probeFingerprint } = require('./certprobe');
const { colonFingerprint, normalizeFingerprint } = require('./certs');
const { launchStaged, spawnScript, elevateScript, legacyStopScript } = require('./elevate');
const { verifyPeer } = require('./mgmtpeer');

// include/config let a profile pull in a second file that never passes through
// this filter, so a banned directive could travel inside it.
const BANNED_DIRECTIVES =
  /^\s*(plugin|up|down|route-up|route-pre-down|ipchange|client-connect|client-disconnect|learn-address|tls-verify|tls-crypt-v2-verify|script-security|management|management-client-auth|auth-user-pass|auth-user-pass-verify|askpass|daemon|log|status|writepid|user|group|chroot|tls-export-cert|peer-fingerprint|include|config)\b/i;

// OpenVPN parses "setenv opt <option>" as a real option, so a profile could
// smuggle a plugin/script hook past the directive ban. The whole form is
// dropped; the app supplies its own compatible options.
const BANNED_OPTION_INJECTION = /^\s*setenv\s+opt\b/i;

// OpenVPN's config parser strips a leading "--" from each line, so "--plugin"
// is executed exactly like "plugin". Match the same form the engine acts on,
// otherwise the prefix is a free bypass.
function directiveOf(line) {
  return String(line)
    .replace(/^\s+/, '')
    .replace(/^--/, '');
}

function sanitizeConfig(config) {
  return String(config || '')
    .split(/\r?\n/)
    .filter((line) => {
      const probe = directiveOf(line);
      return !BANNED_DIRECTIVES.test(probe) && !BANNED_OPTION_INJECTION.test(probe);
    })
    .join('\n')
    .trim();
}

function remoteSpec(config) {
  const lines = String(config || '').split(/\r?\n/);
  const remotes = [];
  let globalProto = null;
  for (let index = 0; index < lines.length; index += 1) {
    const line = directiveOf(lines[index]);
    const proto = /^proto\s+(udp(?:4|6)?|tcp(?:4|6)?(?:-client|-server)?)(?:\s|$)/i.exec(line);
    if (proto) globalProto = proto[1].toLowerCase();
    const remote = /^remote\s+(\S+)(?:\s+(\d+))?(?:\s+(udp(?:4|6)?|tcp(?:4|6)?(?:-client|-server)?))?(?:\s|$)/i.exec(line);
    if (!remote) continue;
    const port = remote[2] ? Number(remote[2]) : 1194;
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    remotes.push({
      line: index,
      host: remote[1],
      port,
      openVpnProtocol: remote[3] ? remote[3].toLowerCase() : null
    });
  }
  // A firewall allow rule must describe the exact endpoint that OpenVPN will
  // use. Multiple remotes would let the engine select one outside that rule.
  if (remotes.length !== 1) return null;
  const remote = remotes[0];
  const openVpnProtocol = remote.openVpnProtocol || globalProto || 'udp';
  return {
    ...remote,
    openVpnProtocol,
    protocol: openVpnProtocol.startsWith('tcp') ? 'TCP' : 'UDP'
  };
}

// The pin is an IPv4 literal, so a protocol that forces IPv6 would make the
// engine resolve that literal in the wrong family and fail before any packet.
function ipv6OnlyProtocol(openVpnProtocol) {
  return /^(?:udp6|tcp6)(?:-|$)/i.test(openVpnProtocol || '');
}

function killSwitchTarget(config) {
  const target = remoteSpec(config);
  if (!target || ipv6OnlyProtocol(target.openVpnProtocol) || net.isIP(target.host) !== 4) return null;
  return { host: target.host, port: target.port, protocol: target.protocol };
}

async function resolveKillSwitchTarget(config, lookup = dns.lookup) {
  const target = remoteSpec(config);
  if (!target || ipv6OnlyProtocol(target.openVpnProtocol)) return null;
  if (net.isIP(target.host) === 4) return target;
  // Do not accept IPv6, IP literals of another family, or a malformed name.
  if (net.isIP(target.host) !== 0) return null;
  try {
    const records = await lookup(target.host, { family: 4, all: true, verbatim: true });
    const address = (Array.isArray(records) ? records : [records])
      .map((record) => typeof record === 'string' ? record : record && record.address)
      .find((value) => net.isIP(value) === 4);
    return address ? { ...target, host: address, sourceHost: target.host } : null;
  } catch {
    return null;
  }
}

function pinRemoteEndpoint(config, target) {
  if (!target || !Number.isInteger(target.line) || net.isIP(target.host) !== 4) return String(config || '');
  const lines = String(config || '').split(/\r?\n/);
  // The replacement is constructed from parsed values, never from the source
  // line, so comments or profile-controlled tokens cannot alter the endpoint.
  lines[target.line] = `remote ${target.host} ${target.port} ${target.openVpnProtocol}`;
  return lines.join('\n');
}

// The tunnel may only start with a certificate the app already knows: either a
// stored pin or a fresh preflight result. Falling back to no peer-fingerprint
// when the preflight fails would leave the first connection unpinned and let
// the log become the pin after the fact. Multi-remote profiles are the one
// exception: one preflight cannot cover several nodes, so they connect on the
// CA chain and are reported as unverified instead of being pinned by a guess.
function pinPreflight(storedPin, probedFingerprint, { multiRemote = false } = {}) {
  const expected = normalizeFingerprint(storedPin);
  const probed = normalizeFingerprint(probedFingerprint);
  if (expected && probed && expected !== probed) return { ok: false, reason: 'mismatch', expected };
  if (!expected && !probed) {
    if (multiRemote) return { ok: true, expected: null, unverified: true };
    return { ok: false, reason: 'unavailable', expected: null };
  }
  // With no stored pin the fresh probe is what the engine must enforce.
  return { ok: true, expected: expected || probed };
}

function summarizeLog(text) {
  if (/AUTH_FAILED|AUTH_FAILED/i.test(text)) return 'auth';
  if (/TLS handshake failed|TLS Error|verify error/i.test(text)) return 'tls';
  if (/All TAP-Windows adapters on this system are currently in use|wintun|CreateFile failed on TAP device/i.test(text)) return 'driver';
  if (/Cannot open|Error opening configuration file|Options error/i.test(text)) return 'config';
  // "Route addition via ipapi [adaptive] succeeded" must not count as a
  // failure; only an explicit add_route failure line does.
  if (/add_route|route addition failed|route add command failed/i.test(text)) return 'route';
  return 'unknown';
}

// OpenVPN config files treat backslashes as escapes; a single '\' in a Windows
// path is a fatal options error, so paths must be doubled.
function configPath(value) {
  return String(value).replace(/\\/g, '\\\\');
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function tryConnect(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (!value) socket.destroy();
      resolve(value);
    };
    socket.setTimeout(900);
    socket.once('connect', () => finish(socket));
    socket.once('timeout', () => finish(null));
    socket.once('error', () => finish(null));
  });
}

class VpnSession extends EventEmitter {
  constructor({ runDir, findEngine, getCredentials }) {
    super();
    this.runDir = runDir;
    this.findEngine = findEngine;
    this.getCredentials = getCredentials;
    this.state = this.baseState();
    this.socket = null;
    this.buffer = '';
    this.port = 0;
    this.attempt = 0;
    this.stopping = false;
    this.connectWaiter = null;
    this.configFile = path.join(runDir, 'run.ovpn');
    this.authFile = path.join(runDir, 'auth.txt');
    this.managementFile = path.join(runDir, 'management.pw');
    this.managementSecret = null;
    this.handshakePending = false;
    this.authWaiter = null;
    this.queued = [];
    this.logFile = path.join(runDir, 'openvpn.log');
    this.probeDir = path.join(runDir, 'probe');
    this.pidFile = path.join(runDir, 'engine.pid');
    this.heartbeatFile = path.join(runDir, 'engine.heartbeat');
    this.stopFile = path.join(runDir, 'engine.stop');
    this.supervisorFile = path.join(runDir, 'engine.supervisor.json');
    this.readyFile = path.join(runDir, 'engine.ready.json');
    this.statusFile = path.join(runDir, 'engine.status.json');
    this.supervisorNonce = null;
    this.heartbeatTimer = null;
    this.engineOps = Promise.resolve();
    this.killSwitch = new KillSwitch(runDir);
    this.killSwitchArmed = false;
  }

  baseState() {
    return {
      status: 'DISCONNECTED',
      server: null,
      isPrivate: false,
      detail: null,
      error: null,
      exitIp: null,
      latencyMs: null,
      measuredMbps: null,
      measuredSource: null,
      exitSource: null,
      downloadBytes: 0,
      uploadBytes: 0,
      startedAt: null,
      protocol: null,
      certFingerprint: null,
      killSwitchActive: false
    };
  }

  snapshot() {
    return { ...this.state };
  }

  update(patch) {
    Object.assign(this.state, patch);
    this.emit('state', this.snapshot());
  }

  protocolOf(config) {
    const proto = (/^\s*proto\s+(\S+)/mi.exec(config) || [])[1];
    const cipher = (/^\s*cipher\s+(\S+)/mi.exec(config) || [])[1];
    if (!proto && !cipher) return null;
    return [proto, cipher].filter(Boolean).join(' · ').toUpperCase();
  }

  buildConfig(rawConfig, { useCredentials = false, allowLegacyTls = false, peerFingerprint = null } = {}) {
    // The profile may not pin the server role or may force old TLS; both are
    // stripped so the app always enforces its own floor and server-EKU check.
    const base = sanitizeConfig(rawConfig)
      .split(/\r?\n/)
      .filter((line) => !/^\s*(remote-cert-tls|tls-version-min)\b/i.test(line))
      .join('\n');
    const lines = [
      base,
      '',
      'verb 3',
      'mute 20',
      'script-security 1',
      'block-ipv6',
      'block-outside-dns',
      'remote-cert-tls server',
      `log "${configPath(this.logFile)}"`,
      `management 127.0.0.1 ${this.port}${this.managementSecret ? ` "${configPath(this.managementFile)}"` : ''}`
    ];
    if (allowLegacyTls) lines.push('tls-version-min 1.0');
    else lines.push('tls-version-min 1.2');
    // The engine itself rejects any certificate other than this fingerprint,
    // so a swapped cert fails the handshake before traffic can flow.
    const pin = colonFingerprint(peerFingerprint);
    if (pin) lines.push(`peer-fingerprint ${pin}`);
    if (useCredentials) lines.push(`auth-user-pass "${configPath(this.authFile)}"`, 'auth-nocache');
    return `${lines.join('\n')}\n`;
  }

  async connect({ server, config, isPrivate, useCredentials = false, allowLegacyTls = false, killSwitchEnabled = false, killSwitchStrict = true, fingerprintPin = null, enginePath = null, verifyEngine = null }) {
    if (['CONNECTING', 'CONNECTED', 'DISCONNECTING'].includes(this.state.status)) {
      throw new Error('SESSION_BUSY');
    }
    // The caller verified this exact path moments ago; re-resolving here could
    // pick a different binary than the one that passed the trust checks.
    const engine = enginePath || (await this.findEngine());
    if (!engine) {
      this.update({
        ...this.baseState(),
        status: 'FAILED',
        error: 'ENGINE_MISSING'
      });
      return this.snapshot();
    }
    this.attempt += 1;
    const token = this.attempt;
    this.stopping = false;
    this.update({
      ...this.baseState(),
      status: 'CONNECTING',
      server,
      isPrivate: Boolean(isPrivate),
      protocol: this.protocolOf(config)
    });

    // Resolve a hostname before the tunnel starts and put that same IPv4 into
    // the transient OpenVPN config. The firewall exception and the engine are
    // therefore bound to one endpoint; a later DNS answer cannot redirect the
    // connection around the Kill Switch rule.
    let tunnelConfig = config;
    let killTarget = null;
    if (killSwitchEnabled) {
      const spec = remoteSpec(config);
      if (spec && ipv6OnlyProtocol(spec.openVpnProtocol)) {
        this.update({
          ...this.baseState(),
          status: 'FAILED',
          server,
          isPrivate: Boolean(isPrivate),
          error: 'KILLSWITCH_PROTO_INVALID'
        });
        return this.snapshot();
      }
      killTarget = await resolveKillSwitchTarget(config);
      if (!killTarget) {
        this.update({ ...this.baseState(), status: 'FAILED', server, isPrivate: Boolean(isPrivate), error: 'KILLSWITCH_TARGET_INVALID' });
        return this.snapshot();
      }
      tunnelConfig = pinRemoteEndpoint(config, killTarget);
      this.update({ protocol: this.protocolOf(tunnelConfig) });
    }

    fs.mkdirSync(this.runDir, { recursive: true });
    // Without a password any local process could drive the management socket
    // (drop the tunnel, read state), so each attempt gets a fresh secret that
    // OpenVPN reads from this file and the app must present on connect.
    this.managementSecret = crypto.randomBytes(24).toString('hex');
    this.handshakePending = false;
    this.queued = [];
    fs.writeFileSync(this.managementFile, `${this.managementSecret}\n`, 'utf8');
    this.port = 7505 + Math.floor(Math.random() * 400);
    // A previous attempt's engine must be gone before a second elevated engine
    // is started.  The supervisor stops it; no new UAC prompt is involved.
    const leftover = await this.retirePreviousEngine();
    if (leftover) {
      this.cleanupFiles();
      this.update({
        ...this.baseState(),
        status: 'FAILED',
        server,
        isPrivate: Boolean(isPrivate),
        error: 'ENGINE_STOP_FAILED',
        detail: 'previous-engine-alive'
      });
      return this.snapshot();
    }
    this.prepareEngineMarkers();
    this.logFile = path.join(this.runDir, `openvpn-${token}.log`);
    try {
      for (const name of fs.readdirSync(this.runDir)) {
        const stale = path.join(this.runDir, name);
        if (/^openvpn-\d+\.log$/.test(name) && stale !== this.logFile) fs.rmSync(stale, { force: true });
      }
    } catch {
      // log pruning is best-effort
    }
    fs.writeFileSync(this.logFile, '', 'utf8');

    // Learn the server certificate at user privilege, then let the elevated
    // engine enforce the same fingerprint for the tunnel carrying traffic.
    const probe = await probeFingerprint({
      enginePath: engine,
      rawConfig: tunnelConfig,
      runDir: this.runDir,
      allowLegacyTls,
      shouldAbort: () => this.stopping || token !== this.attempt
    });
    if (this.stopping || token !== this.attempt) {
      this.cleanupFiles();
      return this.snapshot();
    }
    const fingerprint = probe.ok ? probe.fingerprint : null;
    const decision = pinPreflight(fingerprintPin, fingerprint, {
      multiRemote: !probe.ok && probe.reason === 'MULTI_REMOTE'
    });
    if (!decision.ok) {
      this.cleanupFiles();
      this.update({
        ...this.baseState(),
        status: 'FAILED',
        server,
        isPrivate: Boolean(isPrivate),
        error: decision.reason === 'mismatch' ? 'certpin' : 'certUnavailable',
        detail: decision.reason === 'unavailable' ? (probe.reason || null) : null
      });
      return this.snapshot();
    }
    const expected = decision.expected;
    // A known pin is enforced even when the preflight could not run, so the
    // engine keeps rejecting a swapped certificate on every attempt.
    this.update({ certFingerprint: fingerprint });
    const configText = this.buildConfig(tunnelConfig, {
      useCredentials,
      allowLegacyTls,
      peerFingerprint: fingerprint || expected
    });
    fs.writeFileSync(this.configFile, configText, 'utf8');
    if (useCredentials) {
      const credentials = this.getCredentials();
      fs.writeFileSync(this.authFile, `${credentials.username}\n${credentials.password}\n`, 'utf8');
    }

    // Block outbound traffic before the engine starts, not after the tunnel is
    // up: otherwise the connect window is a leak, and a failed launch would
    // stay covered by nothing at all.
    if (killSwitchEnabled) {
      try {
        await this.killSwitch.enable({
          enginePath: engine,
          enginePid: 0,
          host: killTarget.host,
          port: killTarget.port,
          protocol: killTarget.protocol,
          strict: killSwitchStrict !== false
        });
        this.killSwitchArmed = true;
        this.update({ killSwitchActive: true });
      } catch (error) {
        this.cleanupFiles();
        this.update({ ...this.baseState(), status: 'FAILED', server, isPrivate: Boolean(isPrivate), error: error.message || 'KILLSWITCH_LAUNCH_FAILED' });
        return this.snapshot();
      }
    }

    // Re-check the binary identity as close to the elevated launch as possible:
    // the first verdict may be minutes old by now (probe, UAC, firewall setup).
    if (verifyEngine) {
      let check = null;
      try {
        check = await verifyEngine(engine);
      } catch {
        check = null;
      }
      if (!check || check.ok !== true) {
        this.killSwitchArmed = false;
        this.killSwitch.disable();
        this.cleanupFiles();
        this.update({
          ...this.baseState(),
          status: 'FAILED',
          server,
          isPrivate: Boolean(isPrivate),
          error: (check && check.error) || 'ENGINE_UNTRUSTED'
        });
        return this.snapshot();
      }
    }

    this.supervisorNonce = crypto.randomBytes(16).toString('hex');
    this.startHeartbeat();
    try {
      await this.launchElevated(engine, configText);
    } catch (error) {
      this.killSwitchArmed = false;
      this.killSwitch.disable();
      this.stopHeartbeat();
      const engineAlive = await this.terminateEngine();
      this.cleanupFiles();
      // A newer attempt owns the state now; reporting our launch failure over
      // it would describe an engine that is no longer this attempt's.
      if (token === this.attempt && !this.stopping) {
        this.update({
          ...this.baseState(),
          status: 'FAILED',
          error: engineAlive ? 'ENGINE_STOP_FAILED' : (error.message || 'LAUNCH_FAILED'),
          detail: engineAlive ? 'engine-still-running' : null
        });
      }
      return this.snapshot();
    }

    try {
      await this.waitForTunnel(45000, engine);
    } catch (error) {
      if (token !== this.attempt) return this.snapshot();
      if (this.stopping || error.message === 'STOPPED') {
        this.cleanup();
        return this.snapshot();
      }
      this.fail(this.state.error || 'ENGINE_TIMEOUT');
      return this.snapshot();
    }

    if (token !== this.attempt) return this.snapshot();
    try {
      fs.rmSync(this.authFile, { force: true });
      fs.rmSync(this.managementFile, { force: true });
    } catch {
      // engine already consumed it
    }
    this.update({ status: 'CONNECTED', startedAt: Date.now(), detail: null, error: null });
    this.runProbes(token);
    return this.snapshot();
  }

  launchElevated(enginePath, configText) {
    return launchStaged({
      enginePath,
      configFile: this.configFile,
      configText,
      pidFile: this.pidFile,
      heartbeatFile: this.heartbeatFile,
      stopFile: this.stopFile,
      supervisorFile: this.supervisorFile,
      readyFile: this.readyFile,
      statusFile: this.statusFile,
      nonce: this.supervisorNonce
    });
  }

  async waitForTunnel(timeoutMs, enginePath = null) {
    const deadline = Date.now() + timeoutMs;
    const waiter = new Promise((resolve, reject) => {
      this.connectWaiter = { resolve, reject };
    });
    const wiring = (async () => {
      while (Date.now() < deadline) {
        if (this.stopping) throw Object.assign(new Error('STOPPED'), { handled: true });
        const socket = await tryConnect(this.port);
        if (socket) {
          // A local process can bind the random port first and forge tunnel
          // state. The socket owner must be the engine we launched, and its
          // executable must be that engine, before any command is sent.
          const peer = await verifyPeer({
            port: this.port,
            enginePid: this.enginePid(),
            enginePath
          });
          if (!peer.ok) {
            this.detachSocket(socket);
            this.update({ detail: `mgmt-peer-${peer.reason}` });
          } else {
            try {
              await this.attach(socket, Math.max(500, Math.min(5000, deadline - Date.now())));
              return;
            } catch (error) {
              if (error && error.message === 'MANAGEMENT_AUTH_FAILED') throw error;
              // Something else holds the socket slot (or the handshake stalled);
              // drop it and keep probing until the deadline.
              this.detachSocket(socket);
            }
          }
        }
        let fatal = false;
        try {
          fatal = /Options error|Cannot open configuration|Exiting due to fatal error|AUTH_FAILED|All TAP-Windows adapters/i.test(
            fs.readFileSync(this.logFile, 'utf8')
          );
        } catch {
          fatal = false;
        }
        if (fatal) throw new Error('ENGINE_FAILED');
        await delay(500);
      }
      throw new Error('MANAGEMENT_TIMEOUT');
    })();
    wiring.catch((error) => {
      if (this.connectWaiter) {
        this.connectWaiter.reject(error);
        this.connectWaiter = null;
      }
    });
    const timeout = setTimeout(() => {
      if (this.connectWaiter) {
        this.connectWaiter.reject(new Error('ENGINE_TIMEOUT'));
        this.connectWaiter = null;
      }
    }, timeoutMs + 1000);
    try {
      await waiter;
    } finally {
      clearTimeout(timeout);
    }
  }

  attach(socket, timeoutMs = 5000) {
    this.socket = socket;
    this.buffer = '';
    this.queued = [];
    this.handshakePending = Boolean(this.managementSecret);
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('close', () => this.onSocketClosed(socket));
    socket.on('error', () => this.onSocketClosed(socket));
    if (!this.handshakePending) {
      this.subscribe();
      return Promise.resolve(true);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.authWaiter) return;
        this.authWaiter = null;
        reject(new Error('MANAGEMENT_AUTH_TIMEOUT'));
      }, timeoutMs);
      this.authWaiter = {
        resolve: () => {
          clearTimeout(timer);
          this.authWaiter = null;
          resolve(true);
        },
        reject: (error) => {
          clearTimeout(timer);
          this.authWaiter = null;
          reject(error);
        }
      };
      try {
        socket.write(`${this.managementSecret}\n`);
      } catch {
        // close handler rejects the waiter
      }
    });
  }

  detachSocket(socket) {
    if (!socket) return;
    socket.removeAllListeners('close');
    socket.removeAllListeners('error');
    if (this.socket === socket) this.socket = null;
    this.handshakePending = false;
    this.queued = [];
    try {
      socket.destroy();
    } catch {
      // ignore
    }
  }

  subscribe() {
    for (const command of ['state on', 'log on all', 'bytecount 1']) {
      try {
        this.socket.write(`${command}\n`);
      } catch {
        // close handler will report it
      }
    }
    const queued = this.queued.splice(0);
    for (const command of queued) this.send(command);
  }

  onData(chunk) {
    this.buffer += chunk;
    if (this.handshakePending) {
      // The engine answers the password prompt with "SUCCESS: password is
      // correct" or "ERROR: bad password", and the prompt itself has no
      // trailing newline, so the verdict often arrives glued to it in the
      // same chunk ("ENTER PASSWORD:SUCCESS: ..."). Match on the raw buffer,
      // not on newline-split lines, or the verdict is never seen.
      const success = this.buffer.indexOf('SUCCESS: password is correct');
      const failure = this.buffer.indexOf('ERROR: bad password');
      if (success === -1 && failure === -1) return;
      if (success !== -1 && (failure === -1 || success < failure)) {
        this.buffer = this.buffer.slice(success + 'SUCCESS: password is correct'.length);
        this.handshakePending = false;
        this.subscribe();
        if (this.authWaiter) this.authWaiter.resolve();
      } else {
        this.buffer = this.buffer.slice(failure + 'ERROR: bad password'.length);
        this.handshakePending = false;
        const waiter = this.authWaiter;
        this.authWaiter = null;
        this.fail('management-auth');
        waiter?.reject(new Error('MANAGEMENT_AUTH_FAILED'));
      }
    }
    const lines = this.buffer.split(/\r?\n/);
    this.buffer = lines.pop() || '';
    for (const line of lines) {
      if (line.startsWith('>STATE:')) this.onStateLine(line.slice(7));
      else if (line.startsWith('>BYTECOUNT:')) this.onByteCount(line.slice(11));
      else if (/AUTH_FAILED/.test(line)) this.update({ error: 'auth' });
    }
  }

  onByteCount(payload) {
    const [incoming, outgoing] = payload.split(',').map((value) => Number(value));
    if (Number.isFinite(incoming) && Number.isFinite(outgoing) && incoming >= 0 && outgoing >= 0) {
      this.update({ downloadBytes: incoming, uploadBytes: outgoing });
    }
  }

  onStateLine(payload) {
    const parts = payload.split(',');
    const name = (parts[1] || '').trim();
    if (name === 'CONNECTED') {
      const reconnected = this.state.startedAt != null;
      this.update({ status: 'CONNECTED', startedAt: this.state.startedAt || Date.now(), detail: null, error: null });
      if (this.connectWaiter) {
        this.connectWaiter.resolve();
        this.connectWaiter = null;
      }
      if (reconnected) this.runProbes(this.attempt);
      return;
    }
    if (name === 'RECONNECTING') {
      if (!this.stopping && this.state.status === 'CONNECTED') {
        this.update({ status: 'CONNECTING', detail: 'reconnecting' });
      }
      return;
    }
    if (name === 'EXITING' || name === 'EXIT') {
      if (!this.stopping && this.state.status !== 'DISCONNECTED') {
        this.fail(this.state.error || 'engine-exit');
      }
      if (this.connectWaiter) {
        this.connectWaiter.reject(new Error('ENGINE_EXITED'));
        this.connectWaiter = null;
      }
    }
  }

  onSocketClosed(source) {
    if (source && this.socket !== source) return;
    if (this.authWaiter) {
      this.authWaiter.reject(new Error('MANAGEMENT_CLOSED'));
      return;
    }
    if (this.stopping) return;
    if (this.state.status === 'CONNECTED' || this.state.status === 'CONNECTING') {
      this.fail(this.state.error || this.detectFailure());
    }
    if (this.connectWaiter) {
      this.connectWaiter.reject(new Error('ENGINE_EXITED'));
      this.connectWaiter = null;
    }
  }

  detectFailure() {
    try {
      const text = fs.readFileSync(this.logFile, 'utf8').slice(-8000);
      return summarizeLog(text);
    } catch {
      return 'unknown';
    }
  }

  fail(reason) {
    if (this.state.status === 'FAILED' || this.state.status === 'DISCONNECTED') return;
    // A failed attempt must not leave the firewall blocking traffic it no
    // longer has a tunnel for; the watchdog restores on the stop marker.
    this.killSwitchArmed = false;
    this.killSwitch.disable();
    const mapped = ['auth', 'tls', 'driver', 'config', 'route'].includes(reason) ? reason : this.detectFailure();
    // The engine is elevated.  Ask the elevated supervisor (started with it) to
    // stop it and clean the routes; a taskkill from this user token is denied
    // and used to leave the tunnel running behind a "failed" UI.
    this.writeStop('failed');
    const token = this.attempt;
    this.stopHeartbeat();
    this.cleanup();
    this.update({
      ...this.baseState(),
      status: 'FAILED',
      server: this.state.server,
      isPrivate: this.state.isPrivate,
      error: mapped,
      detail: reason
    });
    this.teardownAfterFailure(token).catch(() => {});
  }

  async teardownAfterFailure(token) {
    // Serialized with retire/stop so a quick reconnect cannot have its fresh
    // stop marker consumed by the previous attempt's teardown.
    return this.withEngineLock(async () => {
      if (token !== this.attempt) return;
      const alive = await this._terminateEngine();
      if (alive && token === this.attempt) {
        // Never report a plain connection error while the tunnel may still be
        // up: the user gets an explicit state they can act on.
        this.update({ error: 'ENGINE_STOP_FAILED', detail: 'engine-still-running' });
      }
    });
  }

  withEngineLock(fn) {
    const run = this.engineOps.then(fn, fn);
    this.engineOps = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  async runProbes(token) {
    await delay(1500);
    if (token !== this.attempt) return;
    const probe = await probeExit();
    if (token !== this.attempt || this.state.status !== 'CONNECTED') return;
    if (probe.ok) {
        this.update({ exitIp: probe.exit, exitSource: probe.source, latencyMs: probe.latencyMs });
    } else {
      this.update({ detail: 'probe-failed' });
    }
    const measured = await measureDownload();
    if (token !== this.attempt || this.state.status !== 'CONNECTED') return;
    if (measured) {
      this.update({ measuredMbps: measured.mbps, measuredSource: measured.source });
    }
  }

  send(command) {
    if (!this.socket || this.socket.destroyed) return false;
    if (this.handshakePending) {
      this.queued.push(command);
      return true;
    }
    try {
      this.socket.write(`${command}\n`);
      return true;
    } catch {
      return false;
    }
  }

  async disconnect() {
    this.killSwitchArmed = false;
    this.killSwitch.disable();
    this.stopping = true;
    this.attempt += 1;
    const pid = this.enginePid();
    const active = Boolean(this.supervisorPid()) || Boolean(pid && this.engineAlive(pid));
    if (this.state.status === 'DISCONNECTED' && !active) {
      this.cleanup();
      this.cleanupEngineMarkers();
      return this.snapshot();
    }
    this.update({ status: 'DISCONNECTING', detail: null });
    const alive = await this.terminateEngine();
    this.cleanup();
    this.update(
      alive
        ? { ...this.baseState(), status: 'DISCONNECTED', error: 'ENGINE_STOP_FAILED', detail: 'engine-still-running' }
        : { ...this.baseState(), status: 'DISCONNECTED' }
    );
    return this.snapshot();
  }

  enginePid() {
    try {
      const pid = Number(fs.readFileSync(this.pidFile, 'utf8').trim());
      return Number.isInteger(pid) && pid > 0 ? pid : 0;
    } catch {
      return 0;
    }
  }

  engineAlive(pid = this.enginePid()) {
    if (!pid) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      // EPERM means the elevated engine exists but is not ours to signal.
      return error && error.code === 'EPERM';
    }
  }

  async waitForEngineExit(pid, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (!this.engineAlive(pid)) return true;
      await delay(150);
    }
    return !this.engineAlive(pid);
  }

  // The elevated supervisor owns teardown.  These markers are the only channel
  // it needs, and both live in the user profile: a same-user process can
  // already kill this UI, so they add no new privilege boundary.
  writeHeartbeat() {
    try {
      fs.writeFileSync(this.heartbeatFile, String(Date.now()), 'ascii');
    } catch {
      // a missed beat only shortens the supervisor's crash timeout
    }
  }

  startHeartbeat() {
    this.stopHeartbeat();
    this.writeHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      this.writeHeartbeat();
      const supervisor = this.supervisorPid();
      if (
        supervisor &&
        !this.stopping &&
        !this.engineAlive(supervisor) &&
        this.engineAlive(this.enginePid()) &&
        ['CONNECTING', 'CONNECTED'].includes(this.state.status)
      ) {
        // The supervisor is gone but the engine is not; surface it instead of
        // implying that a stop request will still be honored.
        this.update({ detail: 'supervisor-lost' });
      }
    }, 1000);
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
  }

  readJson(file) {
    try {
      const text = String(fs.readFileSync(file, 'utf8')).replace(/^\uFEFF/, '');
      const data = JSON.parse(text);
      return data && typeof data === 'object' ? data : null;
    } catch {
      return null;
    }
  }

  supervisorPid() {
    const data = this.readJson(this.supervisorFile);
    if (!data) return 0;
    if (this.supervisorNonce && String(data.nonce || '') !== this.supervisorNonce) return 0;
    const pid = Number(data.supervisorPid);
    return Number.isInteger(pid) && pid > 0 ? pid : 0;
  }

  // The supervisor writes engineStopped=false only when it tried and failed to
  // stop the engine it had verified as its own.  A user-privilege retry (or a
  // second UAC prompt running the same admin stop) cannot do better, so
  // callers report ENGINE_STOP_FAILED instead of asking again.
  supervisorConfirmedAlive() {
    const status = this.readJson(this.statusFile);
    if (!status) return false;
    if (this.supervisorNonce && String(status.nonce || '') !== this.supervisorNonce) return false;
    return status.engineStopped === false;
  }

  writeStop(reason) {
    try {
      fs.writeFileSync(this.stopFile, String(reason || 'stop'), 'ascii');
    } catch {
      // best effort: the supervisor also times out on a stale heartbeat
    }
  }

  prepareEngineMarkers() {
    for (const file of [
      this.pidFile,
      this.heartbeatFile,
      this.stopFile,
      this.readyFile,
      this.statusFile,
      this.supervisorFile
    ]) {
      try {
        fs.rmSync(file, { force: true });
      } catch {
        // ignore
      }
    }
  }

  cleanupEngineMarkers() {
    for (const file of [this.heartbeatFile, this.stopFile, this.readyFile, this.statusFile, this.supervisorFile]) {
      try {
        fs.rmSync(file, { force: true });
      } catch {
        // ignore
      }
    }
  }

  removePidFileIfDead() {
    if (this.engineAlive(this.enginePid())) return;
    try {
      fs.rmSync(this.pidFile, { force: true });
    } catch {
      // ignore
    }
  }

  // Waits for the supervisor to tear the engine down.  Resolves true when the
  // engine is gone (or there was nothing to stop).
  async stopSupervisor(reason, timeoutMs = 20000) {
    if (!this.supervisorPid()) return !this.engineAlive(this.enginePid());
    this.writeStop(reason);
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (!this.supervisorPid()) return !this.engineAlive(this.enginePid());
      if (!this.engineAlive(this.supervisorPid())) return !this.engineAlive(this.enginePid());
      await delay(150);
    }
    return !this.engineAlive(this.enginePid());
  }

  taskkill(pid) {
    return new Promise((resolve) => {
      let killer;
      try {
        killer = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true });
      } catch {
        resolve(false);
        return;
      }
      killer.once('error', () => resolve(false));
      killer.once('exit', (code) => resolve(code === 0));
    });
  }

  // Elevated fallback only for an engine that predates the supervisor.  It is
  // the one path that may show a new UAC prompt, and the caller surfaces a
  // clear failure when consent is refused.
  async elevatedStop(pid) {
    if (!pid) return false;
    try {
      const code = await spawnScript(elevateScript(legacyStopScript(pid)));
      return code === 0;
    } catch {
      return false;
    }
  }

  async killStaleEngine(pid) {
    const killed = await this.taskkill(pid);
    if (killed && (await this.waitForEngineExit(pid, 3000))) return;
    await this.elevatedStop(pid);
    await this.waitForEngineExit(pid, 5000);
  }

  // A failed attempt leaves the elevated engine retrying in the background;
  // it must die before its TAP adapter and log handle can be reused.  Returns
  // true when an engine is still alive afterwards.
  retirePreviousEngine() {
    return this.withEngineLock(() => this._retirePreviousEngine());
  }

  async _retirePreviousEngine() {
    const supervisor = this.supervisorPid();
    if (supervisor) {
      const stopped = await this.stopSupervisor('retire', 20000);
      this.stopHeartbeat();
      if (!stopped) {
        if (this.supervisorConfirmedAlive()) {
          // Confirmed alive by the supervisor's own admin stop; keep the pid
          // and status markers so the next attempt sees the same verdict.
          return this.engineAlive(this.enginePid());
        }
        await this.killStaleEngine(this.enginePid());
        this.removePidFileIfDead();
        this.cleanupEngineMarkers();
        return this.engineAlive(this.enginePid());
      }
      this.removePidFileIfDead();
      this.cleanupEngineMarkers();
      return false;
    }
    const pid = this.enginePid();
    if (!pid || !this.engineAlive(pid)) {
      this.removePidFileIfDead();
      this.cleanupEngineMarkers();
      return false;
    }
    this.send('signal SIGTERM');
    if (!(await this.waitForEngineExit(pid, 5000))) await this.killStaleEngine(pid);
    this.stopHeartbeat();
    this.removePidFileIfDead();
    this.cleanupEngineMarkers();
    return this.engineAlive(pid);
  }

  // Returns true when the engine is still running after the stop attempt.
  terminateEngine() {
    return this.withEngineLock(() => this._terminateEngine());
  }

  async _terminateEngine() {
    const supervisor = this.supervisorPid();
    if (supervisor) {
      const stopped = await this.stopSupervisor('stop', 20000);
      this.stopHeartbeat();
      if (stopped) {
        this.removePidFileIfDead();
        this.cleanupEngineMarkers();
        return false;
      }
      if (this.supervisorConfirmedAlive()) return true;
    }
    const pid = this.enginePid();
    if (!pid || !this.engineAlive(pid)) {
      this.stopHeartbeat();
      this.removePidFileIfDead();
      this.cleanupEngineMarkers();
      return false;
    }
    this.send('signal SIGTERM');
    if (!(await this.waitForEngineExit(pid, 5000))) await this.killStaleEngine(pid);
    this.stopHeartbeat();
    const alive = this.engineAlive(this.enginePid());
    if (alive) return true;
    this.removePidFileIfDead();
    this.cleanupEngineMarkers();
    return false;
  }

  // After a crash the supervisor notices the missing heartbeat on its own.
  // On the next start we signal stop as well so teardown is immediate, without
  // asking for UAC again.  A legacy engine with no supervisor is left to the
  // next connect attempt, which can elevate if it must.
  async recoverStaleSupervisor() {
    const supervisor = this.supervisorPid();
    if (!supervisor) {
      if (!this.engineAlive(this.enginePid())) this.cleanupEngineMarkers();
      return false;
    }
    const stopped = await this.stopSupervisor('startup', 15000);
    if (stopped) {
      this.stopHeartbeat();
      this.removePidFileIfDead();
      this.cleanupEngineMarkers();
    }
    return stopped;
  }

  cleanupFiles() {
    for (const file of [this.authFile, this.managementFile, this.configFile]) {
      try {
        fs.rmSync(file, { force: true });
      } catch {
        // ignore
      }
    }
    try {
      fs.rmSync(this.probeDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }

  cleanup() {
    this.stopHeartbeat();
    if (this.authWaiter) this.authWaiter.reject(new Error('STOPPED'));
    if (this.socket) {
      try {
        this.socket.destroy();
      } catch {
        // ignore
      }
    }
    this.socket = null;
    this.handshakePending = false;
    this.queued = [];
    this.managementSecret = null;
    this.cleanupFiles();
    if (this.connectWaiter) {
      this.connectWaiter.reject(new Error('STOPPED'));
      this.connectWaiter = null;
    }
  }
}

module.exports = {
  VpnSession,
  sanitizeConfig,
  summarizeLog,
  killSwitchTarget,
  resolveKillSwitchTarget,
  pinRemoteEndpoint,
  pinPreflight
};
