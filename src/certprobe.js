'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { fingerprintPem } = require('./certs');

const KEEP_LINE =
  /^\s*(client|tls-client|nobind|remote|proto|port|rport|resolv-retry|connect-timeout|connect-retry|connect-retry-max|verify-x509-name|ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2|key-direction|data-ciphers|data-ciphers-fallback|cipher|auth)\b/i;
const KEEP_BLOCK = new Set(['ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2']);
const DROP_LINE =
  /^\s*(dev|dev-type|route|route-ipv6|route-gateway|redirect-gateway|ifconfig|ifconfig-ipv6|dhcp-option|pull|remote-random|peer-fingerprint|remote-cert-tls|tls-version-min|auth-user-pass)\b/i;

function slash(value) {
  return String(value).replace(/\\/g, '/');
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function selectLines(raw) {
  const kept = [];
  let block = null;
  let remotes = 0;
  let connections = 0;
  for (const line of String(raw || '').split(/\r?\n/)) {
    if (block) {
      kept.push(line);
      if (/^\s*<\//.test(line)) block = null;
      continue;
    }
    const open = /^\s*<([a-z0-9-]+)>\s*$/i.exec(line);
    if (open) {
      const tag = open[1].toLowerCase();
      if (tag === 'connection') connections += 1;
      if (KEEP_BLOCK.has(tag)) {
        kept.push(line);
        block = tag;
      }
      continue;
    }
    if (DROP_LINE.test(line)) continue;
    if (/^\s*remote\s+\S+/i.test(line)) remotes += 1;
    if (KEEP_LINE.test(line)) kept.push(line);
  }
  return { kept, remotes, connections };
}

// A preflight handshake learns the peer certificate before the elevated engine
// starts.  It keeps only connection-critical directives so no profile script,
// route, or management option can run outside the app's own sanitization.
function probeConfig(rawConfig, { logFile, scriptFile, exportDir, allowLegacyTls = false }) {
  const { kept, remotes, connections } = selectLines(rawConfig);
  // Several endpoints or <connection> blocks would pin a certificate the real
  // connection may not use, so those profiles fall back to chain pinning.
  if (remotes !== 1 || connections > 0) return null;
  const client = kept.some((line) => /^\s*(client|tls-client)\b/i.test(line));
  const lines = [...kept];
  if (!client) lines.unshift('client');
  lines.push(
    'dev null',
    'verb 3',
    'mute 20',
    `log "${slash(logFile)}"`,
    'script-security 3',
    `tls-verify "${slash(scriptFile)}"`,
    `tls-export-cert "${slash(exportDir)}"`,
    'remote-cert-tls server',
    allowLegacyTls ? 'tls-version-min 1.0' : 'tls-version-min 1.2'
  );
  return `${lines.join('\n')}\n`;
}

// %peer_cert% is only valid while the verify hook runs; the copy keeps the
// depth-0 (server leaf) certificate after OpenVPN deletes its temp file.
function captureScript(dir) {
  return [
    '@echo off',
    'set "p=%peer_cert:/=\\%"',
    `if exist "%p%" copy /y "%p%" "${dir}\\captured-%1.pem" >nul`,
    'exit /b 0'
  ].join('\r\n');
}

function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  try {
    child.kill();
  } catch {
    // already gone
  }
  try {
    const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true });
    killer.on('error', () => {});
  } catch {
    // best effort
  }
}

async function removeDir(dir) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      return true;
    } catch {
      // the stopped engine may still hold a file; retry briefly
    }
    await delay(100);
  }
  return false;
}

async function probeFingerprint({
  enginePath,
  rawConfig,
  runDir,
  allowLegacyTls = false,
  timeoutMs = 12000,
  shouldAbort
}) {
  if (!enginePath) return { ok: false, reason: 'NO_ENGINE' };
  const dir = path.join(runDir, 'probe');
  const exportDir = path.join(dir, 'export');
  const logFile = path.join(dir, 'probe.log');
  const scriptFile = path.join(dir, 'capture.cmd');
  const captureFile = path.join(dir, 'captured-0.pem');
  const configFile = path.join(dir, 'probe.ovpn');
  const text = probeConfig(rawConfig, { logFile, scriptFile, exportDir, allowLegacyTls });
  if (!text) return { ok: false, reason: 'MULTI_REMOTE' };
  try {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(exportDir, { recursive: true });
    fs.writeFileSync(scriptFile, `${captureScript(dir)}\r\n`, 'utf8');
    fs.writeFileSync(configFile, text, 'utf8');
    fs.writeFileSync(logFile, '', 'utf8');
  } catch {
    return { ok: false, reason: 'PREPARE' };
  }
  const child = spawn(enginePath, ['--config', configFile], { windowsHide: true, stdio: 'ignore' });
  let exited = false;
  child.once('exit', () => {
    exited = true;
  });
  child.once('error', () => {
    exited = true;
  });
  const deadline = Date.now() + timeoutMs;
  // probe.ovpn can carry an inline client key, so the whole directory is
  // removed on every exit path, after the engine has been stopped.
  let result = { ok: false, reason: 'TIMEOUT' };
  try {
    while (Date.now() < deadline) {
      if (shouldAbort && shouldAbort()) {
        result = { ok: false, reason: 'ABORTED' };
        break;
      }
      if (fs.existsSync(captureFile)) {
        try {
          const fingerprint = fingerprintPem(fs.readFileSync(captureFile, 'utf8'));
          if (fingerprint) {
            result = { ok: true, fingerprint };
            break;
          }
        } catch {
          // file still being written; retry on the next tick
        }
      }
      if (exited) {
        result = { ok: false, reason: 'EXITED' };
        break;
      }
      await delay(150);
    }
  } finally {
    stopProcess(child);
    if (!(await removeDir(dir))) result = { ...result, cleanup: 'failed' };
  }
  return result;
}

module.exports = { probeConfig, captureScript, probeFingerprint, selectLines };
