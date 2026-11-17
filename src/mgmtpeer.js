'use strict';

const { spawn } = require('node:child_process');

// The management socket trusts whoever answers on 127.0.0.1:<port>.  Any local
// process could bind that port before the engine does and feed forged state
// lines, so the owner is checked before the password is sent.

function parseTcpOwners(text, port) {
  const owners = new Set();
  const needle = `127.0.0.1:${Number(port)}`;
  for (const line of String(text || '').split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5 || parts[0] !== 'TCP' || parts[1] !== needle || parts[3] !== 'ESTABLISHED') continue;
    const pid = Number(parts[4]);
    if (Number.isInteger(pid) && pid > 0) owners.add(pid);
  }
  return [...owners];
}

function samePath(a, b) {
  return String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
}

function peerVerdict({ owners, enginePid, executable, enginePath }) {
  const list = Array.isArray(owners) ? owners.filter((pid) => Number.isInteger(pid) && pid > 0) : [];
  if (!list.length) return { ok: false, reason: 'owner-unknown' };
  if (enginePid && !list.includes(enginePid)) return { ok: false, reason: 'pid-mismatch' };
  const owner = enginePid && list.includes(enginePid) ? enginePid : list[0];
  if (executable && enginePath && !samePath(executable, enginePath)) return { ok: false, reason: 'path-mismatch' };
  return { ok: true, reason: null, pid: owner };
}

function runCapture(command, args, timeoutMs) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, args, { windowsHide: true });
    } catch {
      resolve(null);
      return;
    }
    let out = '';
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      try { child.kill(); } catch {}
      finish(null);
    }, timeoutMs);
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk) => { out += chunk; });
    child.once('error', () => finish(null));
    child.once('exit', () => finish(out));
  });
}

async function tcpOwners(port) {
  const text = await runCapture('netstat', ['-ano', '-p', 'tcp'], 4000);
  return text ? parseTcpOwners(text, port) : [];
}

async function processExecutable(pid) {
  const script = `$p=Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = ${Number(pid)}" -ErrorAction SilentlyContinue; if ($p) { $p.ExecutablePath }`;
  const out = await runCapture(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    4000
  );
  const path = String(out || '').trim().split(/\r?\n/).pop();
  return path && /[\\/]/.test(path) ? path : null;
}

async function verifyPeer({ port, enginePid, enginePath }) {
  const owners = await tcpOwners(port);
  let executable = null;
  const candidate = enginePid && owners.includes(enginePid) ? enginePid : owners[0];
  if (candidate) executable = await processExecutable(candidate);
  return peerVerdict({ owners, enginePid, executable, enginePath });
}

module.exports = { parseTcpOwners, peerVerdict, samePath, tcpOwners, processExecutable, verifyPeer };
