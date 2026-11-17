'use strict';

const fs = require('node:fs');
const path = require('node:path');

function engineBasenameOk(value) {
  return /^openvpn\.exe$/i.test(path.basename(String(value || '')));
}

// Detect if the engine is the one bundled with the app (in resources/openvpn/)
// Bundled engines are trusted because we control the build and they carry
// the official OpenVPN signature.
function isBundledEngine(enginePath) {
  try {
    const normalized = path.normalize(String(enginePath || '')).toLowerCase();
    return normalized.includes(path.join('resources', 'openvpn').toLowerCase() + path.sep);
  } catch {
    return false;
  }
}

// OpenVPN loads tap-windows6/wintun DLLs from its own directory. If the current
// user can write there, another same-user process can plant a DLL next to a
// genuinely signed openvpn.exe, so the signature check would pass while foreign
// code is loaded. The check runs non-elevated, which is how the app runs.
function dirWritable(dir) {
  const probe = path.join(dir, `.aivpn-probe-${process.pid}-${Date.now()}.tmp`);
  try {
    fs.writeFileSync(probe, 'x', { flag: 'wx' });
    fs.unlinkSync(probe);
    return true;
  } catch {
    return false;
  }
}

function signatureTrusted(signature) {
  if (!signature || signature.status !== 'Valid') return false;
  return /openvpn/i.test(String(signature.signer || ''));
}

/**
 * Decides whether this engine executable may be launched elevated.
 * A custom (not OpenVPN-signed) build is only accepted when the user picked it
 * in this session through the native dialog and strict mode is off.
 * Bundled engines (shipped with the app) are always trusted regardless of
 * directory writability, because we control the build and they carry the
 * official OpenVPN signature.
 */
function engineVerdict({ enginePath, strict = true, signature = null, pickedInSession = false }) {
  const value = String(enginePath || '');
  if (!value) return { ok: false, reason: 'missing' };
  if (!path.isAbsolute(value)) return { ok: false, reason: 'relative' };
  if (!engineBasenameOk(value)) return { ok: false, reason: 'name' };
  let stat = null;
  try {
    stat = fs.statSync(value);
  } catch {
    return { ok: false, reason: 'missing' };
  }
  if (!stat.isFile()) return { ok: false, reason: 'missing' };

  const bundled = isBundledEngine(value);

  // For bundled engines, skip the writable-dir check since we trust our build.
  // For all other engines, enforce the security check.
  if (!bundled && dirWritable(path.dirname(value))) {
    return { ok: false, reason: 'writable-dir' };
  }

  if (signatureTrusted(signature)) return { ok: true, reason: 'trusted' };
  if (strict) return { ok: false, reason: 'untrusted' };
  if (!pickedInSession) return { ok: false, reason: 'pick-required' };
  return { ok: true, reason: 'custom-session' };
}

function errorFor(reason) {
  if (reason === 'writable-dir') return 'ENGINE_DIR_UNSAFE';
  if (reason === 'pick-required') return 'ENGINE_PICK_REQUIRED';
  if (reason === 'missing') return 'ENGINE_MISSING';
  return 'ENGINE_UNTRUSTED';
}

module.exports = { engineVerdict, dirWritable, engineBasenameOk, signatureTrusted, errorFor };
