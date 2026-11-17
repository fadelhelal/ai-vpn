'use strict';

const fs = require('node:fs');
const { X509Certificate } = require('node:crypto');

const MAX_PROFILE_BYTES = 512 * 1024;

function validateOpenVpnProfile(text) {
  if (typeof text !== 'string' || text.length === 0) return false;
  if (Buffer.byteLength(text, 'utf8') > MAX_PROFILE_BYTES) return false;
  const lower = text.toLowerCase();
  return (
    /^\s*client\s*$/mi.test(text) &&
    /^\s*remote\s+\S+/mi.test(text) &&
    lower.includes('<ca>') &&
    lower.includes('</ca>') &&
    lower.includes('<cert>') &&
    lower.includes('</cert>') &&
    lower.includes('<key>') &&
    lower.includes('</key>')
  );
}

/** The size check happens on the file metadata, before the file is read. */
function readProfileFile(filePath) {
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error('PROFILE_INVALID');
  if (stat.size > MAX_PROFILE_BYTES) throw new Error('PROFILE_TOO_LARGE');
  const text = fs.readFileSync(filePath, 'utf8');
  if (!validateOpenVpnProfile(text)) throw new Error('PROFILE_INVALID');
  return text;
}

function profileInfo(text) {
  const certificate = /<cert>\s*([\s\S]*?)\s*<\/cert>/i.exec(text || '');
  if (!certificate) return { expiresAt: 0 };
  try {
    const expiresAt = Date.parse(new X509Certificate(certificate[1]).validTo);
    return { expiresAt: Number.isFinite(expiresAt) ? expiresAt : 0 };
  } catch {
    return { expiresAt: 0 };
  }
}

module.exports = { MAX_PROFILE_BYTES, validateOpenVpnProfile, readProfileFile, profileInfo };
