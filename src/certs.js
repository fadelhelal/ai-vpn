'use strict';

const crypto = require('node:crypto');

/** SHA-256 of the certificate DER, as lowercase hex without separators. */
function fingerprintPem(pem) {
  try {
    const cert = new crypto.X509Certificate(String(pem));
    const hex = cert.fingerprint256.replace(/:/g, '').toLowerCase();
    return hex.length === 64 ? hex : null;
  } catch {
    return null;
  }
}

/** Accepts hex with or without colons; returns 64 lowercase chars or null. */
function normalizeFingerprint(value) {
  const hex = String(value || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  return hex.length === 64 ? hex : null;
}

function colonFingerprint(value) {
  const hex = normalizeFingerprint(value);
  if (!hex) return null;
  return hex.replace(/(.{2})(?=.)/g, '$1:').toUpperCase();
}

function shortFingerprint(value) {
  const hex = normalizeFingerprint(value);
  return hex ? hex.slice(0, 16) : null;
}

module.exports = { fingerprintPem, normalizeFingerprint, colonFingerprint, shortFingerprint };
