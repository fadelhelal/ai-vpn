'use strict';

const crypto = require('node:crypto');

// The signed payload is a fixed projection of the manifest, so a feed cannot
// smuggle extra fields past the signature check or reorder hashes.
function canonicalManifest(manifest) {
  const assets = (Array.isArray(manifest.assets) ? manifest.assets : []).map((asset) => ({
    name: String(asset.name || ''),
    size: Number(asset.size),
    sha256: String(asset.sha256 || '').toLowerCase()
  }));
  return JSON.stringify({
    schema: manifest.schema,
    version: String(manifest.version || ''),
    releasedAt: String(manifest.releasedAt || ''),
    assets
  });
}

function signManifest(manifest, privateKeyPem) {
  const key = crypto.createPrivateKey(privateKeyPem);
  return crypto.sign(null, Buffer.from(canonicalManifest(manifest), 'utf8'), key).toString('base64');
}

function verifyManifest(manifest, publicKeyPem) {
  const signature = Buffer.from(String(manifest.signature || ''), 'base64');
  if (!signature.length) return false;
  try {
    return crypto.verify(
      null,
      Buffer.from(canonicalManifest(manifest), 'utf8'),
      crypto.createPublicKey(publicKeyPem),
      signature
    );
  } catch {
    return false;
  }
}

function keyFingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
}

module.exports = { canonicalManifest, signManifest, verifyManifest, keyFingerprint };
