'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.join(__dirname, '..');
const dist = path.join(root, 'dist');
const { version } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const files = [
  `AI-VPN-Windows-${version}-Setup.exe`,
  `AI-VPN-Windows-${version}-portable.zip`
].map((name) => {
  const target = path.join(dist, name);
  if (!fs.existsSync(target)) throw new Error(`Missing release asset: ${name}`);
  const bytes = fs.readFileSync(target);
  return { name, size: bytes.length, sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
});

const manifest = {
  schema: 1,
  version,
  releasedAt: new Date().toISOString(),
  assets: files,
  notes: 'Publish this file only over HTTPS after signing the executable assets.'
};
// The private key must never sit next to the sources: whoever copies or shares
// the project would be able to sign manifests that every copy of the app
// accepts. Keep it outside the tree (default location below) and point
// AIVPN_RELEASE_KEY at another absolute path when needed.
const keyFile = path.resolve(
  process.env.AIVPN_RELEASE_KEY || path.join(process.env.USERPROFILE || '', '.aivpn-release', 'release-signing.key')
);
const relativeToRoot = path.relative(root, keyFile);
if (!relativeToRoot.startsWith('..') && !path.isAbsolute(relativeToRoot)) {
  throw new Error('The release private key must live outside the project tree; set AIVPN_RELEASE_KEY');
}
if (!fs.existsSync(keyFile)) {
  throw new Error(`Missing release key at ${keyFile}; refusing to publish an unsigned manifest`);
}
const { signManifest, verifyManifest, keyFingerprint } = require('../src/signing');
const { RELEASE_PUBLIC_KEY } = require('../src/release-key');
manifest.signature = signManifest(manifest, fs.readFileSync(keyFile, 'utf8'));
if (!verifyManifest(manifest, RELEASE_PUBLIC_KEY)) {
  throw new Error('Signature does not verify against the public key embedded in the app');
}
const output = path.join(dist, 'release.json');
fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
console.log(`Release manifest ready: ${output}`);
console.log(`Ed25519 public key fingerprint: ${keyFingerprint(RELEASE_PUBLIC_KEY)}`);
