'use strict';

const https = require('node:https');
const { verifyManifest } = require('./signing');
const { RELEASE_PUBLIC_KEY } = require('./release-key');

function validFeedUrl(value) {
  try {
    const url = new URL(String(value || '').trim());
    if (url.protocol !== 'https:' || !url.hostname || ['localhost', '127.0.0.1', '::1'].includes(url.hostname)) return null;
    return url;
  } catch {
    return null;
  }
}

function versionParts(value) {
  const match = String(value || '').match(/^(\d+)\.(\d+)\.(\d+)$/);
  return match ? match.slice(1).map(Number) : null;
}

function isNewer(candidate, current) {
  const a = versionParts(candidate);
  const b = versionParts(current);
  if (!a || !b) return false;
  return a.some((part, index) => part !== b[index] && part > b[index] && a.slice(0, index).every((x, i) => x === b[i]));
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { timeout: 8000, headers: { Accept: 'application/json', 'User-Agent': 'AIVPN-update-check/1' } }, (response) => {
      if (response.statusCode !== 200) { response.resume(); reject(new Error('UPDATE_HTTP')); return; }
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
        if (body.length > 128 * 1024) request.destroy(new Error('UPDATE_TOO_LARGE'));
      });
      response.on('end', () => {
        try { resolve(JSON.parse(body)); } catch { reject(new Error('UPDATE_INVALID')); }
      });
    });
    request.once('timeout', () => request.destroy(new Error('UPDATE_TIMEOUT')));
    request.once('error', reject);
  });
}

async function checkForUpdate(feedUrl, currentVersion) {
  const url = validFeedUrl(feedUrl);
  if (!url) throw new Error('UPDATE_URL_INVALID');
  const manifest = await fetchJson(url);
  const assets = Array.isArray(manifest.assets) ? manifest.assets : [];
  const setup = assets.find((asset) => /^AI-VPN-Windows-\d+\.\d+\.\d+-Setup\.exe$/.test(String(asset.name || '')));
  if (manifest.schema !== 1 || !versionParts(manifest.version) || !setup || !/^[a-f0-9]{64}$/i.test(String(setup.sha256 || ''))) {
    throw new Error('UPDATE_INVALID');
  }
  // HTTPS protects transport, not the publisher; the manifest itself must be
  // signed by the release key baked into this build.
  if (!verifyManifest(manifest, RELEASE_PUBLIC_KEY)) throw new Error('UPDATE_SIGNATURE');
  return { current: currentVersion, latest: manifest.version, available: isNewer(manifest.version, currentVersion) };
}

module.exports = { validFeedUrl, isNewer, checkForUpdate };
