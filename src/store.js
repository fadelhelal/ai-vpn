'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { safeStorage } = require('electron');

const DEFAULTS = {
  language: 'ar',
  disclosureAccepted: false,
  rememberCredentials: false,
  enginePath: '',
  killSwitchEnabled: false,
  killSwitchStrict: true,
  engineStrict: true,
  releaseFeedUrl: '',
  privateProfileName: '',
  privateProfileExpiresAt: 0
};

// Electron 45 returns { result, shouldReEncrypt } from the asynchronous
// decrypt API. Older Electron builds return the plaintext directly.
function decryptedText(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && typeof value.result === 'string') return value.result;
  return null;
}

/**
 * Settings live next to the app data. Every secret is encrypted with the
 * Windows DPAPI through Electron safeStorage; there is no plaintext fallback.
 */
class SettingsStore {
  constructor(dir) {
    this.file = path.join(dir, 'settings.json');
    this.data = { ...DEFAULTS };
    this.secrets = {};
    this.encryptionFlag = false;
    this.load();
  }

  async detectEncryption() {
    try {
      this.encryptionFlag =
        typeof safeStorage.isAsyncEncryptionAvailable === 'function'
          ? await safeStorage.isAsyncEncryptionAvailable()
          : safeStorage.isEncryptionAvailable();
    } catch {
      this.encryptionFlag = false;
    }
    return this.encryptionFlag;
  }

  load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      if (!raw || typeof raw !== 'object') return;
      for (const key of Object.keys(DEFAULTS)) {
        if (raw[key] !== undefined) this.data[key] = raw[key];
      }
      if (raw.secrets && typeof raw.secrets === 'object') this.secrets = raw.secrets;
    } catch {
      // first run
    }
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ ...this.data, secrets: this.secrets }, null, 2), 'utf8');
    fs.renameSync(tmp, this.file);
  }

  get(key) {
    return this.data[key];
  }

  set(patch) {
    for (const [key, value] of Object.entries(patch)) {
      if (key in DEFAULTS) this.data[key] = value;
    }
    this.save();
  }

  encryptionAvailable() {
    return this.encryptionFlag;
  }

  setSecret(name, value) {
    if (value == null || value === '') {
      delete this.secrets[name];
      this.save();
      return true;
    }
    if (!this.encryptionAvailable()) return false;
    try {
      this.secrets[name] = safeStorage.encryptString(String(value)).toString('base64');
    } catch {
      return false;
    }
    this.save();
    return true;
  }

  async getSecret(name) {
    const blob = this.secrets[name];
    if (!blob) return null;
    try {
      if (typeof safeStorage.decryptStringAsync === 'function') {
        return decryptedText(await safeStorage.decryptStringAsync(Buffer.from(blob, 'base64')));
      }
      return safeStorage.decryptString(Buffer.from(blob, 'base64'));
    } catch {
      return null;
    }
  }

  async publicView() {
    return {
      language: this.data.language,
      disclosureAccepted: this.data.disclosureAccepted,
      rememberCredentials: this.data.rememberCredentials,
      username: this.data.rememberCredentials ? (await this.getSecret('username') || '') : '',
      enginePath: this.data.enginePath,
      killSwitchEnabled: this.data.killSwitchEnabled,
      killSwitchStrict: this.data.killSwitchStrict,
      engineStrict: this.data.engineStrict,
      releaseFeedUrl: this.data.releaseFeedUrl,
      privateProfileName: this.data.privateProfileName,
      privateProfileExpiresAt: this.data.privateProfileExpiresAt,
      hasPrivateProfile: Boolean(this.secrets.privateProfile),
      encryptionAvailable: this.encryptionAvailable()
    };
  }
}

module.exports = { SettingsStore, DEFAULTS, decryptedText };
