'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { PREFIX: KILLSWITCH_PREFIX } = require('./killswitch');
const { shortFingerprint } = require('./certs');

function psJson(script, timeout = 8000) {
  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout, windowsHide: true, maxBuffer: 8 * 1024 * 1024 },
      (error, stdout) => {
        if (error || !stdout) return resolve(null);
        try {
          resolve(JSON.parse(stdout));
        } catch {
          resolve(null);
        }
      }
    );
  });
}

/** Extracts only facts that appear verbatim in the OpenVPN log. */
function parseLogFacts(text) {
  const log = String(text || '');
  const facts = {
    tunnelIp: null,
    tunnelGateway: null,
    pushedDns: [],
    tlsVersion: null,
    dataCipher: null,
    dataAuth: null,
    verifyChain: [],
    initialized: /Initialization Sequence Completed/.test(log),
    authFailed: /AUTH_FAILED/.test(log)
  };

  const assign = /ASSIGN_IP,,\s*([0-9.]+)/.exec(log);
  if (assign) facts.tunnelIp = assign[1];
  const ifconfig = /ifconfig\s+([0-9.]+)\s+([0-9.]+)/.exec(log);
  if (ifconfig) facts.tunnelIp = facts.tunnelIp || ifconfig[1];
  const gateway = /route-gateway\s+([0-9.]+)/.exec(log);
  if (gateway) {
    facts.tunnelGateway = gateway[1];
  } else if (ifconfig && !/^(255|0)\./.test(ifconfig[2])) {
    facts.tunnelGateway = ifconfig[2];
  }
  for (const match of log.matchAll(/dhcp-option DNS\s+([0-9.]+)/g)) facts.pushedDns.push(match[1]);
  const control = /Control Channel:\s*TLSv([0-9.]+)/.exec(log);
  if (control) facts.tlsVersion = control[1];
  const dataCipher = /Data Channel:\s*cipher '([^']+)'(?:,\s*auth '([^']+)')?/.exec(log);
  if (dataCipher) {
    facts.dataCipher = dataCipher[1];
    facts.dataAuth = dataCipher[2] || null;
  }
  for (const match of log.matchAll(/VERIFY OK:\s*(depth=\d+,\s*.+)$/gm)) {
    facts.verifyChain.push(match[1].trim());
  }
  return facts;
}

function weakCrypto(facts) {
  const reasons = [];
  if (facts.tlsVersion) {
    const major = Number(facts.tlsVersion.split('.')[0]);
    const minor = Number(facts.tlsVersion.split('.')[1] || 0);
    if (major < 1 || (major === 1 && minor < 2)) reasons.push(`TLS ${facts.tlsVersion}`);
  }
  if (facts.dataCipher && /CBC|BF|DES|RC4|NULL/i.test(facts.dataCipher)) reasons.push(facts.dataCipher);
  if (facts.dataAuth && /^(SHA1|MD5)$/i.test(facts.dataAuth)) reasons.push(`auth ${facts.dataAuth}`);
  return reasons;
}

// DefaultOutboundAction=Block only covers flows without a matching Allow rule:
// an explicit outbound Allow still wins, so one pre-existing wide rule reopens
// the leak. The registry store lists every rule in one read (WMI takes tens of
// seconds), including the scoping attributes that make a rule narrow.
const FIREWALL_RULES_KEY =
  'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules';

function scoped(value) {
  return value !== undefined && value !== '' && value !== '*';
}

function broadOutboundAllows(store) {
  const rules = [];
  for (const [key, raw] of Object.entries(store || {})) {
    const value = String(raw || '');
    if (!value.startsWith('v2.')) continue;
    const fields = {};
    const profiles = [];
    for (const part of value.split('|')) {
      const split = part.indexOf('=');
      if (split <= 0) continue;
      const field = part.slice(0, split);
      const text = part.slice(split + 1);
      if (field === 'Profile') profiles.push(text);
      else fields[field] = text;
    }
    if (fields.Dir !== 'Out' || fields.Action !== 'Allow' || fields.Active !== 'TRUE') continue;
    // Program, package, user, service, interface, port and address scoping all
    // narrow a rule; a rule with none of them allows every outbound flow.
    if ([fields.App, fields.AppPkg, fields.Svc, fields.PFN, fields.LUOwn].some(scoped)) continue;
    if ([fields.IF, fields.InterfaceType].some(scoped)) continue;
    if (scoped(fields.Protocol) && fields.Protocol !== '256') continue;
    if ([fields.RPort, fields.RA4, fields.RA6, fields.LPort].some(scoped)) continue;
    const label = fields.Name || fields.Desc || key;
    if (String(label).startsWith(`${KILLSWITCH_PREFIX} `)) continue;
    rules.push({ label, profiles: profiles.join('/') });
  }
  return rules;
}

function aggregateLevel(checks) {
  let worst = 'ok';
  for (const check of checks) {
    if (check.level === 'critical') return 'critical';
    if (check.level === 'warn') worst = 'warn';
    else if (check.level === 'unknown' && worst === 'ok') worst = 'unknown';
  }
  return worst;
}

/** True only when the level crosses into critical, so a lasting fault alerts once. */
function entersCritical(previousLevel, nextLevel) {
  return nextLevel === 'critical' && previousLevel !== 'critical';
}

/** A critical verdict ends an active tunnel through the normal restore path. */
function shouldDisconnectOnCritical(level, status) {
  return level === 'critical' && status === 'CONNECTED';
}

/** A usable engine must carry a valid signature from OpenVPN Inc. */
function engineTrust(signature) {
  if (!signature || !signature.status) return { ok: false, reason: 'unknown' };
  if (signature.status !== 'Valid') return { ok: false, reason: 'invalid' };
  if (!/openvpn/i.test(String(signature.signer || ''))) return { ok: false, reason: 'foreign-signer' };
  return { ok: true, reason: 'trusted' };
}

/** Fingerprints only: subject strings can be copied by a look-alike CA. */
function certVerdict(known, { chain, sha256, at }) {
  const first = String(chain || '').split(' >> ')[0];
  if (!chain) return { level: 'unknown', code: 'certNone', data: {} };
  if (!sha256) {
    // A chain string is not a pin: subject names can be copied by a look-alike
    // CA.  Without a fingerprint this session the certificate stays
    // unverified; the next preflight records a real pin.
    if (!known) {
      return { level: 'warn', code: 'certNoFingerprint', data: { first, fp: '—' } };
    }
    if (known.chain === chain) {
      return { level: 'ok', code: 'certMatch', data: { first, fp: '—' } };
    }
    return {
      level: 'critical',
      code: 'certChanged',
      data: {
        date: new Date(known.at || Date.now()).toISOString().slice(0, 10),
        old: known.chain,
        now: chain,
        first
      }
    };
  }
  const fp = shortFingerprint(sha256) || '—';
  if (!known) {
    return {
      level: 'ok',
      code: 'certPinned',
      data: { first, fp },
      pin: { chain, sha256, at }
    };
  }
  if (known.sha256) {
    if (known.sha256 === sha256) {
      return { level: 'ok', code: 'certMatch', data: { first, fp } };
    }
    return {
      level: 'critical',
      code: 'certChanged',
      data: {
        date: new Date(known.at || Date.now()).toISOString().slice(0, 10),
        oldFp: shortFingerprint(known.sha256) || '—',
        nowFp: fp,
        first
      }
    };
  }
  // A record from the chain-only era is trusted only when the string still
  // matches, and is upgraded to a fingerprint pin on the spot.
  if (known.chain === chain) {
    return {
      level: 'ok',
      code: 'certMatch',
      data: { first, fp },
      pin: { chain, sha256, at: known.at || at }
    };
  }
  return {
    level: 'critical',
    code: 'certChanged',
    data: {
      date: new Date(known.at || Date.now()).toISOString().slice(0, 10),
      old: known.chain,
      now: chain,
      first
    }
  };
}

function pinKey(server) {
  return server && server.id != null ? String(server.id) : 'private';
}

class Guard {
  constructor({ storeFile, psJson: shell = psJson }) {
    this.storeFile = storeFile;
    this.psJson = shell;
    this.pins = {};
    this.last = null;
    this.signatureCache = new Map();
    this.sessionFacts = null;
    this.lastConnectedAt = 0;
    this.auditDone = true;
    this.load();
  }

  load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.storeFile, 'utf8'));
      if (raw && typeof raw.pins === 'object') this.pins = raw.pins;
    } catch {
      // first run
    }
  }

  save() {
    try {
      fs.mkdirSync(path.dirname(this.storeFile), { recursive: true });
      fs.writeFileSync(this.storeFile, JSON.stringify({ pins: this.pins }, null, 2), 'utf8');
    } catch {
      // pins are advisory only
    }
  }

  resetPin(key) {
    if (!Object.prototype.hasOwnProperty.call(this.pins, key)) return false;
    delete this.pins[key];
    this.save();
    return true;
  }

  pinnedFingerprint(key) {
    const known = this.pins[key];
    return known && typeof known.sha256 === 'string' ? known.sha256 : null;
  }

  // The result is tied to one file, not to the Guard instance: a first check
  // of a trusted engine must not answer for a different openvpn.exe chosen
  // minutes later. Size and mtime also invalidate the entry when the file at
  // the same path is replaced. Callers that are about to launch the engine
  // elevated pass fresh: true and always re-run Authenticode.
  async signatureOf(enginePath, { fresh = false } = {}) {
    if (!enginePath) return null;
    let stat;
    try {
      stat = fs.statSync(enginePath);
    } catch {
      return null;
    }
    const key = `${path.resolve(enginePath).toLowerCase()}|${stat.size}|${Math.round(stat.mtimeMs)}`;
    const cached = this.signatureCache.get(key);
    if (!fresh && cached && Date.now() - cached.at < 10 * 60 * 1000) return cached.signature;
    const quoted = String(enginePath).replace(/'/g, "''");
    const result = await this.psJson(
      `$s = Get-AuthenticodeSignature '${quoted}'; ` +
        `@{ status = $s.Status.ToString(); signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } } | ConvertTo-Json -Compress`
    );
    const signature = result && result.status ? result : null;
    this.signatureCache.set(key, { at: Date.now(), signature });
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [entry, value] of this.signatureCache) {
      if (value.at < cutoff) this.signatureCache.delete(entry);
    }
    return signature;
  }

  async sensors() {
    const [addresses, dns, routes, routes6] = await Promise.all([
      this.psJson(
        "Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,InterfaceAlias | ConvertTo-Json -Compress"
      ),
      this.psJson(
        'Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress'
      ),
      this.psJson(
        "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' | " +
          'Select-Object DestinationPrefix,NextHop,InterfaceAlias | ConvertTo-Json -Compress'
      ),
      this.psJson(
        // Filtering after enumeration avoids a no-match error for a missing default route.
        'try { $ErrorActionPreference = "Stop"; ' +
          '$routes = @(Get-NetRoute -AddressFamily IPv6 | ' +
          "Where-Object { $_.DestinationPrefix -eq '::/0' } | " +
          'Select-Object DestinationPrefix,NextHop,InterfaceAlias); ' +
          'ConvertTo-Json -InputObject $routes -Compress } catch { exit 1 }'
      )
    ]);
    const list = (value) => (Array.isArray(value) ? value : value ? [value] : []);
    return {
      addresses: list(addresses),
      dns: list(dns),
      routes: list(routes),
      routes6: routes6 == null ? null : list(routes6)
    };
  }

  // After the tunnel is gone, anything still pointing at it (routes, DNS,
  // address) is a leftover that can silently break or leak traffic, so it gets
  // one audit per session, delayed 4s to let the adapter teardown finish.
  async auditResidual() {
    const facts = this.sessionFacts;
    const at = Date.now();
    if (!facts) {
      return { at, level: 'idle', checks: [{ id: 'session', level: 'idle', code: 'idle', data: {} }] };
    }
    const also = await this.sensors();
    const checks = [];
    const routes = facts.gateway
      ? also.routes.filter((item) => String(item.NextHop || '').includes(facts.gateway))
      : [];
    if (routes.length) {
      checks.push({
        id: 'residual',
        level: 'critical',
        code: 'residualRoute',
        data: {
          gw: facts.gateway,
          routes: routes
            .map((item) => `${item.DestinationPrefix} → ${item.NextHop} (${item.InterfaceAlias})`)
            .join(' | ')
        }
      });
    }
    const dnsLeft = facts.dns.length
      ? also.dns.filter((item) => (item.ServerAddresses || []).some((server) => facts.dns.includes(server)))
      : [];
    if (dnsLeft.length) {
      checks.push({
        id: 'residual',
        level: 'warn',
        code: 'residualDns',
        data: {
          servers: facts.dns.join(', '),
          iface: dnsLeft.map((item) => item.InterfaceAlias || '—').join(', ')
        }
      });
    }
    if (facts.ip && also.addresses.some((item) => item.IPAddress === facts.ip)) {
      checks.push({ id: 'residual', level: 'warn', code: 'residualAddress', data: { ip: facts.ip } });
    }
    if (!checks.length) {
      return { at, level: 'idle', checks: [{ id: 'session', level: 'idle', code: 'idle', data: {} }] };
    }
    return { at, level: aggregateLevel(checks), checks };
  }

  // The watchdog is trusted only after Windows itself shows the block in place.
  async firewallState() {
    const [profiles, rules, store] = await Promise.all([
      psJson(
        'Get-NetFirewallProfile | Select-Object Name,@{Name=\'DefaultOutboundAction\';Expression={[string]$_.DefaultOutboundAction}} | ConvertTo-Json -Compress'
      ),
      psJson(
        `Get-NetFirewallRule -DisplayName '${KILLSWITCH_PREFIX} *' -ErrorAction SilentlyContinue | ` +
          'Select-Object DisplayName,Enabled,Direction,Action | ConvertTo-Json -Compress'
      ),
      psJson(
        `Get-ItemProperty -Path '${FIREWALL_RULES_KEY}' -ErrorAction SilentlyContinue | ` +
          'Select-Object * -ExcludeProperty PS* | ConvertTo-Json -Compress'
      )
    ]);
    const list = (value) => (Array.isArray(value) ? value : value ? [value] : []);
    return { profiles: list(profiles), rules: list(rules), broad: broadOutboundAllows(store) };
  }

  async inspect({ state, logFile, enginePath, strict = false }) {
    const checks = [];
    const at = Date.now();
    if (!state || state.status !== 'CONNECTED') {
      if (this.sessionFacts && !this.auditDone && Date.now() - this.lastConnectedAt > 4000) {
        this.auditDone = true;
        const residual = await this.auditResidual();
        if (residual.level !== 'idle' || !this.last || this.last.level !== 'critical') {
          this.last = residual;
        }
        return this.last;
      }
      if (this.last && this.last.level === 'critical') return this.last;
      this.last = {
        at,
        level: 'idle',
        checks: [{ id: 'session', level: 'idle', code: 'idle', data: {} }]
      };
      return this.last;
    }

    let log = '';
    try {
      log = fs.readFileSync(logFile, 'utf8');
    } catch {
      log = '';
    }
    const facts = parseLogFacts(log);
    const also = await this.sensors();

    const addressHit = facts.tunnelIp
      ? also.addresses.find((item) => item.IPAddress === facts.tunnelIp)
      : null;
    if (!facts.initialized) {
      checks.push({ id: 'tunnel', level: 'critical', code: 'tunnelNotInit', data: {} });
    } else if (addressHit) {
      checks.push({
        id: 'tunnel',
        level: 'ok',
        code: 'tunnelOk',
        data: { ip: facts.tunnelIp, iface: addressHit.InterfaceAlias }
      });
    } else {
      checks.push({
        id: 'tunnel',
        level: 'critical',
        code: 'tunnelNoIface',
        data: { ip: facts.tunnelIp || '—' }
      });
    }

    const tunnelAlias = addressHit ? addressHit.InterfaceAlias : null;
    const routeHit = facts.tunnelGateway && tunnelAlias
      ? also.routes.filter((item) => item.NextHop === facts.tunnelGateway && item.InterfaceAlias === tunnelAlias)
      : [];
    const covered = new Set(routeHit.map((item) => String(item.DestinationPrefix || '')));
    const splitRoutes = ['0.0.0.0/1', '128.0.0.0/1'];
    const missingRoutes = splitRoutes.filter((prefix) => !covered.has(prefix));
    if (!facts.tunnelGateway) {
      checks.push({ id: 'route', level: 'critical', code: 'routeUnknown', data: {} });
    } else if (!missingRoutes.length) {
      checks.push({
        id: 'route',
        level: 'ok',
        code: 'routeOk',
        data: {
          routes: routeHit
            .map((item) => `${item.DestinationPrefix} → ${item.NextHop} (${item.InterfaceAlias})`)
            .join(' | ')
        }
      });
    } else if (routeHit.length) {
      checks.push({
        id: 'route',
        level: 'critical',
        code: 'routePartial',
        data: { gw: facts.tunnelGateway, missing: missingRoutes.join(', ') }
      });
    } else {
      checks.push({ id: 'route', level: 'critical', code: 'routeMissing', data: { gw: facts.tunnelGateway } });
    }

    const dnsServers = facts.pushedDns;
    const matchingDns = also.dns.filter((item) =>
      (item.ServerAddresses || []).some((server) => dnsServers.includes(server))
    );
    const dnsOnTunnel = tunnelAlias
      ? matchingDns.filter((item) => item.InterfaceAlias === tunnelAlias)
      : [];
    const dnsOutside = tunnelAlias
      ? matchingDns.filter((item) => item.InterfaceAlias !== tunnelAlias)
      : matchingDns;
    if (!dnsServers.length) {
      checks.push({ id: 'dns', level: 'warn', code: 'dnsMissing', data: { count: 0, servers: '—' } });
    } else if (dnsOutside.length) {
      checks.push({
        id: 'dns',
        level: 'warn',
        code: 'dnsOutside',
        data: {
          iface: dnsOutside.map((item) => item.InterfaceAlias || '—').join(', '),
          servers: dnsServers.join(', ')
        }
      });
    } else if (dnsOnTunnel.length) {
      checks.push({
        id: 'dns',
        level: 'ok',
        code: 'dnsOk',
        data: { count: dnsOnTunnel.length, iface: tunnelAlias, servers: dnsServers.join(', ') }
      });
    } else {
      checks.push({
        id: 'dns',
        level: 'warn',
        code: 'dnsMissing',
        data: { count: 0, servers: dnsServers.join(', ') }
      });
    }

    if (also.routes6 == null) {
      checks.push({ id: 'ipv6', level: 'unknown', code: 'ipv6Unknown', data: {} });
    } else {
      const routes6 = also.routes6;
      const outside6 = tunnelAlias
        ? routes6.filter((item) => item.InterfaceAlias !== tunnelAlias)
        : routes6;
      if (outside6.length) {
        checks.push({
          id: 'ipv6',
          level: 'warn',
          code: 'ipv6Outside',
          data: { iface: outside6.map((item) => item.InterfaceAlias || '—').join(', ') }
        });
      } else {
        checks.push({ id: 'ipv6', level: 'ok', code: 'ipv6Ok', data: { count: routes6.length } });
      }
    }

    if (state.killSwitchActive) {
      const fw = await this.firewallState();
      const open = fw.profiles.filter((profile) => String(profile.DefaultOutboundAction) !== 'Block');
      if (!fw.profiles.length) {
        checks.push({ id: 'firewall', level: 'warn', code: 'fwUnknown', data: {} });
      } else if (open.length) {
        checks.push({
          id: 'firewall',
          level: 'critical',
          code: 'fwOpen',
          data: { open: open.map((profile) => `${profile.Name}: ${profile.DefaultOutboundAction || '—'}`).join(', ') }
        });
      } else if (strict && fw.broad && fw.broad.length) {
        // The default is Block, but these rules still let a flow out. They are
        // reported, not modified: the app must not delete system firewall rules.
        checks.push({
          id: 'firewall',
          level: 'critical',
          code: 'fwOpen',
          data: {
            open: fw.broad
              .slice(0, 6)
              .map((rule) => `${rule.label} [${rule.profiles || '—'}]`)
              .join(', ')
          }
        });
      } else if (!fw.rules.length) {
        checks.push({ id: 'firewall', level: 'warn', code: 'fwNoRules', data: {} });
      } else {
        checks.push({
          id: 'firewall',
          level: 'ok',
          code: 'fwOk',
          data: { profiles: fw.profiles.length, rules: fw.rules.length }
        });
      }
    }

    const reasons = weakCrypto(facts);
    let cryptoLevel = 'unknown';
    let cryptoCode = 'cryptoPartial';
    if (reasons.length) {
      cryptoLevel = 'warn';
      cryptoCode = 'cryptoWeak';
    } else if (facts.tlsVersion && facts.dataCipher) {
      cryptoLevel = 'ok';
      cryptoCode = 'cryptoOk';
    }
    checks.push({
      id: 'crypto',
      level: cryptoLevel,
      code: cryptoCode,
      data: {
        reasons: reasons.join(' · '),
        tls: facts.tlsVersion ? `TLS ${facts.tlsVersion}` : 'TLS —',
        cipher: facts.dataCipher || '—',
        auth: facts.dataAuth || '—'
      }
    });

    const key = pinKey(state.server);
    const chain = facts.verifyChain.join(' >> ');
    const sha256 = typeof state.certFingerprint === 'string' ? state.certFingerprint : null;
    const verdict = certVerdict(this.pins[key], { chain, sha256, at });
    if (verdict.pin) {
      this.pins[key] = verdict.pin;
      this.save();
    }
    checks.push({ id: 'cert', level: verdict.level, code: verdict.code, data: verdict.data });

    const signature = await this.signatureOf(enginePath);
    const trust = engineTrust(signature);
    if (!signature) {
      checks.push({ id: 'engine', level: 'unknown', code: 'engineUnknown', data: {} });
    } else if (trust.ok) {
      checks.push({
        id: 'engine',
        level: 'ok',
        code: 'engineValid',
        data: { signer: signature.signer || '—' }
      });
    } else if (trust.reason === 'foreign-signer') {
      checks.push({
        id: 'engine',
        level: 'warn',
        code: 'engineForeign',
        data: { signer: signature.signer || '—' }
      });
    } else {
      checks.push({
        id: 'engine',
        level: 'warn',
        code: 'engineWarn',
        data: { status: signature.status, signer: signature.signer || '—' }
      });
    }

    this.sessionFacts = {
      ip: facts.tunnelIp || null,
      gateway: facts.tunnelGateway || null,
      dns: facts.pushedDns || [],
      alias: addressHit ? addressHit.InterfaceAlias : null
    };
    this.lastConnectedAt = at;
    this.auditDone = false;

    const level = aggregateLevel(checks);

    this.last = { at, level, checks };
    return this.last;
  }
}

module.exports = {
  Guard,
  parseLogFacts,
  weakCrypto,
  aggregateLevel,
  entersCritical,
  shouldDisconnectOnCritical,
  engineTrust,
  certVerdict,
  pinKey,
  broadOutboundAllows
};
