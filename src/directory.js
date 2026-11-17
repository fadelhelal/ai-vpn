'use strict';

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const DIRECTORY_URL = 'https://www.vpngate.net/api/iphone/';
const USER_AGENT = 'AIVPN-Windows/0.1 (+https://www.vpngate.net/)';
const CONFIG_FIELD = 14;
const FETCH_TIMEOUT_MS = 120000;

function sortServers(a, b) {
  const aReach = a.latencyMs != null ? 0 : 1;
  const bReach = b.latencyMs != null ? 0 : 1;
  if (aReach !== bReach) return aReach - bReach;
  if (aReach === 0 && a.latencyMs !== b.latencyMs) return a.latencyMs - b.latencyMs;
  if (b.score !== a.score) return b.score - a.score;
  const aHint = a.pingHintMs == null ? 9999 : a.pingHintMs;
  const bHint = b.pingHintMs == null ? 9999 : b.pingHintMs;
  return aHint - bHint;
}

function remoteTarget(config) {
  const remote = /^\s*remote\s+(\S+)(?:\s+(\d+))?/mi.exec(config || '');
  if (!remote) return null;
  const proto = (/^\s*proto\s+(\S+)/mi.exec(config) || [])[1] || 'udp';
  const port = remote[2] ? Number(remote[2]) : 1194;
  return { host: remote[1], port: proto.startsWith('tcp') ? port : 443 };
}

function tcpLatency(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    const socket = net.connect({ host, port });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(Number(process.hrtime.bigint() - started) / 1e6));
    socket.once('timeout', () => finish(null));
    socket.once('error', () => finish(null));
  });
}

function parseDirectory(text) {
  const servers = [];
  const configs = new Map();
  let sawHeader = false;
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('*')) continue;
    if (line.startsWith('#')) {
      if (line.toLowerCase().includes('hostname')) sawHeader = true;
      continue;
    }
    if (!sawHeader) continue;
    const cols = line.split(',');
    if (cols.length <= CONFIG_FIELD) continue;
    let config;
    try {
      config = Buffer.from(cols[CONFIG_FIELD], 'base64').toString('utf8');
    } catch {
      continue;
    }
    if (!/^\s*client\s*$/mi.test(config) || !/^\s*remote\s+\S+/mi.test(config)) continue;
    const host = (cols[0] || '').trim();
    const ip = (cols[1] || '').trim();
    if (!host || !ip) continue;
    const id = `${host}|${ip}`;
    if (configs.has(id)) continue;
    configs.set(id, config);
    servers.push({
      id,
      host,
      ip,
      country: (cols[5] || '').trim(),
      countryCode: (cols[6] || '').trim(),
      score: Number(cols[2]) || 0,
      pingHintMs: Number(cols[3]) || null,
      speedHintBps: Number(cols[4]) || null,
      sessions: Number(cols[7]) || 0,
      latencyMs: null
    });
  }
  servers.sort(sortServers);
  return { servers, configs };
}

class Directory {
  constructor({ cacheFile }) {
    this.cacheFile = cacheFile;
    this.servers = [];
    this.configs = new Map();
    this.fetchedAt = 0;
    this.loadCache();
  }

  loadCache() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.cacheFile, 'utf8'));
      if (Array.isArray(raw.servers)) {
        // Cached metadata only: previous latency samples are dropped so the UI
        // never presents a stale measurement as current.
        this.servers = raw.servers.map((server) => ({ ...server, latencyMs: null }));
        this.fetchedAt = Number(raw.fetchedAt) || 0;
      }
    } catch {
      // no cache yet
    }
  }

  saveCache() {
    try {
      fs.mkdirSync(path.dirname(this.cacheFile), { recursive: true });
      fs.writeFileSync(
        this.cacheFile,
        JSON.stringify({ fetchedAt: this.fetchedAt, servers: this.servers }),
        'utf8'
      );
    } catch {
      // cache is an optimisation only
    }
  }

  cached() {
    return { servers: this.servers, fetchedAt: this.fetchedAt };
  }

  configFor(id) {
    return this.configs.get(id) || null;
  }

  async refresh({ onProgress } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const response = await fetch(DIRECTORY_URL, {
        headers: { 'user-agent': USER_AGENT, accept: 'text/plain', 'accept-encoding': 'gzip, deflate' },
        signal: controller.signal
      });
      if (!response.ok) throw new Error(`DIRECTORY_HTTP_${response.status}`);

      let text;
      if (response.body && typeof onProgress === 'function') {
        const chunks = [];
        let received = 0;
        for await (const chunk of response.body) {
          chunks.push(chunk);
          received += chunk.length;
          onProgress(received);
        }
        text = Buffer.concat(chunks).toString('utf8');
      } else {
        text = await response.text();
      }

      const parsed = parseDirectory(text);
      if (!parsed.servers.length) throw new Error('DIRECTORY_EMPTY');
      this.servers = parsed.servers;
      this.configs = parsed.configs;
      this.fetchedAt = Date.now();
      this.saveCache();
      return this.cached();
    } catch (error) {
      if (error && error.name === 'AbortError') throw new Error('DIRECTORY_TIMEOUT');
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Measures TCP reachability for the best candidates; UDP relays are probed on 443. */
  async preflight(limit = 24) {
    if (!this.configs.size) throw new Error('DIRECTORY_REQUIRED');
    const candidates = this.servers.filter((server) => this.configs.has(server.id)).slice(0, limit);
    const results = new Map();
    const queue = candidates.slice();
    const workers = Array.from({ length: Math.min(8, queue.length) }, async () => {
      for (;;) {
        const server = queue.shift();
        if (!server) return;
        const target = remoteTarget(this.configs.get(server.id));
        results.set(server.id, target ? await tcpLatency(target.host, target.port, 1600) : null);
      }
    });
    await Promise.all(workers);
    this.servers = this.servers.map((server) =>
      results.has(server.id)
        ? { ...server, latencyMs: results.get(server.id) == null ? null : Math.round(results.get(server.id)) }
        : server
    );
    this.servers.sort(sortServers);
    this.saveCache();
    return this.cached();
  }
}

module.exports = { Directory, parseDirectory, remoteTarget, tcpLatency, sortServers };
