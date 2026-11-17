'use strict';

const SPEED_URL = 'https://speed.cloudflare.com/__down?bytes=40000000';

const EXIT_SOURCES = [
  {
    name: 'ipify',
    url: 'https://api.ipify.org?format=json',
    parse: async (response) => (await response.json()).ip
  },
  {
    name: 'cloudflare',
    url: 'https://www.cloudflare.com/cdn-cgi/trace',
    parse: async (response) => {
      const line = (await response.text()).split(/\r?\n/).find((item) => item.startsWith('ip='));
      return line ? line.slice(3).trim() : '';
    }
  }
];

async function probeExit(timeoutMs = 15000) {
  const perSourceTimeout = Math.max(3000, Math.floor(timeoutMs / EXIT_SOURCES.length));
  let lastReason = 'network';
  for (const source of EXIT_SOURCES) {
    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), perSourceTimeout);
    try {
      const response = await fetch(source.url, {
        signal: controller.signal,
        cache: 'no-store',
        headers: { accept: 'application/json, text/plain;q=0.9' }
      });
      if (!response.ok) {
        lastReason = `http_${response.status}`;
        continue;
      }
      const exit = await source.parse(response);
      if (typeof exit === 'string' && exit) {
        return { ok: true, exit, source: source.name, latencyMs: Date.now() - started };
      }
      lastReason = 'body';
    } catch (error) {
      lastReason = error && error.name === 'AbortError' ? 'timeout' : 'network';
    } finally {
      clearTimeout(timer);
    }
  }
  return { ok: false, reason: lastReason };
}

/**
 * Discards a 2 s warm-up and measures the next 6 s, mirroring the phone app.
 * A window with too few bytes is reported as unmeasured instead of guessed.
 */
async function measureDownload({ warmupMs = 2000, windowMs = 6000 } = {}) {
  const controller = new AbortController();
  try {
    const response = await fetch(SPEED_URL, { signal: controller.signal, cache: 'no-store' });
    if (!response.ok || !response.body) return null;
    let steadyBytes = 0;
    let steadyStart = null;
    let steadyEnd = null;
    const started = performance.now();
    for await (const chunk of response.body) {
      const now = performance.now();
      const elapsed = now - started;
      if (elapsed >= warmupMs) {
        if (steadyStart == null) {
          steadyStart = now;
        } else {
          steadyBytes += chunk.length;
          steadyEnd = now;
        }
      }
      if (elapsed - warmupMs >= windowMs) break;
    }
    controller.abort();
    if (steadyStart == null || steadyEnd == null) return null;
    const seconds = (steadyEnd - steadyStart) / 1000;
    if (seconds < 1 || steadyBytes < 100000) return null;
    return { mbps: (steadyBytes * 8) / 1e6 / seconds, source: 'cloudflare' };
  } catch {
    return null;
  }
}

module.exports = { probeExit, measureDownload };
