'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DAY = 24 * 60 * 60 * 1000;
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const KEYWORDS = ['openvpn', 'softether'];

function trimTitle(value) {
  const text = String(value || '').trim().replace(/\s+/g, ' ');
  if (text.length <= 160) return text;
  const cut = text.slice(0, 160);
  const space = cut.lastIndexOf(' ');
  return `${(space > 80 ? cut.slice(0, space) : cut).trim()}…`;
}

function severityOf(cve) {
  const metrics = cve && cve.metrics ? cve.metrics : {};
  for (const key of Object.keys(metrics)) {
    const entry = Array.isArray(metrics[key]) ? metrics[key][0] : null;
    const data = entry && (entry.cvssData || entry.cvssV3 || entry.cvssV2);
    if (data && (data.baseSeverity || data.severity)) return String(data.baseSeverity || data.severity);
  }
  return 'unknown';
}

function parseNvd(payload) {
  const items = [];
  const vulnerabilities = (payload && payload.vulnerabilities) || [];
  for (const entry of vulnerabilities) {
    const cve = entry && entry.cve;
    if (!cve || !cve.id) continue;
    const description = ((cve.descriptions || []).find((item) => item.lang === 'en') || {}).value || '';
    const published = String(cve.published || '').slice(0, 10);
    items.push({
      id: cve.id,
      title: trimTitle(description),
      severity: severityOf(cve),
      published,
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      source: 'NVD'
    });
  }
  return items;
}

function parseKev(payload) {
  const items = [];
  const list = (payload && payload.vulnerabilities) || [];
  for (const entry of list) {
    const vendor = `${entry.vendorProject || ''} ${entry.product || ''}`.toLowerCase();
    if (!KEYWORDS.some((word) => vendor.includes(word))) continue;
    items.push({
      id: entry.cveID,
      title: trimTitle(entry.vulnerabilityName || entry.shortDescription),
      severity: 'KNOWN_EXPLOITED',
      published: String(entry.dateAdded || '').slice(0, 10),
      url: `https://nvd.nist.gov/vuln/detail/${entry.cveID}`,
      source: 'CISA KEV'
    });
  }
  return items;
}

async function getJson(url, timeoutMs = 20000) {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { accept: 'application/json', 'user-agent': 'AIVPN/0.1 (guard intel)' }
  });
  if (!response.ok) throw new Error(`INTEL_HTTP_${response.status}`);
  return response.json();
}

class Intel {
  constructor({ cacheFile }) {
    this.cacheFile = cacheFile;
    this.data = { fetchedAt: 0, items: [] };
    this.load();
  }

  load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.cacheFile, 'utf8'));
      if (raw && Array.isArray(raw.items)) {
        this.data = { fetchedAt: Number(raw.fetchedAt) || 0, items: raw.items };
      }
    } catch {
      // no cache yet
    }
  }

  cached() {
    return { ...this.data, fresh: Date.now() - this.data.fetchedAt < DAY };
  }

  save() {
    try {
      fs.mkdirSync(path.dirname(this.cacheFile), { recursive: true });
      fs.writeFileSync(this.cacheFile, JSON.stringify(this.data, null, 2), 'utf8');
    } catch {
      // cache is best-effort
    }
  }

  async refresh({ force = false } = {}) {
    if (!force && Date.now() - this.data.fetchedAt < DAY) return this.cached();
    const since = new Date(Date.now() - 60 * DAY).toISOString().replace(/\.\d{3}Z$/, 'Z');
    const until = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const items = [];
    const errors = [];
    for (const keyword of KEYWORDS) {
      try {
        const payload = await getJson(
          `${NVD}?keywordSearch=${encodeURIComponent(keyword)}&pubStartDate=${since}&pubEndDate=${until}&resultsPerPage=20`
        );
        items.push(...parseNvd(payload));
      } catch (error) {
        errors.push(`${keyword}:${error.message}`);
      }
    }
    try {
      items.push(...parseKev(await getJson(KEV)));
    } catch (error) {
      errors.push(`kev:${error.message}`);
    }

    const seen = new Set();
    const unique = items
      .filter((item) => {
        if (!item.id || seen.has(item.id)) return false;
        seen.add(item.id);
        return true;
      })
      .sort((a, b) => String(b.published).localeCompare(String(a.published)))
      .slice(0, 40);

    if (unique.length || !this.data.items.length) {
      this.data = { fetchedAt: Date.now(), items: unique };
      this.save();
    }
    return { ...this.cached(), errors };
  }
}

module.exports = { Intel, parseNvd, parseKev };
