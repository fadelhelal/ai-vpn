'use strict';

const os = require('node:os');
const path = require('node:path');
const { Directory } = require('../src/directory');

async function main() {
  const directory = new Directory({ cacheFile: path.join(os.tmpdir(), 'aivpn-check-servers.json') });

  console.log('Fetching the VPN Gate directory…');
  const started = Date.now();
  const cached = await directory.refresh();
  console.log(`Fetched ${cached.servers.length} usable servers in ${Date.now() - started} ms.`);

  const top = cached.servers.slice(0, 6);
  console.log('\nTop candidates (before probing):');
  for (const server of top) {
    console.log(
      `  ${server.countryCode || '??'}  ${server.host.padEnd(34)} score=${String(server.score).padStart(5)} hint=${server.pingHintMs || '?'} ms`
    );
  }

  console.log('\nProbing TCP reachability (8 workers)…');
  const probed = await directory.preflight(8);
  console.log('After probing:');
  for (const server of probed.servers.slice(0, 8)) {
    console.log(
      `  ${server.countryCode || '??'}  ${server.host.padEnd(34)} latency=${server.latencyMs == null ? 'unreachable' : `${server.latencyMs} ms`}`
    );
  }
}

main().catch((error) => {
  console.error(`check-directory failed: ${error.message}`);
  process.exit(1);
});
