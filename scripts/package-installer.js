'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const { version } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const candidates = [
  process.env.INNO_SETUP_COMPILER,
  'C:\\Program Files\\Inno Setup 7\\ISCC.exe',
  'C:\\Program Files (x86)\\Inno Setup 7\\ISCC.exe',
  path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Inno Setup 7', 'ISCC.exe'),
  'C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe',
  'C:\\Program Files\\Inno Setup 6\\ISCC.exe',
  path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Inno Setup 6', 'ISCC.exe')
].filter(Boolean);

function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', windowsHide: true });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${path.basename(command)} failed with exit code ${result.status}.`);
}

function main() {
  run(process.execPath, [path.join(root, 'scripts', 'package-portable.js')]);
  const compiler = candidates.find((candidate) => fs.existsSync(candidate));
  if (!compiler) {
    throw new Error('Inno Setup compiler not found. Install Inno Setup or set INNO_SETUP_COMPILER.');
  }
  run(compiler, [`/DAppVersion=${version}`, path.join(root, 'installer', 'AIVPN.iss')]);
  const setup = path.join(root, 'dist', `AI-VPN-Windows-${version}-Setup.exe`);
  if (!fs.existsSync(setup)) throw new Error('Installer output was not produced.');
  console.log(`Installer ready: ${setup}`);
}

try { main(); } catch (error) { console.error(`package-installer failed: ${error.message}`); process.exit(1); }
