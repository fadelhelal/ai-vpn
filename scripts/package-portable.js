'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const electronDist = path.join(root, 'node_modules', 'electron', 'dist');
const outDir = path.join(root, 'dist', 'AIVPN');
const appDir = path.join(outDir, 'resources', 'app');

const APP_FILES = ['main.js', 'preload.js', 'package.json', 'src', 'renderer', 'assets'];
const DIST_DOCS = [
  { from: path.join(root, 'LICENSE'), to: 'LICENSE' },
  { from: path.join(root, 'docs', 'PRIVACY_AR.md'), to: 'PRIVACY_AR.md' }
];

// OpenVPN bundled files to copy from standard install location
const OPENVPN_FILES = [
  'openvpn.exe',
  'libcrypto-3-x64.dll',
  'libssl-3-x64.dll',
  'wintun.dll',
  'tapctl.exe',
  'openvpnserv.exe',
  'ovpn-dco-win.dll'
];

const OPENVPN_SOURCE_DIRS = [
  'C:\\Program Files\\OpenVPN\\bin',
  'C:\\Program Files (x86)\\OpenVPN\\bin'
];

const README = `AI VPN — نسخة Windows محمولة
================================

1) شغّل AIVPN.exe مباشرة — OpenVPN 2.6 مضمّن في الحزمة.
2) افتح «الإعدادات»، واستورد ملف OpenVPN الخاص بك مرة واحدة، ثم اضغط زر الطاقة في الرئيسية.
3) وافق على طلب صلاحية المسؤول (UAC) الذي يظهر عند كل اتصال.

ملاحظات:
- لا يحتاج تثبيت OpenVPN منفصلاً؛ المحرك مضمّن مع التطبيق.
- الملف غير موقّع بشهادة كود؛ سيعرض SmartScreen تحذير «ناشر غير معروف».
- الإعدادات والأسرار المشفرة تُحفظ في: %APPDATA%\\AIVPN
- لا إعلانات ولا تتبع. راجع PRIVACY_AR.md.
- الترخيص: MIT (LICENSE). OpenVPN مضمّن تحت ترخيص GPLv2.
`;

function copyApp() {
  fs.mkdirSync(appDir, { recursive: true });
  for (const item of APP_FILES) {
    const source = path.join(root, item);
    const target = path.join(appDir, item);
    fs.cpSync(source, target, { recursive: true });
  }
  fs.rmSync(path.join(outDir, 'resources', 'default_app.asar'), { force: true });
  assertNoPrivateKeys(appDir);
}

function copyBundledOpenVPN() {
  const targetDir = path.join(outDir, 'resources', 'openvpn');
  fs.mkdirSync(targetDir, { recursive: true });

  let copied = 0;
  for (const sourceDir of OPENVPN_SOURCE_DIRS) {
    if (!fs.existsSync(sourceDir)) continue;
    for (const file of OPENVPN_FILES) {
      const source = path.join(sourceDir, file);
      const target = path.join(targetDir, file);
      try {
        if (fs.existsSync(source)) {
          fs.copyFileSync(source, target);
          copied++;
        }
      } catch {
        // ignore individual file errors
      }
    }
    if (copied > 0) break; // found a valid install, stop searching
  }

  if (copied === 0) {
    console.warn('⚠ OpenVPN not found in standard locations. Bundle will work only if user has OpenVPN installed separately.');
    console.warn('   Expected locations:', OPENVPN_SOURCE_DIRS.join(', '));
  } else {
    console.log(`✓ Bundled ${copied} OpenVPN file(s) from standard install location.`);
  }
}

// A release private key next to the sources would let anyone who receives the
// project sign updates that every install accepts, so packaging fails loudly
// if one ever lands in the copied tree.
function assertNoPrivateKeys(dir) {
  if (fs.existsSync(path.join(dir, 'keys'))) throw new Error('Refusing to package a keys/ directory');
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) { stack.push(full); continue; }
      if (/\.(key|pem|p12|pfx)$/i.test(entry.name)) throw new Error(`Refusing to package a key file: ${full}`);
      if (!/\.(js|json|md|txt|html|css|yml|yaml)$/i.test(entry.name)) continue;
      if (entry.size > 2 * 1024 * 1024) continue;
      const text = fs.readFileSync(full, 'utf8');
      if (/BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/.test(text)) throw new Error(`Refusing to package an embedded private key: ${full}`);
    }
  }
}

async function stampMetadata(exePath) {
  let rcedit;
  try {
    const module = require('rcedit');
    rcedit = typeof module === 'function' ? module : module.rcedit;
  } catch {
    rcedit = null;
  }
  if (typeof rcedit !== 'function') {
    console.warn('rcedit is not available — the exe keeps the default Electron icon.');
    return;
  }
  const { version } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  await rcedit(exePath, {
    icon: path.join(root, 'assets', 'icon.ico'),
    'file-version': version,
    'product-version': version,
    'version-string': {
      ProductName: 'AI VPN',
      FileDescription: 'AI VPN — free OpenVPN client',
      CompanyName: 'AIVPN contributors',
      LegalCopyright: 'MIT License'
    }
  });
}

// Compress-Archive can silently drop a file that is briefly locked (for
// example right after rcedit rewrites AIVPN.exe), and the resulting zip still
// has a valid checksum. Read the central directory back and require every
// staged file to be present before the archive is accepted.
function zipEntries(file) {
  const buffer = fs.readFileSync(file);
  const eocd = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) throw new Error('ZIP end-of-central-directory record is missing');
  const count = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let index = 0; index < count; index += 1) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) throw new Error('ZIP central directory is corrupt');
    const uncompressed = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength).replace(/\\/g, '/');
    if (!name.endsWith('/')) entries.set(name, uncompressed);
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function stagedFiles(dir, prefix = 'AIVPN/') {
  const files = new Map();
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) { stack.push(full); continue; }
      const relative = path.relative(dir, full).replace(/\\/g, '/');
      files.set(prefix + relative, fs.statSync(full).size);
    }
  }
  return files;
}

function assertArchiveComplete(archive, dir) {
  const expected = stagedFiles(dir);
  const actual = zipEntries(archive);
  const missing = [...expected.keys()].filter((name) => !actual.has(name));
  const wrongSize = [...expected.entries()].filter(([name, size]) => actual.has(name) && actual.get(name) !== size);
  if (missing.length || wrongSize.length) {
    const parts = [];
    if (missing.length) parts.push(`missing ${missing.length} (${missing.slice(0, 5).join(', ')})`);
    if (wrongSize.length) parts.push(`size mismatch ${wrongSize.length}`);
    throw new Error(`ZIP archive is incomplete: ${parts.join('; ')}`);
  }
}

function createArchive(archive) {
  const zip = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', "Compress-Archive -Path 'AIVPN' -DestinationPath '" + archive.replace(/'/g, "''") + "' -Force"],
    { cwd: path.join(root, 'dist'), encoding: 'utf8', windowsHide: true }
  );
  if (zip.status !== 0 || !fs.existsSync(archive)) {
    throw new Error(`ZIP creation failed: ${(zip.stderr || zip.stdout || 'unknown error').trim()}`);
  }
}

async function main() {
  if (!fs.existsSync(path.join(electronDist, 'electron.exe'))) {
    throw new Error('Electron runtime not found. Run "npm install" first.');
  }
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  fs.cpSync(electronDist, outDir, { recursive: true });

  const exe = path.join(outDir, 'AIVPN.exe');
  fs.renameSync(path.join(outDir, 'electron.exe'), exe);

  copyApp();
  copyBundledOpenVPN();
  for (const doc of DIST_DOCS) {
    fs.copyFileSync(doc.from, path.join(outDir, doc.to));
  }
  fs.writeFileSync(path.join(outDir, 'README.txt'), `\uFEFF${README}`, 'utf8');

  await stampMetadata(exe);
  const { version } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const archive = path.join(root, 'dist', `AI-VPN-Windows-${version}-portable.zip`);
  const checksum = `${archive}.sha256`;
  fs.rmSync(archive, { force: true });
  fs.rmSync(checksum, { force: true });
  let archiveError = null;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    fs.rmSync(archive, { force: true });
    try {
      createArchive(archive);
      assertArchiveComplete(archive, outDir);
      archiveError = null;
      break;
    } catch (error) {
      archiveError = error;
      if (attempt === 1) spawnSync(process.execPath, ['-e', 'setTimeout(() => {}, 2000)']);
    }
  }
  if (archiveError) throw archiveError;
  const digest = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
  fs.writeFileSync(checksum, `${digest}  ${path.basename(archive)}\n`, 'utf8');
  console.log(`Portable build ready: ${exe}`);
  console.log(`Archive ready: ${archive}`);
  console.log(`SHA-256 ready: ${checksum}`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`package-portable failed: ${error.message}`);
    process.exit(1);
  });
}

module.exports = { assertNoPrivateKeys };
