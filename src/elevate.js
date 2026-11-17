'use strict';

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');

// Everything the elevated process runs is passed inline on a fixed command
// line, never through a file under the user's profile.  A local process can
// rewrite a launch script between our write and the UAC prompt; it cannot
// rewrite a command line that is already spawned.

function hashText(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex').toUpperCase();
}

function encodeCommand(script) {
  return Buffer.from(String(script), 'utf16le').toString('base64');
}

function decodeCommand(encoded) {
  return Buffer.from(String(encoded), 'base64').toString('utf16le');
}

function psQuote(value) {
  return String(value).replace(/'/g, "''");
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readMarker(file) {
  try {
    // PowerShell 5.1 Set-Content -Encoding utf8 writes a BOM; JSON.parse does
    // not accept it, so strip it before parsing.
    const text = String(fs.readFileSync(file, 'utf8')).replace(/^\uFEFF/, '');
    const data = JSON.parse(text);
    return data && typeof data === 'object' ? data : null;
  } catch {
    return null;
  }
}

// Removes only routes that appeared while the engine was running and that sit
// on a VPN adapter.  A full route snapshot taken before launch is the baseline,
// so a default route or any other adapter's route is never touched.  OpenVPN
// DCO can keep its split-default routes after a forced exit; this deletes them
// without resetting the machine's networking.
function routeCleanupScript() {
  return [
    'function Remove-AivpnTunnelRoutes {',
    '  param([string]$StagePath)',
    '  $removedCount=0',
    "  $beforeFile=Join-Path $StagePath 'routes-before.json'",
    '  if (-not (Test-Path -LiteralPath $beforeFile)) { return -1 }',
    '  $before=@()',
    '  try { $parsed=Get-Content -Raw -LiteralPath $beforeFile | ConvertFrom-Json; $before=@($parsed) } catch { return -1 }',
    '  $seen=@{}',
    '  foreach ($r in $before) { if ($null -ne $r) { $seen["$($r.ifIndex)|$($r.DestinationPrefix)|$($r.NextHop)"]=$true } }',
    '  $vpnIds=@()',
    '  try {',
    '    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {',
    "      if ([string]$a.InterfaceDescription -match 'OpenVPN|Wintun|TAP-Windows') { $vpnIds += [int]$a.ifIndex }",
    '    }',
    '  } catch {}',
    '  if ($vpnIds.Count -eq 0) { return 0 }',
    '  foreach ($route in @(Get-NetRoute -ErrorAction SilentlyContinue)) {',
    '    if (-not ($vpnIds -contains [int]$route.ifIndex)) { continue }',
    '    $key="$($route.ifIndex)|$($route.DestinationPrefix)|$($route.NextHop)"',
    '    if ($seen.ContainsKey($key)) { continue }',
    '    try {',
    '      Remove-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.ifIndex -NextHop $route.NextHop -Confirm:$false -ErrorAction Stop',
    '      $removedCount++',
    '    } catch { $script:routeErrors++ }',
    '  }',
    '  return $removedCount',
    '}'
  ].join('\r\n');
}

// OpenVPN DCO can leave pushed DNS servers assigned to its persistent adapter
// after the engine exits. Snapshot the IPv4 DNS state before launch and restore
// it during supervisor teardown, alongside the route cleanup.
function dnsCleanupScript() {
  return [
    'function Restore-AivpnTunnelDns {',
    '  param([string]$StagePath)',
    "  $beforeFile=Join-Path $StagePath 'dns-before.json'",
    '  if (-not (Test-Path -LiteralPath $beforeFile)) { return -1 }',
    '  try { $parsed=Get-Content -Raw -LiteralPath $beforeFile | ConvertFrom-Json; $before=@($parsed) } catch { return -1 }',
    '  $known=@{}',
    '  foreach ($entry in $before) { if ($null -ne $entry) { $known[[int]$entry.InterfaceIndex]=$entry } }',
    '  $restored=0',
    '  try { $adapters=@(Get-NetAdapter -ErrorAction Stop | Where-Object { [string]$_.InterfaceDescription -match \'OpenVPN|Wintun|TAP-Windows\' }) } catch { return -1 }',
    '  foreach ($adapter in $adapters) {',
    '    $id=[int]$adapter.ifIndex',
    '    $servers=if ($known.ContainsKey($id)) { @($known[$id].ServerAddresses | Where-Object { $_ }) } else { @() }',
    '    try {',
    '      if ($servers.Count -gt 0) {',
    '        Set-DnsClientServerAddress -InterfaceIndex $id -ServerAddresses $servers -ErrorAction Stop',
    '      } else {',
    '        Set-DnsClientServerAddress -InterfaceIndex $id -ResetServerAddresses -ErrorAction Stop',
    '      }',
    '      $restored++',
    '    } catch { $script:dnsErrors++ }',
    '  }',
    '  return $restored',
    '}'
  ].join('\r\n');
}

// Get-FileHash is unavailable on some Windows PowerShell installations. The
// supervisor must still verify the staged config before launching the elevated
// engine, so use the .NET runtime shipped with Windows instead.
function sha256FileScript() {
  return [
    'function Get-AivpnSha256 {',
    '  param([string]$Path)',
    '  $bytes=[System.IO.File]::ReadAllBytes($Path)',
    '  $sha=[System.Security.Cryptography.SHA256]::Create()',
    '  try { return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace(\'-\',\'\') }',
    '  finally { $sha.Dispose() }',
    '}'
  ].join('\r\n');
}

// The elevated supervisor starts the engine and stays alive for the whole
// session.  It owns teardown, so a failed connection, a stop request, or a
// crashed UI no longer depends on a non-elevated taskkill, which Windows
// denies for an administrator process.  The heartbeat and stop markers live in
// the user profile: a same-user process can already kill the UI and rewrite
// the config, so those files are not a new privilege boundary.  The script
// itself never comes from disk.
function stageAndRunScript({
  enginePath,
  configFile,
  configHash,
  pidFile,
  heartbeatFile,
  stopFile,
  supervisorFile,
  readyFile,
  statusFile,
  nonce,
  heartbeatSecs = 30,
  cleanupRoutes = true,
  aclExtra = []
}) {
  const grants = ["'*S-1-5-32-544:(OI)(CI)F'", "'*S-1-5-18:(OI)(CI)F'"]
    .concat(aclExtra.map((identity) => `'${psQuote(identity)}'`))
    .join(' ');
  const stale = Math.max(3, Math.min(600, Number(heartbeatSecs) || 30));
  return [
    "$ErrorActionPreference='Stop'",
    `$src='${psQuote(configFile)}'`,
    `$expected='${psQuote(configHash)}'`,
    `$engine='${psQuote(enginePath)}'`,
    `$pidFile='${psQuote(pidFile)}'`,
    `$heartbeat='${psQuote(heartbeatFile)}'`,
    `$stop='${psQuote(stopFile)}'`,
    `$supervisor='${psQuote(supervisorFile)}'`,
    `$ready='${psQuote(readyFile)}'`,
    `$status='${psQuote(statusFile)}'`,
    `$nonce='${psQuote(nonce)}'`,
    `$staleSecs=${stale}`,
    `$cleanupRoutes=$${cleanupRoutes ? 'true' : 'false'}`,
    routeCleanupScript(),
    dnsCleanupScript(),
    sha256FileScript(),
    "$root=Join-Path $env:ProgramData 'AIVPN'",
    'New-Item -ItemType Directory -Path $root -Force | Out-Null',
    `icacls $root /inheritance:r /grant:r ${grants} | Out-Null`,
    "Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'stage-*' -and $_.LastWriteTime -lt (Get-Date).AddDays(-1) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue",
    "$stage=Join-Path $root ('stage-' + [guid]::NewGuid().ToString('N'))",
    'New-Item -ItemType Directory -Path $stage | Out-Null',
    `icacls $stage /inheritance:r /grant:r ${grants} | Out-Null`,
    '$enginePid=0',
    '$engineStart=$null',
    '$engineStopped=$true',
    '$removed=0',
    '$routeErrors=0',
    '$dnsRestored=0',
    '$dnsErrors=0',
    "$fail=''",
    "$reason='engine-exit'",
    'try {',
    "  Copy-Item -LiteralPath $src -Destination (Join-Path $stage 'run.ovpn') -Force",
    "  $actual=Get-AivpnSha256 -Path (Join-Path $stage 'run.ovpn')",
    '  if ($actual -ne $expected) {',
    "    $fail='tampered'",
    '  } else {',
    '    if ($cleanupRoutes) {',
    '      try {',
    "        @(Get-NetRoute -ErrorAction SilentlyContinue | Select-Object ifIndex,DestinationPrefix,NextHop) | ConvertTo-Json -Compress -Depth 3 | Set-Content -LiteralPath (Join-Path $stage 'routes-before.json') -Encoding utf8",
    "        @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object InterfaceIndex,ServerAddresses) | ConvertTo-Json -Compress -Depth 3 | Set-Content -LiteralPath (Join-Path $stage 'dns-before.json') -Encoding utf8",
    '      } catch {}',
    '    }',
    "    $p=Start-Process -FilePath $engine -ArgumentList @('--config',(Join-Path $stage 'run.ovpn')) -WindowStyle Hidden -PassThru",
    '    $enginePid=[int]$p.Id',
    '    $engineStopped=$false',
    '    $engineStart=$p.StartTime',
    '    Set-Content -LiteralPath $pidFile -Value $enginePid -Encoding ascii',
    "    @{nonce=$nonce;enginePid=$enginePid;supervisorPid=$PID;startedAt=(Get-Date).ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath $supervisor -Encoding utf8",
    "    @{nonce=$nonce;enginePid=$enginePid;supervisorPid=$PID;stage=$stage} | ConvertTo-Json -Compress | Set-Content -LiteralPath $ready -Encoding utf8",
    '    $started=Get-Date',
    '    while ($true) {',
    "      if (Test-Path -LiteralPath $stop) { $reason='stop'; break }",
    "      if ($null -eq (Get-Process -Id $enginePid -ErrorAction SilentlyContinue)) { $reason='engine-exit'; break }",
    '      $fresh=$false',
    '      if (Test-Path -LiteralPath $heartbeat) {',
    '        $age=((Get-Date)-(Get-Item -LiteralPath $heartbeat).LastWriteTime).TotalSeconds',
    '        if ($age -le $staleSecs) { $fresh=$true }',
    '      } elseif (((Get-Date)-$started).TotalSeconds -le $staleSecs) { $fresh=$true }',
    "      if (-not $fresh) { $reason='heartbeat-lost'; break }",
    '      Start-Sleep -Milliseconds 500',
    '    }',
    '  }',
    '} catch {',
    "  $fail='stage-error'",
    '}',
    "if ($fail -ne '') {",
    '  if ($enginePid -gt 0) {',
    '    $proc=Get-Process -Id $enginePid -ErrorAction SilentlyContinue',
    '    if ($null -ne $proc -and $proc.StartTime -eq $engineStart) {',
    '      Stop-Process -Id $enginePid -Force -ErrorAction SilentlyContinue',
    '      Wait-Process -Id $enginePid -Timeout 5 -ErrorAction SilentlyContinue',
    '      $proc=Get-Process -Id $enginePid -ErrorAction SilentlyContinue',
    '    }',
    '    if ($null -eq $proc) { $engineStopped=$true }',
    '  }',
    '  if ($cleanupRoutes) { try { $removed=Remove-AivpnTunnelRoutes -StagePath $stage } catch { $routeErrors++ }; try { $dnsRestored=Restore-AivpnTunnelDns -StagePath $stage } catch { $dnsErrors++ } }',
    "  @{nonce=$nonce;state='failed';reason=$fail;enginePid=$enginePid;engineStopped=$engineStopped;routesRemoved=$removed;routeErrors=$routeErrors;dnsRestored=$dnsRestored;dnsErrors=$dnsErrors;supervisorPid=$PID} | ConvertTo-Json -Compress | Set-Content -LiteralPath $status -Encoding utf8",
    "  Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue",
    '  if ($engineStopped) {',
    "    Remove-Item -LiteralPath $ready,$pidFile,$heartbeat,$supervisor -Force -ErrorAction SilentlyContinue",
    '    if ($routeErrors -eq 0 -and $dnsErrors -eq 0 -and $removed -ge 0 -and $dnsRestored -ge 0) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }',
    '  }',
    "  if ($fail -eq 'tampered') { exit 3 } else { exit 4 }",
    '}',
    'try {',
    '  $proc=Get-Process -Id $enginePid -ErrorAction SilentlyContinue',
    '  if ($null -ne $proc -and $proc.StartTime -eq $engineStart) {',
    '    Stop-Process -Id $enginePid -Force -ErrorAction SilentlyContinue',
    '    Wait-Process -Id $enginePid -Timeout 5 -ErrorAction SilentlyContinue',
    '    $proc=Get-Process -Id $enginePid -ErrorAction SilentlyContinue',
    '  }',
    '  if ($null -eq $proc) { $engineStopped=$true }',
    '} catch {}',
    'Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue',
    'if ($cleanupRoutes) { try { $removed=Remove-AivpnTunnelRoutes -StagePath $stage } catch { $routeErrors++ }; try { $dnsRestored=Restore-AivpnTunnelDns -StagePath $stage } catch { $dnsErrors++ } }',
    "@{nonce=$nonce;state='stopped';reason=$reason;enginePid=$enginePid;engineStopped=$engineStopped;routesRemoved=$removed;routeErrors=$routeErrors;dnsRestored=$dnsRestored;dnsErrors=$dnsErrors;supervisorPid=$PID;stoppedAt=(Get-Date).ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath $status -Encoding utf8",
    'if ($engineStopped) {',
    "  Remove-Item -LiteralPath $ready,$pidFile,$heartbeat,$supervisor -Force -ErrorAction SilentlyContinue",
    '  if ($routeErrors -eq 0 -and $dnsErrors -eq 0 -and $removed -ge 0 -and $dnsRestored -ge 0) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }',
    '  exit 0',
    '}',
    'exit 5'
  ].join('\r\n');
}

function legacyStopScript(pid) {
  // Last resort for an engine left behind by a build without a supervisor.
  // There is no pre-launch route snapshot for it, so only the two split-default
  // prefixes on a VPN adapter are removed, never any other route.
  return [
    "$ErrorActionPreference='Stop'",
    `Stop-Process -Id ${Number(pid)} -Force -ErrorAction SilentlyContinue`,
    "$ids=@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { [string]$_.InterfaceDescription -match 'OpenVPN|Wintun|TAP-Windows' } | Select-Object -ExpandProperty ifIndex)",
    'if ($ids.Count -gt 0) {',
    "  foreach ($p in @('0.0.0.0/1','128.0.0.0/1')) {",
    '    Get-NetRoute -DestinationPrefix $p -ErrorAction SilentlyContinue | Where-Object { $ids -contains [int]$_.ifIndex } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue',
    '  }',
    '}',
    'exit 0'
  ].join('\r\n');
}

function elevateScript(innerScript, { maxEncodedLength = 20000 } = {}) {
  const encoded = encodeCommand(innerScript);
  // powershell.exe caps a command line at 32767 characters. The staging launcher
  // passes this wrapper through -Command, so it can use a larger safe budget than
  // the kill-switch path, whose wrapper is encoded again.
  if (encoded.length > maxEncodedLength) throw new Error('LAUNCH_TOO_LARGE');
  // No -Wait: the supervisor runs for the whole session, so the launcher has to
  // return once UAC was accepted.  The ready marker tells us the engine started.
  return [
    '$ErrorActionPreference="Stop"',
    `try { $p=Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','${encoded}' -Verb RunAs -WindowStyle Hidden -PassThru } catch { exit 2 }`,
    'if ($null -eq $p) { exit 2 }',
    'exit 0'
  ].join('\r\n');
}

function spawnScript(script) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      // The outer launcher carries the base64 supervisor script inline.  It is
      // passed as a -Command argument rather than -EncodedCommand: encoding the
      // wrapper again would exceed the powershell.exe command-line limit.  The
      // script text is generated here, never read from a file.
      child = spawn(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', String(script)],
        { windowsHide: true }
      );
    } catch {
      reject(new Error('LAUNCH_FAILED'));
      return;
    }
    child.once('error', () => reject(new Error('LAUNCH_FAILED')));
    child.once('exit', (code) => resolve(code));
  });
}

async function launchStaged({
  enginePath,
  configFile,
  configText,
  pidFile,
  heartbeatFile,
  stopFile,
  supervisorFile,
  readyFile,
  statusFile,
  nonce,
  heartbeatSecs = 30,
  cleanupRoutes = true,
  startTimeoutMs = 20000
}) {
  for (const file of [readyFile, statusFile, supervisorFile, stopFile]) {
    try {
      fs.rmSync(file, { force: true });
    } catch {
      // stale markers are best-effort
    }
  }
  const inner = stageAndRunScript({
    enginePath,
    configFile,
    configHash: hashText(configText),
    pidFile,
    heartbeatFile,
    stopFile,
    supervisorFile,
    readyFile,
    statusFile,
    nonce,
    heartbeatSecs,
    cleanupRoutes
  });
  const code = await spawnScript(elevateScript(inner, { maxEncodedLength: 28000 }));
  if (code === 2) throw new Error('ELEVATION_CANCELLED');
  if (code !== 0) throw new Error('LAUNCH_FAILED');
  const deadline = Date.now() + startTimeoutMs;
  while (Date.now() < deadline) {
    const ready = readMarker(readyFile);
    if (ready && ready.nonce === nonce) return ready;
    const status = readMarker(statusFile);
    if (status && status.nonce === nonce) {
      if (status.state === 'failed') {
        throw new Error(status.reason === 'tampered' ? 'TAMPERED' : 'LAUNCH_FAILED');
      }
      // The supervisor started and the engine exited before the tunnel came up.
      if (status.state === 'stopped') throw new Error('ENGINE_FAILED');
    }
    await delay(150);
  }
  // The supervisor may be alive but wedged before its ready marker; the stop
  // file makes its next 500 ms poll exit instead of waiting out the heartbeat.
  try {
    fs.writeFileSync(stopFile, 'start-timeout', 'ascii');
  } catch {
    // heartbeat loss remains the backstop
  }
  throw new Error('SUPERVISOR_START_TIMEOUT');
}

module.exports = {
  hashText,
  encodeCommand,
  decodeCommand,
  routeCleanupScript,
  dnsCleanupScript,
  sha256FileScript,
  stageAndRunScript,
  legacyStopScript,
  elevateScript,
  spawnScript,
  launchStaged
};
