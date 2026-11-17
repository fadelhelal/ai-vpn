'use strict';

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { elevateScript } = require('./elevate');

const PREFIX = 'AI VPN Kill Switch';
const READY_TIMEOUT_MS = 20000;
const HEALTH_TIMEOUT_MS = 10000;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readJson(file) {
  try {
    const text = String(fs.readFileSync(file, 'utf8')).replace(/^\uFEFF/, '');
    const data = JSON.parse(text);
    return data && typeof data === 'object' ? data : null;
  } catch {
    return null;
  }
}

function q(value) {
  return String(value).replace(/'/g, "''");
}

function firewallProgramPath(value) {
  return path.win32.normalize(String(value || '')).replace(/\//g, '\\');
}

function restoreBlock() {
  return `
function Assert-AivpnSnapshot($saved) {
  $saved=@($saved)
  if ($saved.Count -ne 3) { throw 'invalid-snapshot-count' }
  foreach ($name in @('Domain','Private','Public')) {
    $p=@($saved | Where-Object { [string]$_.Name -eq $name })
    if ($p.Count -ne 1 -or @('Allow','Block','NotConfigured') -notcontains [string]$p[0].DefaultOutboundAction) { throw 'invalid-snapshot-profile' }
  }
}
function Read-AivpnSnapshot {
  if (-not (Test-Path -LiteralPath $backup)) { throw 'snapshot-missing' }
  $saved=@(Get-Content -Raw -LiteralPath $backup -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
  Assert-AivpnSnapshot $saved
  return $saved
}
function Restore-AivpnPolicy {
  $saved=$null
  # If the watchdog died before writing its snapshot, only recover the
  # unmistakable all-Block state which it created; otherwise never guess.
  try { $saved=@(Read-AivpnSnapshot) } catch {
    $current=@(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
    $allBlocked=($current.Count -eq 3 -and @($current | Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' }).Count -eq 0)
    if (-not $allBlocked) { throw }
    Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.DisplayName -like "$prefix *" } | Remove-NetFirewallRule -ErrorAction Stop
    Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public -DefaultOutboundAction NotConfigured -ErrorAction Stop
    return
  }
  Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.DisplayName -like "$prefix *" } | Remove-NetFirewallRule -ErrorAction Stop
  foreach ($p in $saved) { Set-NetFirewallProfile -PolicyStore PersistentStore -Profile $p.Name -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction Stop }
  Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
}`;
}

function watchdogScript(options) {
  const { heartbeat, stop, lock, backup, ready, failed, nonce, enginePid, strict, enginePath, host, port, protocol } = options;
  const programPath = firewallProgramPath(enginePath);
  return `
$ErrorActionPreference='Stop'
$prefix='${PREFIX}'
$heartbeat='${q(heartbeat)}'
$stop='${q(stop)}'
$lock='${q(lock)}'
$backup='${q(backup)}'
$ready='${q(ready)}'
$failed='${q(failed)}'
$nonce='${q(nonce)}'
$strict=$${strict ? 'true' : 'false'}
$enginePid=${Number(enginePid) || 0}
 $enginePath='${q(programPath)}'
$hostRemote='${q(host)}'
$protocol='${q(protocol)}'
$remotePort='${Number(port)}'
$mode='crash'
function Set-AivpnFailed([string]$reason) {
  try {
    @{nonce=$nonce;state='failed';reason=$reason;checkedAt=(Get-Date).ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath $failed -Encoding utf8
  } catch {}
}
function Test-AivpnKillSwitch {
  $errors=@()
  $bad=@(Get-NetFirewallProfile | Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' })
  if ($bad.Count -gt 0) { $errors += 'profile' }
  $transport=Get-NetFirewallRule -DisplayName "$prefix VPN transport" -ErrorAction SilentlyContinue
  if ($null -eq $transport) {
    $errors += 'transport-missing'
  } else {
    if ([string]$transport.Direction -ne 'Outbound' -or [string]$transport.Action -ne 'Allow' -or [string]$transport.Enabled -ne 'True') { $errors += 'transport-rule' }
    $app=$transport | Get-NetFirewallApplicationFilter
    if ($null -eq $app -or [string]$app.Program -ne $enginePath) { $errors += 'transport-program' }
    $addr=$transport | Get-NetFirewallAddressFilter
    if ($null -eq $addr -or -not (@($addr.RemoteAddress) -contains $hostRemote)) { $errors += 'transport-remote' }
    $portFilter=$transport | Get-NetFirewallPortFilter
    if ($null -eq $portFilter -or [string]$portFilter.Protocol -ne $protocol -or [string]$portFilter.RemotePort -ne $remotePort) { $errors += 'transport-port' }
  }
  $iface=Get-NetFirewallRule -DisplayName "$prefix VPN interface" -ErrorAction SilentlyContinue
  if ($null -eq $iface) {
    $errors += 'interface-missing'
  } else {
    if ([string]$iface.Direction -ne 'Outbound' -or [string]$iface.Action -ne 'Allow') { $errors += 'interface-rule' }
    $ifaceType=$iface | Get-NetFirewallInterfaceTypeFilter
    if ($null -eq $ifaceType -or [string]$ifaceType.InterfaceType -ne 'RemoteAccess') { $errors += 'interface-type' }
  }
  return ($errors -join ',')
}
$profiles=Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction
$profiles | ConvertTo-Json | Set-Content -LiteralPath $backup -Encoding utf8
# OpenVPN's DCO/TAP adapters are classified by Windows as Public, not
# RemoteAccess, so the interface rule never matches them and the default
# block would drop every tunnel packet.  Allow outbound traffic on the tunnel
# adapter itself; the adapter appears only after the engine starts, so the
# loop below keeps looking for new ones.
$script:tunnelAliases=@{}
function Add-AivpnTunnelRules {
  try { $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceDescription -match 'OpenVPN|Wintun|TAP-Windows' }) } catch { return }
  foreach($adapter in $adapters) {
    $name=[string]$adapter.Name
    if ([string]::IsNullOrWhiteSpace($name)) { continue }
    if ($name -match '[\\*\\?\\[\\]]') { continue }
    if ($script:tunnelAliases.ContainsKey($name)) { continue }
    $ruleName="$prefix tunnel $name"
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) { $script:tunnelAliases[$name]=$true; continue }
    try {
      New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Allow -InterfaceAlias $name | Out-Null
      $script:tunnelAliases[$name]=$true
    } catch {}
  }
}
# The try covers rule creation as well: a failure halfway must still restore
# the previous profile defaults instead of leaving a partial block behind.
try {
  Get-NetFirewallRule -DisplayName "$prefix *" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName "$prefix VPN transport" -Direction Outbound -Action Allow -Program '${q(programPath)}' -RemoteAddress '${q(host)}' -Protocol '${q(protocol)}' -RemotePort ${Number(port)} | Out-Null
  New-NetFirewallRule -DisplayName "$prefix VPN interface" -Direction Outbound -Action Allow -InterfaceType RemoteAccess | Out-Null
  Add-AivpnTunnelRules
  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
  # The block is only real if the ActiveStore shows it and the allow rules
  # carry the expected filters.  Publish readiness only after reading them back.
  $verifyFail=Test-AivpnKillSwitch
  if ($verifyFail -ne '') {
    $mode='failed'
    Set-AivpnFailed $verifyFail
  } else {
    @{nonce=$nonce;state='ready';checkedAt=(Get-Date).ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath $ready -Encoding utf8
    while ($true) {
      if (Test-Path -LiteralPath $stop) { $mode='clean'; break }
      $fresh=$false
      if (Test-Path -LiteralPath $heartbeat) {
        $age=((Get-Date)-(Get-Item -LiteralPath $heartbeat).LastWriteTime).TotalSeconds
        if ($age -le 5) { $fresh=$true }
      }
      if (-not $fresh) {
        if (-not $strict) { break }
        $waited=0
        $resumed=$false
        while ($waited -lt 120) {
          Start-Sleep -Milliseconds 500
          $waited++
          if (Test-Path -LiteralPath $stop) { $mode='clean'; break }
          if (Test-Path -LiteralPath $heartbeat) {
            $age=((Get-Date)-(Get-Item -LiteralPath $heartbeat).LastWriteTime).TotalSeconds
            if ($age -le 5) { $resumed=$true; break }
          }
        }
        if ($mode -eq 'clean') { break }
        if ($resumed) { continue }
        break
      }
      Add-AivpnTunnelRules
      Start-Sleep -Milliseconds 500
    }
  }
} catch {
  $mode='failed'
  Set-AivpnFailed ('script-error: ' + $_.Exception.Message)
} finally {
  if ($enginePid -gt 0) { Stop-Process -Id $enginePid -Force -ErrorAction SilentlyContinue }
  if ($mode -eq 'clean' -or $mode -eq 'failed' -or -not $strict) {
    ${restoreBlock({ prefix: PREFIX, backup }).replace(/\n/g, '\n    ')}
    Remove-Item -LiteralPath $lock,$heartbeat,$stop,$ready -Force -ErrorAction SilentlyContinue
  }
}
if ($mode -eq 'failed') { exit 6 }
`;
}

function recoveryScript(options) {
  const { heartbeat, stop, lock, backup, ready, failed } = options;
  return `
$ErrorActionPreference='Stop'
$prefix='${PREFIX}'
$heartbeat='${q(heartbeat)}'
$stop='${q(stop)}'
$lock='${q(lock)}'
$backup='${q(backup)}'
$ready='${q(ready)}'
$failed='${q(failed)}'
${restoreBlock({ prefix: PREFIX, backup })}
Remove-Item -LiteralPath $lock,$heartbeat,$stop,$ready,$failed -Force -ErrorAction SilentlyContinue
`;
}

class KillSwitch {
  constructor(runDir) {
    this.runDir = runDir;
    this.heartbeat = path.join(runDir, 'killswitch.heartbeat');
    this.stopFile = path.join(runDir, 'killswitch.stop');
    this.lockFile = path.join(runDir, 'killswitch.lock.json');
    this.backupFile = path.join(runDir, 'killswitch-firewall.json');
    this.readyFile = path.join(runDir, 'killswitch.ready.json');
    this.failedFile = path.join(runDir, 'killswitch.failed.json');
    this.script = path.join(runDir, 'killswitch-watchdog.ps1');
    this.timer = null;
  }

  locked() {
    return fs.existsSync(this.lockFile);
  }

  writeHeartbeat() {
    try { fs.writeFileSync(this.heartbeat, String(Date.now()), 'ascii'); } catch {}
  }

  async enable({ enginePath, enginePid, host, port, protocol, strict = true, timeoutMs = READY_TIMEOUT_MS }) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || !Number.isInteger(port)) throw new Error('KILLSWITCH_TARGET_INVALID');
    if (this.locked()) throw new Error('KILLSWITCH_LOCKED');
    fs.mkdirSync(this.runDir, { recursive: true });
    for (const file of [this.stopFile, this.readyFile, this.failedFile]) {
      fs.rmSync(file, { force: true });
    }
    const nonce = crypto.randomBytes(16).toString('hex');
    this.writeHeartbeat();
    const paths = {
      heartbeat: this.heartbeat,
      stop: this.stopFile,
      lock: this.lockFile,
      backup: this.backupFile,
      ready: this.readyFile,
      failed: this.failedFile,
      nonce
    };
    const script = watchdogScript({
      ...paths,
      enginePid,
      strict: Boolean(strict),
      enginePath,
      host,
      port,
      protocol
    });
    // The watchdog is passed inline to the elevated launcher.  Do not leave a
    // second, mutable copy in the user profile; remove a copy left by older
    // versions before starting a new attempt.
    try { fs.rmSync(this.script, { force: true }); } catch {}
    fs.writeFileSync(
      this.lockFile,
      JSON.stringify({ prefix: PREFIX, strict: Boolean(strict), nonce, startedAt: Date.now() }),
      'utf8'
    );
    try {
      await this.spawnElevated(script);
    } catch (error) {
      try { fs.rmSync(this.lockFile, { force: true }); } catch {}
      throw error;
    }
    // The launcher returns once UAC was accepted; the elevated watchdog still
    // has to apply the rules and read them back.  Keep the heartbeat fresh
    // while waiting, then start the tunnel only after the ready marker that
    // carries this attempt's nonce.
    this.writeHeartbeat();
    this.timer = setInterval(() => this.writeHeartbeat(), 1000);
    const deadline = Date.now() + Math.max(1000, Number(timeoutMs) || READY_TIMEOUT_MS);
    while (Date.now() < deadline) {
      const ready = readJson(this.readyFile);
      if (ready && ready.nonce === nonce && ready.state === 'ready') return;
      const failure = readJson(this.failedFile);
      if (failure && failure.nonce === nonce) {
        this.disable();
        const error = new Error('KILLSWITCH_NOT_READY');
        error.reason = failure.reason || 'verify';
        throw error;
      }
      await delay(100);
    }
    // A stale marker from another attempt never counts: only the nonce this
    // attempt put in the lock file can report readiness.
    this.disable();
    const error = new Error('KILLSWITCH_NOT_READY');
    error.reason = 'timeout';
    throw error;
  }

  // The script text travels inline on the elevated command line, so rewriting
  // the copy on disk cannot change what runs with administrator rights.
  spawnElevated(script) {
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawn(
          'powershell.exe',
          ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', elevateScript(script)],
          { windowsHide: true }
        );
      } catch {
        reject(new Error('KILLSWITCH_LAUNCH_FAILED'));
        return;
      }
      child.once('error', () => reject(new Error('KILLSWITCH_LAUNCH_FAILED')));
      child.once('exit', (code) => (code === 0 ? resolve() : reject(new Error('KILLSWITCH_ELEVATION_CANCELLED'))));
    });
  }

  // Rebuild the recovery script from known paths instead of trusting the file
  // on disk: a swapped file would otherwise run as administrator.
  recover() {
    if (!this.locked()) return Promise.resolve();
    return this.spawnElevated(recoveryScript({
      heartbeat: this.heartbeat,
      stop: this.stopFile,
      lock: this.lockFile,
      backup: this.backupFile,
      ready: this.readyFile,
      failed: this.failedFile
    })).catch((error) => {
      if (error.message === 'KILLSWITCH_ELEVATION_CANCELLED') {
        throw new Error('KILLSWITCH_RESTORE_FAILED');
      }
      throw error;
    });
  }

  disable() {
    this.stopHeartbeat();
    try { fs.writeFileSync(this.stopFile, 'stop', 'ascii'); } catch {}
    try { fs.rmSync(this.script, { force: true }); } catch {}
  }

  // Recovery removes the markers itself.  Clearing only the app-side timer
  // avoids recreating a heartbeat after the elevated recovery has finished.
  stopHeartbeat() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

module.exports = { KillSwitch, PREFIX, watchdogScript, recoveryScript, firewallProgramPath };
