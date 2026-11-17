param(
  [Parameter(Mandatory = $true)] [string] $CertificateThumbprint,
  [string] $TimestampServer = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$package = Get-Content -Raw (Join-Path $root 'package.json') | ConvertFrom-Json
$version = $package.version
$files = @(
  (Join-Path $root 'dist\AIVPN\AIVPN.exe'),
  (Join-Path $root "dist\AI-VPN-Windows-$version-Setup.exe")
) | Where-Object { Test-Path -LiteralPath $_ }

if ($files.Count -eq 0) { throw 'No release executables found. Run npm run package:installer first.' }
$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
if (-not $signtool) { throw 'signtool.exe was not found. Install the Windows SDK Signing Tools.' }

foreach ($file in $files) {
  & $signtool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 $file
  if ($LASTEXITCODE -ne 0) { throw "Signing failed: $file" }
  $signature = Get-AuthenticodeSignature -FilePath $file
  if ($signature.Status -ne 'Valid') { throw "Signature validation failed: $file" }
  Write-Host "Signed and verified: $file"
}
