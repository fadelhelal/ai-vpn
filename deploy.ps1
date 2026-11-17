# ============================================
# Deploy AI VPN to GitHub
# Run in PowerShell as Administrator
# ============================================

$ErrorActionPreference = "Stop"

# --- Config ---
$githubUser = "fadelhelal"
$repoName   = "ai-vpn"
$winPath    = "C:\Users\DELL\Desktop\aivpn-windows"
$androidPath = "C:\Users\DELL\Desktop\persistlink\freevpn-android\FreeVPN_Android_Starter"

Write-Host "=== 1. Initialize Git in Windows project ===" -ForegroundColor Cyan
Set-Location $winPath
if (-not (Test-Path ".git")) { git init }
git config user.name "$githubUser"
git config user.email "$githubUser@users.noreply.github.com"

Write-Host "=== 2. Add all files (Windows) ===" -ForegroundColor Cyan
git add .github/workflows/build-windows.yml
git add scripts/package-portable.js
git add main.js
git add src/enginecheck.js
git add assets/icon.ico
git add assets/icon.png
git add -A

Write-Host "=== 3. Commit Windows ===" -ForegroundColor Cyan
git commit -m "feat: Windows v0.2.19 - bundled OpenVPN 2.6, unified icon, CI workflow" -q

Write-Host "=== 4. Add remote and push ===" -ForegroundColor Cyan
git remote remove origin 2>$null
git remote add origin "https://github.com/$githubUser/$repoName.git"
git branch -M main
git push -u origin main

Write-Host "=== 5. Android project (optional) ===" -ForegroundColor Cyan
Set-Location $androidPath
if (-not (Test-Path ".git")) { git init }
git config user.name "$githubUser"
git config user.email "$githubUser@users.noreply.github.com"
git add -A
git commit -m "feat: Android starter v0.10.27 (experimental framework)" -q

Write-Host "For Android, run manually:" -ForegroundColor Yellow
Write-Host "  cd $androidPath"
Write-Host "  git remote add origin https://github.com/$githubUser/ai-vpn-android.git"
Write-Host "  git push -u origin main"

Write-Host "`nDone! Open https://github.com/$githubUser/$repoName/actions to watch the build" -ForegroundColor Green