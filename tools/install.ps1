# Installs TinyGuard for this PC: copies it to Program Files, adds a Start menu shortcut and starts it with Windows (as administrator).
# Run from the unzipped folder, in an administrator PowerShell:   .\install.ps1        (remove with:  .\install.ps1 -Uninstall)
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run this in an administrator PowerShell." }
$dest = Join-Path $env:ProgramFiles "TinyGuard"
$lnk = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\TinyGuard.lnk"
if ($Uninstall) {
  schtasks /delete /tn "TinyGuard" /f 2>$null | Out-Null
  schtasks /delete /tn "TinyGuard Watchdog" /f 2>$null | Out-Null
  Get-Process TinyGuard -ErrorAction SilentlyContinue | Stop-Process -Force
  Remove-Item $lnk -Force -ErrorAction SilentlyContinue
  Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "TinyGuard removed. Its data folder (%LOCALAPPDATA%\TinyGuard) was left in place."
  return
}
Get-Process TinyGuard -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item (Join-Path $PSScriptRoot "*") $dest -Recurse -Force -Exclude "install.ps1"
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut($lnk); $s.TargetPath = Join-Path $dest "TinyGuard.exe"; $s.WorkingDirectory = $dest; $s.Save()
schtasks /create /tn "TinyGuard" /tr "`"$dest\TinyGuard.exe`"" /sc onlogon /rl highest /f | Out-Null
Start-Process (Join-Path $dest "TinyGuard.exe")
Write-Host "TinyGuard installed in $dest and set to start when you log in."
