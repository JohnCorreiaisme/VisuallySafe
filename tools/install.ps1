# Installs Visually Safe for this PC: copies it to Program Files, adds a Start menu shortcut and starts it with Windows (as administrator).
# Run from the unzipped folder, in an administrator PowerShell:   .\install.ps1        (remove with:  .\install.ps1 -Uninstall)
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run this in an administrator PowerShell." }
$dest = Join-Path $env:ProgramFiles "VisuallySafe"
$lnk = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\VisuallySafe.lnk"
if ($Uninstall) {
  schtasks /delete /tn "VisuallySafe" /f 2>$null | Out-Null
  schtasks /delete /tn "VisuallySafe Watchdog" /f 2>$null | Out-Null
  Get-Process Visually Safe -ErrorAction SilentlyContinue | Stop-Process -Force
  Remove-Item $lnk -Force -ErrorAction SilentlyContinue
  Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "Visually Safe removed. Its data folder (%LOCALAPPDATA%\VisuallySafe) was left in place."
  return
}
Get-Process Visually Safe -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item (Join-Path $PSScriptRoot "*") $dest -Recurse -Force -Exclude "install.ps1"
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut($lnk); $s.TargetPath = Join-Path $dest "VisuallySafe.exe"; $s.WorkingDirectory = $dest; $s.Save()
schtasks /create /tn "VisuallySafe" /tr "`"$dest\VisuallySafe.exe`"" /sc onlogon /rl highest /f | Out-Null
Start-Process (Join-Path $dest "VisuallySafe.exe")
Write-Host "Visually Safe installed in $dest and set to start when you log in."
