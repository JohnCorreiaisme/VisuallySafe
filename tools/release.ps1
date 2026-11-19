# Builds TinyGuard, optionally signs it, and packs a release zip.
#   .\tools\release.ps1                         (unsigned build + zip)
#   .\tools\release.ps1 -CertThumbprint ABC123  (sign TinyGuard.exe and the .scr files with a code-signing certificate from your store)
# A signature only removes the "unknown publisher" warning if the certificate comes from a trusted authority.
param([string]$CertThumbprint = "", [string]$TimestampUrl = "http://timestamp.digicert.com")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$ver = (Select-Xml -Path TinyGuard.csproj -XPath "//Version").Node.InnerText
dotnet build -c Release -o dist\build | Out-Host
if ($LASTEXITCODE -ne 0) { throw "build failed" }
Copy-Item bin\tinyguard.model dist\build\ -Force
if (Test-Path bin\yara) { Copy-Item bin\yara dist\build\yara -Recurse -Force }
Copy-Item tools\install.ps1 dist\build\ -Force
if ($CertThumbprint) {
  $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My | Where-Object Thumbprint -eq $CertThumbprint | Select-Object -First 1
  if (-not $cert) { throw "certificate $CertThumbprint not found" }
  foreach ($f in "TinyGuard.exe","TinyGuard.scr","TinyGuardDefrag.scr") {
    $p = Join-Path dist\build $f
    if (Test-Path $p) { Set-AuthenticodeSignature -FilePath $p -Certificate $cert -TimestampServer $TimestampUrl -HashAlgorithm SHA256 | Out-Host }
  }
} else { Write-Host "Not signed (no -CertThumbprint given)." }
Get-ChildItem dist\build -Include *.pdb -Recurse | Remove-Item -Force
$zip = "dist\TinyGuard-$ver.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path dist\build\* -DestinationPath $zip
(Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() + "  TinyGuard-$ver.zip" | Set-Content "dist\TinyGuard-$ver.sha256"
Write-Host "Done: $zip"
