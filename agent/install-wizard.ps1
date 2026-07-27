param(
    [string]$InstallPath = "$env:USERPROFILE\networkbusteros"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null

Copy-Item -Path "$PSScriptRoot\nb-cloudone-server.js" -Destination $InstallPath -Force
Copy-Item -Path "$PSScriptRoot\nb-cloudone-smoketest.js" -Destination $InstallPath -Force
Copy-Item -Path "$PSScriptRoot\networkbusteros-node-service.js" -Destination $InstallPath -Force
Copy-Item -Path "$PSScriptRoot\networkbusteros-powershell-service.ps1" -Destination $InstallPath -Force

Write-Host "networkbusteros installed to $InstallPath"
