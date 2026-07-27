param(
  [string]$SourceRepo = "https://github.com/Cleanskiier27/Preciseliens.git",
  [string]$SourceRef = "main",
  [string]$SourcePath = "src/transformers/models",
  [string]$OutDir = "vendor/transformers-model-suite/models"
)

$ErrorActionPreference = "Stop"

$work = Join-Path $env:TEMP ("model-suite-sync-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $work | Out-Null

try {
  git clone --filter=blob:none --no-checkout $SourceRepo $work | Out-Null
  Push-Location $work
  git sparse-checkout init --cone | Out-Null
  git sparse-checkout set $SourcePath | Out-Null
  git checkout $SourceRef | Out-Null
  Pop-Location

  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  $src = Join-Path $work $SourcePath

  if (-not (Test-Path $src)) {
    throw "Source path not found: $src"
  }

  if (Test-Path $OutDir) {
    Get-ChildItem -Path $OutDir -Force | Remove-Item -Recurse -Force
  }

  Copy-Item -Path (Join-Path $src "*") -Destination $OutDir -Recurse -Force

  $meta = @(
    "source_repo=$SourceRepo"
    "source_ref=$SourceRef"
    "source_path=$SourcePath"
    "synced_at_utc=$([DateTime]::UtcNow.ToString("o"))"
  )

  $metaDir = Split-Path $OutDir -Parent
  Set-Content -Path (Join-Path $metaDir ".source-meta") -Value $meta -Encoding UTF8

  Write-Host "Model suite synced to $OutDir"
}
finally {
  if (Test-Path $work) {
    Remove-Item -Path $work -Recurse -Force
  }
}
