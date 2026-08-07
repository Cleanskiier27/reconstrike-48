param(
  [Parameter(Position = 0)]
  [ValidateSet('help', 'auth', 'version', 'composer-envs', 'composer-dags', 'composer-runs', 'composer-logs')]
  [string]$Command = 'help',

  [string]$Project,
  [string]$Location = 'us-central1',
  [string]$Environment,
  [string]$DagId,
  [string]$TaskId,
  [string]$StartTime,
  [string]$EndTime
)

$ErrorActionPreference = 'Stop'

function Get-GcloudCommand {
  $cmd = Get-Command gcloud.cmd -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  $cmd = Get-Command gcloud -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  throw 'gcloud is not installed or is not available on PATH.'
}

function Invoke-Gcloud {
  param([Parameter(Mandatory = $true)][string[]]$Args)
  $gcloud = Get-GcloudCommand
  & $gcloud @Args
}

function Add-ProjectArg {
  param([string[]]$Args)
  if ([string]::IsNullOrWhiteSpace($Project)) { return $Args }
  return @('--project', $Project) + $Args
}

function Write-Help {
@'
networkbuster gcloud helper

Usage:
  .\scripts\networkbuster-gcloud.ps1 <command> [options]

Commands:
  help             Show this help text
  auth             Run gcloud auth login
  version          Show gcloud version
  composer-envs    List Composer environments
  composer-dags    List DAGs in a Composer environment
  composer-runs    List DAG runs in a Composer environment
  composer-logs    Read Composer logs for a DAG or task

Common options:
  -Project <id>     Set the GCP project
  -Location <id>    Set the Composer location, default: us-central1
  -Environment <n>  Composer environment name
  -DagId <id>       DAG ID for runs or logs
  -TaskId <id>      Task ID for logs
  -StartTime <ts>   Log start time in RFC3339 format
  -EndTime <ts>     Log end time in RFC3339 format

Examples:
  .\scripts\networkbuster-gcloud.ps1 auth
  .\scripts\networkbuster-gcloud.ps1 version
  .\scripts\networkbuster-gcloud.ps1 composer-envs -Project my-project
  .\scripts\networkbuster-gcloud.ps1 composer-dags -Environment my-env -Location us-central1
  .\scripts\networkbuster-gcloud.ps1 composer-runs -Environment my-env -DagId my_dag
  .\scripts\networkbuster-gcloud.ps1 composer-logs -Environment my-env -DagId my_dag -TaskId my_task
'@ | Write-Host
}

switch ($Command) {
  'help' {
    Write-Help
  }
  'auth' {
    Invoke-Gcloud -Args (Add-ProjectArg @('auth', 'login'))
  }
  'version' {
    Invoke-Gcloud -Args (Add-ProjectArg @('--version'))
  }
  'composer-envs' {
    Invoke-Gcloud -Args (Add-ProjectArg @('composer', 'environments', 'list', '--locations', $Location, '--format', 'table(name,location,state)'))
  }
  'composer-dags' {
    if ([string]::IsNullOrWhiteSpace($Environment)) { throw 'Environment is required for composer-dags.' }
    Invoke-Gcloud -Args (Add-ProjectArg @('composer', 'environments', 'run', $Environment, '--location', $Location, 'dags', 'list', '--'))
  }
  'composer-runs' {
    if ([string]::IsNullOrWhiteSpace($Environment)) { throw 'Environment is required for composer-runs.' }
    if ([string]::IsNullOrWhiteSpace($DagId)) { throw 'DagId is required for composer-runs.' }
    Invoke-Gcloud -Args (Add-ProjectArg @('composer', 'environments', 'run', $Environment, '--location', $Location, 'dags', 'list-runs', '--', '-d', $DagId, '--no-backfill'))
  }
  'composer-logs' {
    if ([string]::IsNullOrWhiteSpace($Environment)) { throw 'Environment is required for composer-logs.' }
    if ([string]::IsNullOrWhiteSpace($DagId)) { throw 'DagId is required for composer-logs.' }

    $filter = "resource.type=\"cloud_composer_environment\" AND resource.labels.environment_name=\"$Environment\" AND labels.dag_id=\"$DagId\" AND severity>=ERROR"
    if (-not [string]::IsNullOrWhiteSpace($TaskId)) { $filter += " AND labels.task_id=\"$TaskId\"" }
    if (-not [string]::IsNullOrWhiteSpace($StartTime)) { $filter += " AND timestamp>=\"$StartTime\"" }
    if (-not [string]::IsNullOrWhiteSpace($EndTime)) { $filter += " AND timestamp<=\"$EndTime\"" }

    Invoke-Gcloud -Args (Add-ProjectArg @('logging', 'read', $filter, '--limit', '50', '--format', 'table(timestamp,severity,labels.task_id,textPayload)'))
  }
  default {
    throw "Unknown command: $Command"
  }
}
