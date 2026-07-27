# networkbusteros Software Suite

networkbusteros is a mixed PowerShell and Node.js toolkit for local automation and a lightweight cloud service smoke-test flow.

## Features

- PowerShell service loader for module import orchestration
- Node.js service loader for dependency and JSON bootstrap checks
- HTTP service endpoint via nb-cloudone-server
- Smoke test utility for validating service readiness
- Integration sync scripts for model-suite sourcing

## Repository Layout

- install-wizard.ps1: Install/startup helper script
- networkbusteros-powershell-service.ps1: PowerShell module loader
- networkbusteros-node-service.js: Node.js loader/bootstrap logic
- nb-cloudone-server.js: HTTP server
- nb-cloudone-smoketest.js: API smoke test
- integration/model-suite/README.md: model-suite integration details
- scripts/source-model-suite.ps1: PowerShell sync script
- scripts/source-model-suite.sh: Bash sync script
- .github/workflows/source-model-suite.yml: CI automation for model sync

## Requirements

- Windows 10/11 for PowerShell-centric workflows
- PowerShell 5.1 or newer
- Node.js 14 or newer
- Git

## Quick Start

1. Clone the repository:

```bash
git clone https://github.com/Cleanskiier27/Dependabot.git
cd Dependabot
```

2. Start the cloud server:

```bash
node nb-cloudone-server.js
```

3. In a second terminal, run the smoke test:

```bash
node nb-cloudone-smoketest.js
```

4. Optional PowerShell loader run:

```powershell
powershell -ExecutionPolicy Bypass -File .\networkbusteros-powershell-service.ps1
```

## Integration: Model Suite Sync

Use one of the sync scripts to source model files into vendor/transformers-model-suite/models.

PowerShell:

```powershell
./scripts/source-model-suite.ps1
```

Bash:

```bash
bash ./scripts/source-model-suite.sh
```

CI automation is configured in .github/workflows/source-model-suite.yml.

## Releases

- Changelog: CHANGELOG.md
- GitHub release note categories: .github/release.yml

For each release, update CHANGELOG.md and publish a GitHub release from the main branch.

## Troubleshooting

### Node command not found

Cause: Node.js is not installed or not in PATH.

Fix:

- Install Node.js 14+.
- Open a new terminal session.
- Verify with:

```bash
node --version
```

### Smoke test says server not reachable

Cause: nb-cloudone-server is not running, or is running on a different port.

Fix:

- Start server first:

```bash
node nb-cloudone-server.js
```

- Then run smoke test in another terminal:

```bash
node nb-cloudone-smoketest.js
```

- If using a custom port, set PORT for both processes.

### PowerShell execution policy error

Cause: Local script execution is restricted.

Fix:

```powershell
powershell -ExecutionPolicy Bypass -File .\networkbusteros-powershell-service.ps1
```

### Module paths not found in PowerShell loader

Cause: Expected module folders are not present in this clone/workspace.

Fix:

- Run from repository root.
- Update module paths in networkbusteros-powershell-service.ps1 to match your environment.
- Use Test-Path in PowerShell to validate each module path before import.

## Author

Made by Andrew T Middleton.

## License

MIT
