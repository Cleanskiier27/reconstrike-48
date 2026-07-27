# Model Suite Integration

This integration sources model-related code from the upstream suite repository and places it under `vendor/transformers-model-suite/`.

## Source

Default source repository:

- `https://github.com/Cleanskiier27/Preciseliens`

Default source path:

- `src/transformers/models`

## How it works

- Uses sparse checkout to fetch only model files.
- Copies them into:
  - `vendor/transformers-model-suite/models`
- Writes metadata to:
  - `vendor/transformers-model-suite/.source-meta`

## Local usage

PowerShell:

```powershell
./scripts/source-model-suite.ps1
```

Bash:

```bash
bash ./scripts/source-model-suite.sh
```

## CI usage

GitHub Actions workflow:

- `.github/workflows/source-model-suite.yml`

It can run manually or on schedule and opens a pull request with updates.
