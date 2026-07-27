#!/usr/bin/env bash
set -euo pipefail

SOURCE_REPO="${1:-https://github.com/Cleanskiier27/Preciseliens.git}"
SOURCE_REF="${2:-main}"
SOURCE_PATH="${3:-src/transformers/models}"
OUT_DIR="${4:-vendor/transformers-model-suite/models}"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

git clone --filter=blob:none --no-checkout "$SOURCE_REPO" "$WORK_DIR"
cd "$WORK_DIR"
git sparse-checkout init --cone
git sparse-checkout set "$SOURCE_PATH"
git checkout "$SOURCE_REF"
cd - >/dev/null

mkdir -p "$OUT_DIR"
SRC_DIR="$WORK_DIR/$SOURCE_PATH"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "Source path not found: $SRC_DIR" >&2
  exit 1
fi

rm -rf "$OUT_DIR"/*
cp -R "$SRC_DIR"/* "$OUT_DIR"/

META_DIR="$(dirname "$OUT_DIR")"
cat > "$META_DIR/.source-meta" <<EOF
source_repo=$SOURCE_REPO
source_ref=$SOURCE_REF
source_path=$SOURCE_PATH
synced_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

echo "Model suite synced to $OUT_DIR"
