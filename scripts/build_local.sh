#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p dist/releases
export GOCACHE="${ROOT_DIR}/.gocache"

go test ./...
go build -o dist/paasau ./cmd/paasau
GOOS=windows GOARCH=amd64 go build -o dist/releases/paasau_windows_amd64.exe ./cmd/paasau

echo "Built:"
echo "  dist/paasau"
echo "  dist/releases/paasau_windows_amd64.exe"
