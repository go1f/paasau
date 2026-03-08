#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p dist/releases

orb -m ubuntu bash -lc "
set -euo pipefail
cd '$ROOT_DIR'
export GOCACHE='$ROOT_DIR/.gocache-orb'
go test ./...
go build -o dist/releases/paasau_linux_arm64 ./cmd/paasau
GOOS=windows GOARCH=amd64 go build -o dist/releases/paasau_windows_amd64.exe ./cmd/paasau
"

echo "Built via Orb Ubuntu:"
echo "  dist/releases/paasau_linux_arm64"
echo "  dist/releases/paasau_windows_amd64.exe"
