#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p dist/releases
export GOCACHE="${ROOT_DIR}/.gocache"

echo "Building Linux ARMv7 static binary..."
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 \
  go build -o dist/releases/paasau_linux_armv7 ./cmd/paasau

echo "Built:"
file dist/releases/paasau_linux_armv7

if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-arm64/bin"
  if [[ -x "${TOOLCHAIN}/aarch64-linux-android21-clang" ]]; then
    echo "Building Android ARM64 binary with ANDROID_NDK_HOME..."
    GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC="${TOOLCHAIN}/aarch64-linux-android21-clang" \
      go build -o dist/releases/paasau_android_arm64 ./cmd/paasau
    file dist/releases/paasau_android_arm64
  fi
  if [[ -x "${TOOLCHAIN}/armv7a-linux-androideabi21-clang" ]]; then
    echo "Building Android ARMv7 binary with ANDROID_NDK_HOME..."
    GOOS=android GOARCH=arm GOARM=7 CGO_ENABLED=1 CC="${TOOLCHAIN}/armv7a-linux-androideabi21-clang" \
      go build -o dist/releases/paasau_android_armv7 ./cmd/paasau
    file dist/releases/paasau_android_armv7
  fi
else
  echo "ANDROID_NDK_HOME is not set; skipped native Android builds."
fi
