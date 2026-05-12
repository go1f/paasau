#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBPCAP_VERSION="${LIBPCAP_VERSION:-1.10.5}"
ORB_MACHINE="${ORB_MACHINE:-ubuntu}"

orb -m "$ORB_MACHINE" bash -lc "
set -euo pipefail
LIBPCAP_VERSION='$LIBPCAP_VERSION'

cd '$ROOT_DIR'
mkdir -p dist/releases

if ! command -v arm-linux-gnueabihf-gcc >/dev/null 2>&1 || ! dpkg -s libpcap-dev:armhf >/dev/null 2>&1; then
  sudo dpkg --add-architecture armhf
  sudo apt-get update
  sudo apt-get install -y gcc-arm-linux-gnueabihf libc6-dev-armhf-cross libpcap-dev:armhf pkg-config file curl make flex bison
fi

LIBPCAP_PREFIX=\"/tmp/paasau-libpcap-armv7-\$LIBPCAP_VERSION\"
if [[ ! -f \"\$LIBPCAP_PREFIX/lib/libpcap.a\" ]]; then
  cd /tmp
  rm -rf \"libpcap-\$LIBPCAP_VERSION\" \"libpcap-\$LIBPCAP_VERSION.tar.xz\"
  curl -L --fail -o \"libpcap-\$LIBPCAP_VERSION.tar.xz\" \"https://www.tcpdump.org/release/libpcap-\$LIBPCAP_VERSION.tar.xz\"
  tar xf \"libpcap-\$LIBPCAP_VERSION.tar.xz\"
  cd \"libpcap-\$LIBPCAP_VERSION\"
  CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib \\
    ./configure \\
      --host=arm-linux-gnueabihf \\
      --prefix=\"\$LIBPCAP_PREFIX\" \\
      --disable-shared \\
      --disable-dbus \\
      --disable-bluetooth \\
      --disable-usb \\
      --disable-rdma \\
      --without-libnl
  make -j\"\$(nproc)\"
  make install
fi

cd '$ROOT_DIR'
export GOCACHE=\"\$PWD/.gocache-orb\"
export CGO_CFLAGS=\"-I\$LIBPCAP_PREFIX/include\"
export CGO_LDFLAGS=\"-L\$LIBPCAP_PREFIX/lib -lpcap -static\"

GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=1 CC=arm-linux-gnueabihf-gcc \\
  go build -tags 'netgo osusergo' -ldflags '-linkmode external -extldflags -static' \\
  -o dist/releases/paasau_arm-linux-gnueabihf_static ./cmd/paasau

file dist/releases/paasau_arm-linux-gnueabihf_static
arm-linux-gnueabihf-readelf -d dist/releases/paasau_arm-linux-gnueabihf_static | grep NEEDED || true
"
