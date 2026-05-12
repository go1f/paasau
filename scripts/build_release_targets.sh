#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORB_MACHINE="${ORB_MACHINE:-ubuntu}"
LIBPCAP_VERSION="${LIBPCAP_VERSION:-1.10.5}"

cd "$ROOT_DIR"
mkdir -p dist/releases
rm -f \
  dist/releases/paasau_arm-linux-gnueabihf_static \
  dist/releases/paasau_arm-linux-gnueabi_static \
  dist/releases/paasau_aarch64-linux-gnu_static \
  dist/releases/paasau_windows_amd64.exe \
  dist/releases/SHA256SUMS \
  dist/releases/paasau_linux_armv7_cgo \
  dist/releases/paasau_linux_armv7_cgo_static \
  dist/releases/paasau_linux_arm_eabi_cgo_static \
  dist/releases/paasau_linux_aarch64_cgo_static

echo "Building Windows amd64..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/releases/paasau_windows_amd64.exe ./cmd/paasau

orb -m "$ORB_MACHINE" bash -lc "
set -euo pipefail
LIBPCAP_VERSION='$LIBPCAP_VERSION'
ROOT_DIR='$ROOT_DIR'

cd \"\$ROOT_DIR\"
mkdir -p dist/releases

sudo dpkg --add-architecture armhf
sudo dpkg --add-architecture armel
sudo apt-get update
sudo apt-get install -y \\
  gcc-arm-linux-gnueabihf libc6-dev-armhf-cross libpcap-dev:armhf \\
  gcc-arm-linux-gnueabi libc6-dev-armel-cross \\
  libpcap-dev:arm64 pkg-config file curl make flex bison

build_libpcap() {
  local target=\"\$1\"
  local host=\"\$2\"
  local cc=\"\$3\"
  local ar=\"\$4\"
  local ranlib=\"\$5\"
  local cflags=\"\${6:-}\"
  local prefix=\"/tmp/paasau-libpcap-\$target-\$LIBPCAP_VERSION\"

  if [[ -f \"\$prefix/lib/libpcap.a\" ]]; then
    echo \"Using cached libpcap for \$target: \$prefix\"
    return
  fi

  cd /tmp
  rm -rf \"libpcap-\$LIBPCAP_VERSION-\$target\" \"libpcap-\$LIBPCAP_VERSION.tar.xz\"
  curl -L --fail -o \"libpcap-\$LIBPCAP_VERSION.tar.xz\" \"https://www.tcpdump.org/release/libpcap-\$LIBPCAP_VERSION.tar.xz\"
  tar xf \"libpcap-\$LIBPCAP_VERSION.tar.xz\"
  mv \"libpcap-\$LIBPCAP_VERSION\" \"libpcap-\$LIBPCAP_VERSION-\$target\"
  cd \"libpcap-\$LIBPCAP_VERSION-\$target\"

  CC=\"\$cc\" AR=\"\$ar\" RANLIB=\"\$ranlib\" CFLAGS=\"\$cflags\" ./configure \\
    --host=\"\$host\" \\
    --prefix=\"\$prefix\" \\
    --disable-shared \\
    --disable-dbus \\
    --disable-bluetooth \\
    --disable-usb \\
    --disable-rdma \\
    --without-libnl
  make -j\"\$(nproc)\"
  make install
}

build_go_static() {
  local output=\"\$1\"
  local goarch=\"\$2\"
  local goarm=\"\$3\"
  local cc=\"\$4\"
  local prefix=\"\$5\"

  cd \"\$ROOT_DIR\"
  export GOCACHE=\"\$ROOT_DIR/.gocache-orb\"
  export CGO_CFLAGS=\"-I\$prefix/include\"
  export CGO_LDFLAGS=\"-L\$prefix/lib -lpcap -static\"

  GOOS=linux GOARCH=\"\$goarch\" GOARM=\"\$goarm\" CGO_ENABLED=1 CC=\"\$cc\" \\
    go build -tags 'netgo osusergo' -ldflags '-linkmode external -extldflags -static' \\
    -o \"dist/releases/\$output\" ./cmd/paasau
  file \"dist/releases/\$output\"
}

build_libpcap armv7 arm-linux-gnueabihf arm-linux-gnueabihf-gcc arm-linux-gnueabihf-ar arm-linux-gnueabihf-ranlib ''
build_go_static paasau_arm-linux-gnueabihf_static arm 7 arm-linux-gnueabihf-gcc /tmp/paasau-libpcap-armv7-\$LIBPCAP_VERSION

build_libpcap arm-gnueabi-soft arm-linux-gnueabi arm-linux-gnueabi-gcc arm-linux-gnueabi-ar arm-linux-gnueabi-ranlib '-mfloat-abi=soft'
build_go_static paasau_arm-linux-gnueabi_static arm 5 arm-linux-gnueabi-gcc /tmp/paasau-libpcap-arm-gnueabi-soft-\$LIBPCAP_VERSION

build_libpcap aarch64 aarch64-linux-gnu cc ar ranlib ''
build_go_static paasau_aarch64-linux-gnu_static arm64 '' cc /tmp/paasau-libpcap-aarch64-\$LIBPCAP_VERSION

cd \"\$ROOT_DIR\"
for bin in dist/releases/paasau_arm-linux-gnueabihf_static dist/releases/paasau_arm-linux-gnueabi_static dist/releases/paasau_aarch64-linux-gnu_static; do
  echo \"Checking dynamic dependencies for \$bin\"
  readelf -d \"\$bin\" | grep NEEDED && exit 1 || true
done
"

cd "$ROOT_DIR"
shasum -a 256 \
  dist/releases/paasau_arm-linux-gnueabihf_static \
  dist/releases/paasau_arm-linux-gnueabi_static \
  dist/releases/paasau_aarch64-linux-gnu_static \
  dist/releases/paasau_windows_amd64.exe \
  > dist/releases/SHA256SUMS

echo "Release artifacts:"
ls -lh \
  dist/releases/paasau_arm-linux-gnueabihf_static \
  dist/releases/paasau_arm-linux-gnueabi_static \
  dist/releases/paasau_aarch64-linux-gnu_static \
  dist/releases/paasau_windows_amd64.exe \
  dist/releases/SHA256SUMS
