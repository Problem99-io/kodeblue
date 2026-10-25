#!/bin/sh
# Build kodeblue release files.
#   deploy/build-dist.sh [OUT]          (default OUT=dist)
# Produces:
#   OUT/agent/   what a hub serves to servers: install.sh, kodeblue-linux-{amd64,arm64}.tar.gz, SHA256SUMS
#   OUT/kodeblue-hub-linux-{amd64,arm64}.tar.gz   hub bundles (binary, agent files, systemd unit, installer)
#   OUT/install-hub.sh    the hub installer on its own, which downloads a bundle (curl … | sudo sh)
# Environment:
#   ARCHES="amd64"        build one architecture (default: amd64 arm64)
#   VERSION=v1.2.3        version stamped into every binary (default: git describe)
#   COMMIT=<sha>          commit stamped into the engine (default: git rev-parse HEAD)
#   SOURCE_DATE_EPOCH=N   build time; default: the commit time, so the same commit
#                         gives byte-identical tarballs (with GNU tar)
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-dist}
ARCHES=${ARCHES:-"amd64 arm64"}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
COMMIT=${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}
export SOURCE_DATE_EPOCH
BUILD_TIME=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)

mod=github.com/Problem99-io/kodeblue
LDFLAGS="-s -w -X $mod/internal/blue/hubproto.Version=$VERSION"
ENGINE_LDFLAGS="-s -w -X $mod/internal/buildinfo.Version=$VERSION -X $mod/internal/buildinfo.Commit=$COMMIT -X $mod/internal/buildinfo.BuildTime=$BUILD_TIME"
sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

# Keep macOS metadata (xattrs, ._ files) out of the tarballs.
export COPYFILE_DISABLE=1
TARFLAGS=""
if tar --no-xattrs -cf /dev/null /dev/null 2>/dev/null; then TARFLAGS="--no-xattrs"; fi
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  # Fixed order, owner and times: the same commit gives the same tarball.
  TARFLAGS="$TARFLAGS --sort=name --owner=0 --group=0 --numeric-owner --mtime=@$SOURCE_DATE_EPOCH"
else
  TARFLAGS="$TARFLAGS --uid 0 --gid 0 --uname root --gname root"
fi
pack() { # dir name -> name.tar.gz in OUT path $3
  tar $TARFLAGS -C "$1" -cf - "$2" | gzip -n -9 > "$3"
}

rm -rf "$OUT"
mkdir -p "$OUT/agent"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
for arch in $ARCHES; do
  echo "building kodeblue $VERSION linux/$arch"
  d="$tmp/$arch/kodeblue"
  mkdir -p "$d/deploy"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$d/kodeblue" ./cmd/kodeblue
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "$ENGINE_LDFLAGS" -o "$d/kodeblue-engine" ./cmd/kodeblue-engine
  cp deploy/install.sh deploy/kodeblue.service deploy/kodeblue-respond.socket deploy/kodeblue-respond@.service deploy/kodeblue.toml.example "$d/deploy/"
  cp LICENSE NOTICE "$d/"
  pack "$tmp/$arch" kodeblue "$OUT/agent/kodeblue-linux-$arch.tar.gz"
done
cp deploy/install.sh "$OUT/agent/install.sh"
(cd "$OUT/agent" && sum install.sh kodeblue-linux-*.tar.gz > SHA256SUMS)

for arch in $ARCHES; do
  echo "building kodeblue-hub $VERSION linux/$arch"
  d="$tmp/hub-$arch/kodeblue-hub"
  mkdir -p "$d"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$d/kodeblue-hub" ./cmd/kodeblue-hub
  cp deploy/hub/install-hub.sh deploy/hub/kodeblue-hub.service LICENSE NOTICE "$d/"
  cp -R "$OUT/agent" "$d/dist"
  pack "$tmp/hub-$arch" kodeblue-hub "$OUT/kodeblue-hub-linux-$arch.tar.gz"
done
cp deploy/hub/install-hub.sh "$OUT/install-hub.sh"
echo "release files in $OUT"
