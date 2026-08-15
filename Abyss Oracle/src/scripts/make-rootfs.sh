#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/initramfs.cpio.gz"
WORK="$ROOT/.rootfs"
BUSYBOX="${BUSYBOX:-busybox}"

rm -rf "$WORK"
mkdir -p "$WORK"/{bin,sbin,etc,proc,sys,dev,tmp,home/ctf}
cp "$ROOT/rootfs/init" "$WORK/init"
cp "$ROOT/module/abyss_oracle.ko" "$WORK/abyss_oracle.ko"
"${CC:-gcc}" -static -O2 -s "$ROOT/rootfs/dropper.c" -o "$WORK/bin/dropper"

if command -v "$BUSYBOX" >/dev/null 2>&1; then
  cp "$(command -v "$BUSYBOX")" "$WORK/bin/busybox"
else
  echo "busybox not found; set BUSYBOX=/path/to/static/busybox" >&2
  exit 1
fi

chmod +x "$WORK/init" "$WORK/bin/busybox" "$WORK/bin/dropper"
ln -s /bin/busybox "$WORK/bin/sh"
ln -s /bin/busybox "$WORK/bin/mount"
ln -s /bin/busybox "$WORK/bin/chmod"
ln -s /bin/busybox "$WORK/bin/chown"
ln -s /bin/busybox "$WORK/bin/mkdir"
ln -s /bin/busybox "$WORK/bin/cat"
ln -s /bin/busybox "$WORK/bin/id"
ln -s /bin/busybox "$WORK/bin/poweroff"
ln -s /bin/busybox "$WORK/bin/setsid"
ln -s /bin/busybox "$WORK/bin/cttyhack"
ln -s /bin/busybox "$WORK/bin/insmod"

(cd "$WORK" && find . -print0 | cpio --null -ov --format=newc | gzip -9) > "$OUT"
echo "$OUT"
