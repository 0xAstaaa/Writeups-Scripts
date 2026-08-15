#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/author/src"
USERS="$ROOT/users"

mkdir -p "$USERS"
rm -f "$USERS/abyss_oracle.h" "$USERS/abyss_oracle.ko"

echo "[+] building kernel module"
bash "$SRC/scripts/build-module.sh"

echo "[+] building initramfs"
bash "$SRC/scripts/make-rootfs.sh"

echo "[+] copying public artifacts"
cp "$SRC/initramfs.cpio.gz" "$USERS/initramfs.cpio.gz"
cp "$SRC/scripts/run-qemu.sh" "$USERS/run-qemu.sh"
cp "$SRC/initramfs.cpio.gz" "$ROOT/author/deploy/initramfs.cpio.gz"
if [ -f "$SRC/bzImage" ]; then
  cp "$SRC/bzImage" "$USERS/bzImage"
  cp "$SRC/bzImage" "$ROOT/author/deploy/bzImage"
else
  echo "[!] place bzImage at author/src/bzImage before packaging final users dist"
fi

echo "[+] done"
