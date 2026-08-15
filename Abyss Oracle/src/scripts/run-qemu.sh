#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/bzImage" ]; then
  DIR="$SCRIPT_DIR"
else
  DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
KERNEL="${KERNEL:-$DIR/bzImage}"
INITRAMFS="${INITRAMFS:-$DIR/initramfs.cpio.gz}"
EXPLOIT="$(realpath "${1:-$PWD/exploit}")"
LOCAL_FLAG="${LOCAL_FLAG:-CTF{local_test_only}}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/root"
cd "$WORK/root"
gzip -dc "$INITRAMFS" | cpio -id --quiet
mkdir -p home/ctf
cp "$EXPLOIT" home/ctf/exploit
printf '%s\n' "$LOCAL_FLAG" > flag
chmod 755 home/ctf/exploit
chmod 400 flag
find . -print0 | cpio --null -o --format=newc --quiet | gzip -9 > "$WORK/initramfs.cpio.gz"

qemu-system-x86_64 \
  -m 128M \
  -cpu qemu64,+smep,+smap \
  -kernel "$KERNEL" \
  -initrd "$WORK/initramfs.cpio.gz" \
  -append "console=ttyS0 oops=panic panic=1 quiet kaslr pti=on smep smap" \
  -monitor none \
  -nic none \
  -nographic \
  -no-reboot \
  -smp 1
