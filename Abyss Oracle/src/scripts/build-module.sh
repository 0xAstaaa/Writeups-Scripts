#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
make -C "$ROOT/module" clean
make -C "$ROOT/module" KDIR="${KDIR:-/lib/modules/$(uname -r)/build}"
objcopy --remove-section=.BTF --remove-section=.BTF.ext --remove-section=.BTF.base "$ROOT/module/abyss_oracle.ko"
strip --strip-unneeded "$ROOT/module/abyss_oracle.ko"
