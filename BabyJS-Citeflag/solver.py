#!/usr/bin/env python3
import argparse
import json
import os
import re
import select
import socket
import subprocess
import sys
import time


PROMPT = b"mqjs > "
ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")
FLAG_RE = re.compile(rb"CITEFLAG\{[^}]*\}")


def build_repl_lines(source, chunk_size):
    lines = ['S=""']
    for i in range(0, len(source), chunk_size):
        lines.append("S+=" + json.dumps(source[i:i + chunk_size]) + ";0")
    lines.append("(1,eval)(S)")
    return lines


def strip_ansi(data):
    return ANSI_RE.sub(b"", data)


def read_until(fd, recv_once, token, timeout):
    out = bytearray()
    end = time.time() + timeout
    while time.time() < end:
        remaining = max(0.0, end - time.time())
        ready, _, _ = select.select([fd], [], [], min(0.1, remaining))
        if not ready:
            continue
        chunk = recv_once()
        if not chunk:
            break
        out += chunk
        clean = strip_ansi(bytes(out))
        if token in out or FLAG_RE.search(clean):
            return bytes(out)
    return bytes(out)


def drain(fd, recv_once, timeout=0.75):
    out = bytearray()
    end = time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], min(0.1, end - time.time()))
        if not ready:
            continue
        chunk = recv_once()
        if not chunk:
            break
        out += chunk
    return bytes(out)


def run_driver(lines, fd, recv_once, send_all, verbose):
    raw = bytearray()
    raw += read_until(fd, recv_once, PROMPT, 5.0)

    for idx, line in enumerate(lines):
        send_all((line + "\n").encode())
        timeout = 30.0 if idx == len(lines) - 1 else 5.0
        raw += read_until(fd, recv_once, PROMPT, timeout)
        if verbose and (idx == 0 or idx % 20 == 0 or idx == len(lines) - 1):
            print(f"sent {idx + 1}/{len(lines)}", file=sys.stderr)

    raw += drain(fd, recv_once)
    clean = strip_ansi(bytes(raw))
    flags = sorted(set(m.group(0).decode("latin1") for m in FLAG_RE.finditer(clean)))
    if flags:
        for flag in flags:
            print(flag)
        return 0

    sys.stdout.buffer.write(clean[-4096:])
    if not clean.endswith(b"\n"):
        print()
    return 1


def run_local(lines, argv, verbose):
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    fd = proc.stdout.fileno()

    def recv_once():
        return os.read(fd, 4096)

    def send_all(data):
        proc.stdin.write(data)
        proc.stdin.flush()

    try:
        return run_driver(lines, fd, recv_once, send_all, verbose)
    finally:
        try:
            proc.stdin.close()
        except BrokenPipeError:
            pass
        proc.wait(timeout=2)


def run_remote(lines, host, port, verbose):
    sock = socket.create_connection((host, port), timeout=10)
    sock.setblocking(False)

    def recv_once():
        try:
            return sock.recv(4096)
        except BlockingIOError:
            return b""

    def send_all(data):
        sock.sendall(data)

    try:
        return run_driver(lines, sock, recv_once, send_all, verbose)
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="pwn-44-72b52c7fcca5411180fc533e8a29989e.challs.citeflag.online")
    parser.add_argument("port", nargs="?", type=int, default=31062)
    parser.add_argument("-e", "--exploit", default="exploit.js")
    parser.add_argument("-c", "--chunk-size", type=int, default=80)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--local-cmd", nargs="+", default=["/tmp/mquickjs/mqjs"])
    args = parser.parse_args()

    with open(args.exploit, "r", encoding="ascii") as f:
        source = f.read()
    lines = build_repl_lines(source, args.chunk_size)

    if args.local:
        return run_local(lines, args.local_cmd, args.verbose)
    return run_remote(lines, args.host, args.port, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
