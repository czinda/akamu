#!/usr/bin/env python3
"""Minimal UDP DNS responder for demo purposes.

Serves TXT records from files in a directory.  Each file is named after the
query name (lowercase, no trailing dot) and contains one TXT value per line.
All other query types receive NXDOMAIN.

Usage:
    python3 mock_dns.py --port 5053 --record-dir /tmp/dns-records

The server runs until interrupted (Ctrl-C / SIGTERM).
"""

import argparse
import os
import socket
import struct
import sys
import signal


def build_response(query, record_dir):
    """Build a DNS response packet for the given query."""
    if len(query) < 12:
        return None  # too short to be DNS

    txid = query[:2]
    flags = struct.unpack("!H", query[2:4])[0]
    qdcount = struct.unpack("!H", query[4:6])[0]
    if qdcount < 1:
        return None

    # Parse the question section.
    offset = 12
    labels = []
    while offset < len(query):
        length = query[offset]
        offset += 1
        if length == 0:
            break
        labels.append(query[offset : offset + length].decode("ascii", errors="replace"))
        offset += length

    qname = ".".join(labels).lower()
    if offset + 4 > len(query):
        return None
    qtype = struct.unpack("!H", query[offset : offset + 2])[0]
    qclass = struct.unpack("!H", query[offset + 2 : offset + 4])[0]

    # Only handle IN class, TXT type.
    TYPE_TXT = 16
    CLASS_IN = 1

    question = query[12 : offset + 4]

    txt_values = []
    if qtype == TYPE_TXT and qclass == CLASS_IN:
        txt_file = os.path.join(record_dir, qname)
        if not os.path.abspath(txt_file).startswith(os.path.abspath(record_dir)):
            return None
        if os.path.isfile(txt_file):
            with open(txt_file) as f:
                txt_values = [line.strip() for line in f if line.strip()]

    if txt_values:
        rcode = 0  # NOERROR
        ancount = len(txt_values)
    else:
        rcode = 3  # NXDOMAIN
        ancount = 0

    # Build response header.
    resp_flags = 0x8000 | (flags & 0x0100) | rcode  # QR=1, RD echoed, rcode
    header = txid + struct.pack("!HHHHH", resp_flags, 1, ancount, 0, 0)

    # Build answer section.
    answers = b""
    for val in txt_values:
        val_bytes = val.encode("utf-8")
        if len(val_bytes) > 255:
            continue
        # Name pointer to offset 12 (question name).
        answers += b"\xc0\x0c"
        # TYPE=TXT, CLASS=IN, TTL=60
        rdata = bytes([len(val_bytes)]) + val_bytes
        answers += struct.pack("!HHiH", TYPE_TXT, CLASS_IN, 60, len(rdata))
        answers += rdata

    return header + question + answers


def main():
    parser = argparse.ArgumentParser(description="Minimal DNS TXT responder")
    parser.add_argument("--port", type=int, default=5053)
    parser.add_argument("--record-dir", required=True)
    args = parser.parse_args()

    os.makedirs(args.record_dir, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))
    sock.settimeout(1.0)

    print(f"mock_dns: listening on 127.0.0.1:{args.port}, records from {args.record_dir}", flush=True)

    running = True

    def handle_signal(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    while running:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue

        resp = build_response(data, args.record_dir)
        if resp:
            sock.sendto(resp, addr)

    sock.close()
    print("mock_dns: stopped", flush=True)


if __name__ == "__main__":
    main()
