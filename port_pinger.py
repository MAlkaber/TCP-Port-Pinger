#!/usr/bin/env python3
"""
TCP Port Pinger
================
A minimal command-line tool that checks whether one or more TCP ports
are open on a target host, using Python's built-in `socket` module.

Project 01 of a pentest/red-team learning portfolio.
Read README.md first for the concept walkthrough - this file is meant
to be read top to bottom AFTER that, with the concepts already in your head.

Usage:
    python port_pinger.py <host> <ports> [--timeout SECONDS]

Examples:
    python port_pinger.py scanme.nmap.org 22
    python port_pinger.py scanme.nmap.org 22,80,443
    python port_pinger.py 192.168.1.10 20-25
"""

import argparse
import socket
import time


def parse_ports(port_spec: str) -> list[int]:
    """
    Turn a port specification string into a sorted list of unique ints.

    Accepts:
        "80"               -> [80]
        "22,80,443"        -> [22, 80, 443]
        "20-25"            -> [20, 21, 22, 23, 24, 25]
        "22,80,1000-1005"  -> mix of both
    """
    ports: set[int] = set()

    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_str, end_str = chunk.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    for p in ports:
        if not (0 < p <= 65535):
            raise ValueError(f"Port {p} is out of range (1-65535)")

    return sorted(ports)


def check_port(host: str, port: int, timeout: float) -> tuple[bool, float]:
    """
    Attempt a TCP connect() to host:port. Returns (is_open, elapsed_seconds).

    HOW THIS WORKS (this is the whole concept behind the tool):
    A TCP connection starts with a three-way handshake: SYN -> SYN/ACK -> ACK.
    socket.connect() performs that full handshake for us. If the target is
    listening on that port, the OS completes the handshake and connect()
    succeeds. If nothing is listening, the target replies with a TCP RST
    and connect() fails immediately. If the host is unreachable or a
    firewall silently drops the packet, connect() just hangs until our
    timeout expires.

    This technique is called a "TCP connect scan" - the simplest, most
    reliable, but also the noisiest/most detectable type of port scan
    (it's what `nmap -sT` does under the hood). A "SYN scan" (`nmap -sS`)
    does only the first two steps using raw sockets and never completes
    the handshake, which is quieter but requires raw-socket privileges -
    we'll build that version in a later project once raw sockets and
    scapy are introduced.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    start = time.perf_counter()
    try:
        # connect_ex() returns an integer error code instead of raising an
        # exception on failure - 0 means success, anything else means the
        # connection did not complete (refused, timed out, unreachable...).
        # That makes the success/failure branch cleaner here than a
        # try/except around connect().
        result_code = sock.connect_ex((host, port))
        is_open = result_code == 0
    except socket.gaierror as exc:
        # DNS resolution failed - the hostname itself doesn't exist.
        sock.close()
        raise SystemExit(f"[!] Could not resolve host '{host}': {exc}")
    finally:
        sock.close()

    elapsed = time.perf_counter() - start
    return is_open, elapsed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check whether TCP ports are open on a target host."
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument(
        "ports",
        help="Port, comma-separated list, and/or range, e.g. '80', '22,80,443', '20-25'",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Seconds to wait per port before giving up (default: 1.0)",
    )
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"Target:  {args.host}")
    print(f"Ports:   {ports}")
    print(f"Timeout: {args.timeout}s\n")

    open_ports = []
    for port in ports:
        is_open, elapsed = check_port(args.host, port, args.timeout)
        status = "OPEN" if is_open else "closed"
        print(f"  {port:>5}/tcp  {status:<7} ({elapsed:.3f}s)")
        if is_open:
            open_ports.append(port)

    print()
    if open_ports:
        print(f"[+] {len(open_ports)} open port(s): {open_ports}")
    else:
        print("[-] No open ports found.")


if __name__ == "__main__":
    main()
