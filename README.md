# TCP Port Pinger

**Project 01** of a pentest/red-team learning portfolio — see the [full roadmap](../ROADMAP.md).

A command-line tool that checks whether one or more TCP ports are open on a
target host, written from scratch using nothing but Python's standard
library (`socket`). This is the "hello world" of network scanning — every
serious scanner (including nmap) is doing a fancier version of exactly this.

> ⚠️ **Legal/ethical note:** Only scan hosts you own or are explicitly
> authorized to test. `scanme.nmap.org` is a host the nmap project
> deliberately leaves up for people to practice against — safe to use in
> the examples below. Scanning systems you don't have permission to touch
> is illegal in most jurisdictions (in the US, the Computer Fraud and
> Abuse Act) — this rule applies to *every* tool in this portfolio, not
> just this one.

## What it does

```
$ python3 port_pinger.py scanme.nmap.org 22,80,443,8080
Target:  scanme.nmap.org
Ports:   [22, 80, 443, 8080]
Timeout: 1.0s

     22/tcp  OPEN    (0.187s)
     80/tcp  OPEN    (0.191s)
    443/tcp  closed  (0.203s)
   8080/tcp  closed  (1.002s)

[+] 2 open port(s): [22, 80]
```

## Concepts you need before reading the code

**The TCP three-way handshake.** Before any data flows over TCP, the
client and server perform: `SYN` → `SYN/ACK` → `ACK`. Your OS's network
stack does this automatically whenever you call `connect()` on a socket —
you never touch the packets directly. If a port is listening, the
handshake completes. If nothing is listening, the target replies with a
`RST` packet and the connection is refused *immediately*. If a firewall
silently drops your packet instead of rejecting it, `connect()` just hangs
until it times out — that's the difference between "closed" and
"filtered" in nmap's output.

**Why this is called a "connect scan".** Because we let the OS complete
the *full* handshake, this is the most reliable scan type — no root
privileges needed, works everywhere — but it's also the loudest: a full
connection gets logged by the target (nmap's `-sT` flag does this). A
"SYN scan" (`nmap -sS`, aka "half-open scan") sends the SYN, reads the
SYN/ACK, and then bails without finishing the handshake — quieter, faster,
but requires crafting raw packets, which requires elevated privileges.
We'll build that version in a later project once we introduce `scapy`.

**Sockets, in one paragraph.** A "socket" is your program's handle to a
network connection — think of it like a file handle, but for a network
stream instead of a file. `socket.socket(AF_INET, SOCK_STREAM)` creates
an IPv4 (`AF_INET`) TCP (`SOCK_STREAM`) socket. `connect((host, port))`
tries to open it. `connect_ex()` is the same thing but returns an error
*code* (0 = success) instead of raising an exception — convenient when
you expect failure to be the common case, like it is here.

## Code walkthrough

Open [`port_pinger.py`](port_pinger.py) side by side with this section.

- **`parse_ports()`** — turns a string like `"22,80,443"` or `"20-25"`
  (or a mix, `"22,80,1000-1005"`) into a clean, sorted list of unique
  integers. This is a pattern you'll reuse constantly: real recon tools
  need flexible, human-friendly input formats, and parsing them correctly
  (including validating the 1–65535 range) is half the job.
- **`check_port()`** — the actual scan logic, one port at a time. Notice
  the `timeout` is set with `sock.settimeout()` *before* calling
  `connect_ex()` — without this, a filtered port could hang your script
  for the OS default TCP timeout (often 30–120 seconds) *per port*.
- **`main()`** — wires up `argparse` for a proper CLI (`--help` works for
  free), loops over every requested port, and prints a running result.

## Try it yourself (exercises)

Don't move to Project 02 until you can comfortably do these without
looking at the code:

1. Run it against `scanme.nmap.org` for ports `1-1024` and time how long
   it takes. Then drop `--timeout` to `0.3` and re-run — what changes,
   and why might a lower timeout give you *wrong* results on a slow or
   distant network?
2. Add a `--verbose` flag that, when set, also prints *closed* ports with
   the specific reason (refused vs. timed out) — you'll need to change
   `check_port()` to return more than just a bool.
3. What happens right now if the hostname doesn't resolve? Try
   `python3 port_pinger.py not-a-real-host-xyz 80` and read the error.
   Where in the code is that handled?
4. (Preview of Project 03) Sketch — in English, not code — why scanning
   1000 ports one at a time like this script does is slow, and what
   Python feature would let you check many ports *at the same time*.

## Running it

Built and tested for Kali Linux (Python 3.11+, no third-party packages):

```bash
git clone <your-repo-url>
cd 01-tcp-port-pinger
python3 port_pinger.py scanme.nmap.org 22,80,443
```

Works identically on Windows/macOS (`python port_pinger.py ...`) since it
only uses the standard library.

## What's next

**Project 02 — CIDR/IP Range Expander:** before you can scan a whole
network instead of one host, you need to turn something like
`192.168.1.0/24` into a list of 254 individual addresses. That's next.
