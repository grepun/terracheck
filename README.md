# CVE-2023-48795 Scanner

A Python-based tool that scans SSH hosts for exposure to **CVE-2023-48795**. Rather than guessing from a version banner, it performs the real SSH handshake and inspects the server's negotiated algorithms to determine exploitability directly, so the script reports what a host actually is vulnerable to.

## Installation

```bash
git clone https://github.com/grepun/terracheck
```

## Usage

Single IP

```bash
python3 terrapin.py -ip <ip>
```

Multiple IPs

```bash
python3 terrapin.py -ip <file>
```

If SSH is on a different port

```bash
python3 terrapin.py -ip <ip> -port <#>
```
