# Popcorn - Kernel Exploit Lab

Privilege escalation and kernel exploitation research toolkit.

## Core Tool: privesc-research.sh

Automatic 7-vector privilege escalation scanner:

1. **Kernel** — Dirty COW, Netfilter, Meltdown/Spectre
2. **Sudo** — NOPASSWD entries, wildcards
3. **SUID** — Exploitable binaries
4. **Capabilities** — CAP_SYS_ADMIN abuse
5. **Container/VM** — Escape opportunities
6. **Weak Permissions** — World-writable files
7. **Cron Jobs** — Writable scripts

## Quick Start

```bash
./privesc-research.sh --dry-run           # Scan vectors
./privesc-research.sh --auto-exploit      # Escalate to root
```

## Kernel Exploits

| CVE | Vulnerability | Status |
|-----|---------------|--------|
| CVE-2016-5195 | Dirty COW | In progress |
| CVE-2021-22555 | Netfilter | In progress |
| CVE-2021-4034 | PwnKit | In progress |

## Authorization

✓ Own infrastructure  
✓ Authorized pentesting  
✓ CTF competitions  
✗ Unauthorized systems  

Use only on systems you own or have explicit written permission to test.

## Status

Privilege escalation research toolkit - Under development
