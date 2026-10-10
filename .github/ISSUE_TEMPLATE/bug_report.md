---
name: Bug report
about: Something does not behave as expected
labels: bug
---

## What Happened

<!-- Short description -->

## What You Expected

<!-- Expected behaviour -->

## How to Reproduce

```bash
# The exact commands you ran
```

## Environment

| Component | Value |
|---|---|
| Operating system | |
| Kernel | `uname -r` |
| LSM chain | `cat /sys/kernel/security/lsm` |
| AXlinux version | `axctl version` |
| Installation path | RPM / .deb / install.sh |

## `axctl status` Output

```
```

## Audit Record

<!-- If available, the JSONL records under /var/log/axlinux/ -->

```bash
sudo axctl logs --limit 20
```

> **If this is not a security vulnerability**, use this form. Do not
> disclose security vulnerabilities such as access control bypasses
> publicly — follow the procedure in
> [SECURITY.md](../../SECURITY.md).