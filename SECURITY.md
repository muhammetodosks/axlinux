# Security Policy

## Supported Versions

| Version | Status |
|---|---|
| 1.2.0 | ✅ Supported |
| < 1.2.0 | ❌ Not supported |

## Reporting a Vulnerability

**Please do not open a public GitHub issue.** A public issue hands the
details to the entire world before a fix is in place.

Instead, send an email to:

```
security@axlinux.invalid
```

> This address is a placeholder. Replace it with a real address under your
> own control before publishing.

## What to Report

- Bugs that allow access control to be **bypassed**
- Policy parsing errors (an invalid policy being accepted)
- Loss or corruption of audit records
- The system breaking during installation/removal
- `axdaemon` running with unexpected privileges

## What Not to Report

- A policy not behaving as expected, provided this does **not** create a
  security vulnerability
- The `inode_permission` hook being unable to return the path (known
  structural limitation)
- Performance observations

## Process

1. **Acknowledgement** — we confirm receipt of the report within 48 hours.
2. **Assessment** — we reproduce the bug and determine its impact.
3. **Fix** — we close the root cause; we do not apply surface patches.
4. **Verification** — the fix is re-measured on a real system.
5. **Release** — the fix is published, after which the reporter may
   disclose publicly.

## Emergency Exit (for users)

If you have locked yourself out:

```bash
sudo axctl mode disabled
```

This command always works and removes all restrictions. No reboot is
required.

## About the Security Model

AXlinux is a **Mandatory Access Control** system. A policy written
incorrectly can lock you out of your own system. This is not a bug but
the natural consequence of the design — which is why the safe order of
application (`policy check` → `simulate` → `permissive` → `reload`) is
specified in exactly that order.

Details: [README.md](README.md#emergency-exit)