# AXlinux — Working Notes and Safety Notice

> This file is **not part of the license**. See [LICENSE](LICENSE) for
> the license text (MIT).

## AXlinux runs on physical machines

AXlinux is designed to be used on the machine you work on every day. It
does **not** require a virtual machine and does **not** refuse to run on
physical hardware. Neither `install.sh` nor `axctl` contains a
virtual-machine check.

If you have read that "AXlinux refuses to run on a physical machine",
that refers to the **test suite**: `tests/deep_verify.sh` declines to run
enforcement tests on physical hardware, because a test that
deliberately denies access can lock the machine you are working on.
Override with `AXLINUX_ALLOW_PHYSICAL=1` if you have console access and
a known way out.

This distinction matters: documenting a test-harness limitation as a
product limitation would be false, and would also discourage the exact
daily use the tool is built for.

## Before you enforce anything

```bash
axctl policy check      # 1. syntax and semantic validation
axctl policy simulate  # 2. see the effect in advance
axctl mode permissive   # 3. observe, do not block
axctl reload            # 4. apply
axctl status            # 5. confirm the real state
```

Skipping this order can lock you out.

## Emergency exit

```bash
sudo axctl mode disabled
```

This command **always works**, removes every restriction, and requires no
reboot.

Measured: a policy denying `cat /etc/hostname` made that read fail
(`rc=1`); `axctl mode disabled` immediately afterwards made the same read
succeed (`rc=0`).

## Do not lock out your own shell

Shells are the recovery path. A deny rule that targets `bash`, `zsh` or
`fish` can leave you without a way in. The validator warns when a rule
targets such recovery processes — treat that warning seriously.

## Be careful with `file.execute` on `/usr/bin`

A deny rule covering a whole binary directory can prevent services from
starting. Verify your allow-list first, and use `permissive` mode while
you learn.

## Further reading

- [SECURITY.md](SECURITY.md) — reporting a security vulnerability
- [README.md](README.md#why-it-is-safe-on-a-physical-machine) — the full
  safety argument with measurements
- [docs/policy-language.md](docs/policy-language.md) — policy reference