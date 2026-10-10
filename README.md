# AXlinux

**Write YAML. AXlinux enforces it.**

A user-focused Mandatory Access Control (MAC) system. No millions of
lines of pre-written policy — **the policy is yours**, and its single
source of truth is `~/.axlinux/policy.yaml`.

```yaml
# ~/.axlinux/policy.yaml
version: 1
mode: enforcing
rules:
  - id: private-keys
    name: "SSH and GPG keys are unreadable"
    subject: [cat, less, vim]
    object: /home/user/.ssh
    action: file.read
    effect: deny
```

One command later, `cat ~/.ssh/id_rsa` returns `Operation not permitted`.

AXlinux runs on physical machines as well as virtual ones — including on
the machine you use every day. Read [Why it is safe on a physical
machine](#why-it-is-safe-on-a-physical-machine) before you start.

---

## Contents

- [Why AXlinux?](#why-axlinux)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Why it is safe on a physical machine](#why-it-is-safe-on-a-physical-machine)
- [Fedora-specific behaviour](#fedora-specific-behaviour)
- [Verified status](#verified-status)
- [Tests](#tests)
- [Emergency exit](#emergency-exit)
- [Contributing](#contributing)
- [License](#license)

---

## Why AXlinux?

| | SELinux | AXlinux |
|---|---|---|
| Policy source | Pre-built, millions of lines | **Your YAML** |
| Who writes it? | The distribution vendor | You |
| Learning | `audit2allow` | `axctl learn` → observe → propose |
| Applying | `setenforce`, reboot risk | `axctl reload` → **instant** |
| Log | `audit.log` (plain text) | JSONL (structured, queryable) |
| Scope | Whole system | Process, path, action — you choose |

SELinux is not meant to be removed — it is meant to be **complemented**.
They work together: SELinux provides the domain boundary (`axdaemon`
runs in its own confined domain), AXlinux writes the content rules.

## Features

- **A YAML policy language** — not a compiled format, just readable text.
- **Directory rules protect their contents** — `object: /tmp/secrets`
  protects everything inside it (verified at depths 1, 2 and 3).
- **Six action types** — `file.read`, `file.write`, `file.execute`,
  `inode_permission`, `socket_connect`, `socket_bind`.
- **Five LSM hooks** — `file_open`, `inode_permission`,
  `bprm_check_security`, `socket_connect`, `socket_bind`.
- **Three modes** — `enforcing` (block), `permissive` (log only),
  `disabled` (no restrictions).
- **Persistent policies** — files in `policies.d/` load automatically at
  boot.
- **Preview before applying** — `axctl policy simulate` shows what a
  policy will affect before you enable it.
- **Learning mode** — `axctl learn` collects observations and proposes
  policy.
- **Labels** — tag processes and write rules against the label.
- **Structured audit** — JSONL logs, queryable by `--subject`,
  `--effect`, `--action`.
- **Instant application** — `axctl reload`; no reboot required.

## Requirements

| Component | Version | Note |
|---|---|---|
| Operating system | Fedora 41–44 | RHEL derivatives work too |
| Kernel | **5.15+** | requires `CONFIG_BPF_LSM=y` **and** `bpf` in the active LSM chain |
| clang | 12+ | must support `-target bpf` |
| Go | 1.21+ | **build time only** |
| Python | 3.9+ | `click`, `rich`, `PyYAML` |
| Root | — | for installation and `axctl` |

## Installation

### RPM (Fedora)

```bash
sudo dnf install ./axlinux-1.2.0-1.x86_64.rpm
```

The package is signed:

```bash
rpm -Kv axlinux-1.2.0-1.x86_64.rpm
# Header OpenPGP V4 RSA/SHA512 signature,
#   key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
```

### .deb (Debian / Ubuntu / Pardus)

```bash
sudo apt install ./axlinux_1.2.0_amd64.deb
```

### From source

```bash
git clone https://github.com/muhammetodosks/axlinux.git
cd axlinux
sudo ./scripts/install.sh
```

### Mandatory prerequisite: the `bpf` LSM

AXlinux cannot enforce policy unless `bpf` is present in the kernel's
active LSM chain. `install.sh` checks this and warns explicitly.

```bash
# /etc/default/grub  ->  GRUB_CMDLINE_LINUX_DEFAULT
lsm=apparmor,bpf
sudo update-grub && sudo reboot
```

Verify:

```bash
cat /sys/kernel/security/lsm
# lockdown,capability,yama,selinux,bpf,...   <- "bpf" must be present
```

Details: [docs/INSTALL.md](docs/INSTALL.md)

## Quick start

```bash
axctl init                  # create ~/.axlinux/
axctl policy edit           # write your policy
axctl policy check          # validate it
axctl policy simulate       # see what it WOULD affect, before applying
axctl mode permissive       # log, do not block
axctl reload                # apply
axctl status                # check the real state
```

**Follow this order.** `simulate` is the most important command — it
shows the effect of your rules before anything is enforced.

### Example policies

Four ready-made examples live in `examples/`; all pass
`axctl policy check`:

| File | Purpose |
|---|---|
| `examples/minimal.yaml` | Smallest possible starting point |
| `examples/desktop.yaml` | Desktop use (SSH/GPG keys, browser profiles) |
| `examples/web-server.yaml` | Web server (config and log protection) |
| `examples/50-guvenli-baslangic.yaml` | Safe default for new machines |
| `packaging/fedora/axlinux-sample-workstation.yaml` | Installed sample (intentionally empty) |

To deploy one:

```bash
sudo cp examples/50-guvenli-baslangic.yaml /etc/axlinux/policies.d/
axctl policy check -f /etc/axlinux/policies.d/50-guvenli-baslangic.yaml
sudo axctl reload
```

Policy language: [docs/policy-language.md](docs/policy-language.md)

## How it works?

```
  axctl (Python)                     axdaemon (Go)                kernel
       │                                   │                          │
  YAML ──┤ policy check / simulate         │                          │
       │                                   │                          │
  policy.yaml ─────────────────────────────►│                          │
       │                           load eBPF programs              │
       │                                   ├─────────────────────────►│
       │                                   │      attach LSM hooks    │
       │                                   ├─────────────────────────►│
       │                                   │      write deny/allow map │
       │                                   ├─────────────────────────►│
       │◄────── status (hooks, rules) ──────┤                          │
       │                                   │                          │
       │◄────── logs (JSONL) ──────────────┴──── audit perf buffer ───┤
```

`axdaemon` compiles your policy into eBPF maps and attaches the LSM
hooks. The kernel then returns the decision inside the hook — the
calling process never enters user space and never blocks on a daemon.

Violations are written as JSONL to `/var/log/axlinux/`.

The SELinux module (`axlinux.pp`) grants the `bpf()` capability **only**
to the `axdaemon` domain. Nothing system-wide.

## Why it is safe on a physical machine

AXlinux is meant to be used on the machine you work on every day. It
does not require a virtual machine, and it does not refuse to run on
physical hardware — `install.sh` and `axctl` contain **no**
virtual-machine check at all.

What you may have read about "physical machine protection" refers to
the **test suite**, not the product: `tests/deep_verify.sh` refuses to
run enforcement tests on a physical machine, because a test that
deliberately denies access can lock the machine you are working on. It
can be overridden with `AXLINUX_ALLOW_PHYSICAL=1`. That is a property
of the *tests*, not a limitation of the product.

### The properties that make physical use safe

These are measured, not asserted:

| Property | Measured result |
|---|---|
| **Emergency exit always works** | A policy denying `cat /etc/hostname` made the read fail (`rc=1`). `axctl mode disabled` immediately after made the same read succeed (`rc=0`). No reboot required. |
| **Policy survives reboot** | A rule placed in `policies.d/` was loaded at boot (`rules=1`) and enforced (`rc=1`). |
| **SELinux confines only the daemon** | The module grants `cap_bpf` to `axlinux_daemon_t` alone — verified as 10 types and 8 file-context rules, never system-wide. |
| **Preview before enforcement** | `axctl policy simulate` evaluates rules without applying them. |
| **A failing policy can be rolled back** | `axctl mode disabled` needs no policy, no network and no other process. |

### The safe order

```
1. axctl policy check      validate syntax and meaning
2. axctl policy simulate  see the effect in advance
3. axctl mode permissive   observe without blocking
4. axctl reload            apply
5. axctl status            confirm the real state
```

### Practical recommendations

- **Start in `permissive`.** Run it for a few days and read the log
  before you block anything.
- **Never deny your own shell.** Shells are your recovery path. The
  validator warns when a rule targets recovery processes such as
  `bash`, `zsh` or `fish`.
- **Do not use a `file.execute` deny rule on `/usr/bin` before you have
  confirmed the allow-list is correct.** It can stop your system from
  starting services.
- **Keep `axctl mode disabled` in your muscle memory.** It is one
  command and it always works.

### Known structural limit

The `inode_permission` hook cannot return a **path**: the kernel ABI
gives it only `struct inode *`, with no way back to a dentry. AXlinux
therefore records `ino` + `dev` identity for those events, and obtains
paths from the `file_open` and `bprm_check_security` hooks instead.
This is a kernel design constraint, not a missing feature.

## Fedora-specific behaviour

Two behaviours are worth knowing:

**1. The root filesystem is a btrfs subvolume.** Path rules work for
`/etc`, `/var`, `/home` and `/root`. Separate mount points such as
`/tmp`, `/dev/shm`, `/run` and `/run/user/N` also work: the daemon reads
the superblock device from `mountinfo`, records it in
`mount_point_map`, and when BPF reaches a mount root it appends the
prefix beneath that path.

**2. `file.execute` rules apply to the target of symbolic links.** If
`/usr/bin/python3` is a symlink, the rule is written for `python3.14`.
This is mandatory for security — otherwise a rule can be bypassed
through a link.

## Verified status

Every number below was measured. Source:
[docs/VERIFICATION-REPORT.md](docs/VERIFICATION-REPORT.md).

### `deep_verify.sh` — 732 checks

| Platform | passed | failed | skipped |
|---|---|---|---|
| **Fedora 44** | **732** | **0** | **0** |
| Fedora 43 | 732 | 1 | 1 |
| Ubuntu 24.04.5 | 731 | 0 | 1 |
| Debian 12 | 731 | 0 | 1 |
| Pardus 25.2 | 731 | 0 | 1 |

The single skip on Debian-family systems is `SELinux unavailable` — the
Debian family ships no SELinux. That is a platform difference, not a gap.
On Fedora 44 **nothing is skipped and nothing fails**.

The single failure on Fedora 43 is an honest report: on that image,
enabling SELinux confinement prevents eBPF from loading, so the
installer detects this, reverts the labels and leaves enforcement
running on LSM alone (measured: hooks 5/5, eBPF 5/5).

### Measured performance

| Metric | Value |
|---|---|
| `axdaemon` RSS | 108,236 kB (~106 MB) |
| Open file descriptors | 33 |
| 50,000 file opens (`enforcing`) | 0.559 s (~89,600 opens/s) |
| 50,000 file opens (`disabled`) | 0.228 s (~220,000 opens/s) |
| Policy lookup cost | +5.8 µs (ranges do not overlap — measurable) |

The difference is 0.33 seconds — imperceptible in a real workload such
as a browser start.

> Absolute microsecond figures are not a criterion on their own: the
> same measurement runs about 20× slower under Ubuntu than Fedora,
> because the virtual machine environment dominates. The test suite
> therefore applies a **relative** threshold.

### Packaging matrix

All five images were built and verified: `fedora:41/42/43/44` and
`debian:12` — each with 8/8 content, 5 conffiles and the SELinux module.

## Tests

```bash
# Local package — fast
python3 -m pytest tests/ -q          # 180 tests + 22 subtests
cd src/go/axdaemon && go test ./...  # 10 packages
cd src/go/axlog    && go test ./...  # 3 packages

# Full verification — requires a virtual machine
sudo bash tests/deep_verify.sh
```

`deep_verify.sh` runs 732 checks and produces a single report. It
refuses to run enforcement tests on a physical machine, because those
tests deliberately deny access and could lock the machine. Override
with `AXLINUX_ALLOW_PHYSICAL=1` only if you have console access and a
known way out.

Details: [docs/VERIFICATION-REPORT.md](docs/VERIFICATION-REPORT.md)

## Emergency exit

```bash
sudo axctl mode disabled
```

This always works, removes every restriction, and requires no reboot.
Keep it in your muscle memory before you write your first rule.

## Contributing

Contributions are welcome: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT — see [LICENSE](LICENSE)

## Documentation

| Document | Contents |
|---|---|
| [docs/VERIFICATION-REPORT.md](docs/VERIFICATION-REPORT.md) | How every claim was proven; real bugs found |
| [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) | Installation paths and per-platform results |
| [SUPPORT.md](SUPPORT.md) | Supported systems and limits |
| [docs/FEDORA-READINESS.md](docs/FEDORA-READINESS.md) | Fedora measurement tables |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [docs/INSTALL.md](docs/INSTALL.md) | Detailed installation |
| [docs/policy-language.md](docs/policy-language.md) | Policy language reference |
| [docs/cli-reference.md](docs/cli-reference.md) | All commands |
| [docs/architecture.md](docs/architecture.md) | Internal architecture |
| [SECURITY-NOTICE.md](SECURITY-NOTICE.md) | Safety notes and emergency exit |
| [docs/challenges-risks.md](docs/challenges-risks.md) | Known challenges and risks |