# AXlinux 1.2.0 — Distribution Document

**You write YAML, AXlinux enforces it.**

AXlinux audits **which process read or wrote which file, which port it
connected to, and what it executed** in real time, by placing eBPF hooks
into the kernel's LSM (Linux Security Module) chain. You write a rule, it is
applied. If you do not write a rule, the system stays open.

| | |
|---|---|
| Version | **1.2.0** |
| Driver module | Linux LSM + eBPF (CO-RE) |
| Distribution | `axdaemon` (Go), `axlog` (Go), `axctl` (Python 3) |
| Verified | Ubuntu 24.04.5, Debian 12 (bookworm), **Pardus 25.2 (yirmibes)** |

Fedora version support and kernel requirements: [`SUPPORT.md`](../SUPPORT.md).
The packaging matrix in CI is the contract of this table (`fedora:41/42/43/44`, `debian:12`).
| Test result | **Fedora 44: 732 passed / 0 failed / 0 skipped** — see the table in §1 for the other distributions. Local package: 180 pytest + 22 subtests, 13 Go packages |

---

## 1. Status

AXlinux was verified end to end with **real enforcement** on three
distributions. The tests were run in a virtual machine; both LSM hook
groups genuinely passed through eBPF.

| Verified | Result |
|---|---|
| Fedora 44 (Cloud) | 732/0/0 · signed RPM · SELinux Enforcing · 5/5 hooks |
| Fedora 43 (Cloud) | 732/1/1 · LSM enforcement works (hook 5/5) · SELinux confinement cannot be done on this image and is rolled back with a warning during installation |
| Ubuntu 24.04.5 LTS | 731/0/1 · 5/5 eBPF programs · 5/5 hooks · audit healthy |
| Debian 12 (bookworm) | 731/0/1 · 5/5 · 5/5 · audit healthy |
| Pardus 25.2 (yirmibes) | 731/0/1 · 5/5 · 5/5 · audit healthy |

The single skipped item in the `731/0/1` rows is **SELinux**: the Debian
family does not ship SELinux; this is not a gap but a platform difference.
On Fedora 44 the same item works and passes with 0 skipped items.

Areas covered: all CLI commands, learning mode end to end, 5 LSM hooks, 6
action types, permanent JSONL audit, three modes and emergency shutdown,
lockout protection, error paths and policy language edge cases.

---

## 2. Requirements

| Component | Version | Note |
|---|---|---|
| Kernel | **5.15+** | `CONFIG_BPF_LSM=y` **and** `lsm=bpf` must be in the chain |
| clang | 12+ | must support `-target bpf` |
| Go | 1.21+ | for **compilation** only (not needed at runtime) |
| Python | 3.9+ | `click`, `rich`, `PyYAML` |
| Root privilege | — | for the installation and for `axctl` |

Verify the kernel's LSM support:

```bash
cat /sys/kernel/security/lsm      # the output must contain 'bpf'
```

If `bpf` is not in the list, first make sure that `CONFIG_BPF_LSM=y` is set
in `/boot/config-$(uname -r)`. `lockdown`, `capability`, `landlock`,
`yama`, `apparmor`, `tomoyo` are not required for authentication — AXlinux
does not replace them, it is **added** to them.

---

## 3. Installation

```bash
tar -xzf axlinux-kaynak-<tarih>.tar.gz
cd axlinux
sudo bash install.sh
```

The script proceeds in 10 steps and writes what it is doing at each step.
Currently:

```
[ 1/10] Yetki denetimi
[ 2/10] Ortam denetimi
[ 3/10] bpf LSM denetimi
[ 4/10] Dependencies
[ 5/10] Kaynak kod
[ 6/10] Derleme
[ 7/10] Kurulum
[ 8/10] Servisler
[ 9/10] Verification
[10/10] First policy
```

Silent (unattended) installation:

```bash
sudo bash install.sh --unattended
```

The installation is **distribution independent**: `apt-get`, `dnf`/`yum`,
`pacman`, `apk` and `zypper` are supported. A single missing package does
not bring down the entire installation — packages are installed one by one,
the missing ones are skipped and reported.

### What the installation puts in place

| Path | Content |
|---|---|
| `/usr/bin/axctl` | CLI entry point |
| `/usr/bin/axdaemon` | LSM enforcer (Go) |
| `/usr/bin/axlog` | Audit writer (Go) |
| `/usr/lib/axlinux/` | `axbpf.o` and the Python package |
| `/etc/axlinux/` | Sample policies |
| `/etc/systemd/system/` | `axdaemon.service`, `axlog.service` |
| `/usr/lib/tmpfiles.d/axlinux.conf` | management of `/run/axlinux` |
| `~/.axlinux/policy.yaml` | Your policy (per user) |

---


## Fedora 44 (SELinux Enforcing)

Fedora is the primary target distribution of AXlinux and it is verified
under **Enforcing** SELinux. `selinux=permissive` is not used.

### Fedora-specific behaviours

The root filesystem is a **btrfs subvolume** (`subvolid=256`,
`mountinfo: root=/root mountpoint=/`). This gives rise to two separate
issues in path resolution:

| Location | Visible path | Note |
|---|---|---|
| `/etc/...` | `/etc/...` | works |
| `/var/...`, `/home/...` | `/var/...`, `/home/...` | works |
| `/root/...` | `/root/...` | works |
  | `/tmp/...`, `/dev/shm/...`, `/run/...` | `/tmp/...` | works (mount point map) |

Root filesystem is a btrfs subvolume: the invisible `root` component is
discarded via `mount_artifact_map`. Separate mounts (`/tmp` tmpfs): the
invisible mount point prefix is added back via `mount_point_map`. Both are
verified inside `tests/deep_verify.sh` with real deny rules
(`separate mount path [tmpfs /tmp] applied`). Because `/tmp` is a tmpfs
mount, the name of the mount point is not visible in the dentry chain. This
is a structural limit, not a bug. When using path rules, make sure that the
absolute path is **on the root filesystem**.

On the SELinux side:

```bash
# Processes run in their own domains
$ ps -eo label,comm | grep ax
system_u:object_r:axlinux_daemon_t:s0 axdaemon
system_u:object_r:axlinux_log_t:s0      axlog

# Is the policy actually loaded
$ sudo semodule -l | grep axlinux
axlinux
```

The SELinux module requires `selinux-policy-devel`; `install.sh` installs
the package itself and recompiles the module every time.

### Fedora verification result

On Fedora 44, kernel `6.19.10-300.fc44.x86_64`, SELinux Enforcing:

```
bpf: 5/5   hooks: 5/5   enforcement: True   audit healthy: True
tests/deep_verify.sh: 732 passed / 0 failed / 0 skipped
```

## 4. The first five minutes

```bash
# 1) Start: empty policy = system is open
sudo axctl init

# 2) Examine one of the ready-made templates
axctl template ls
sudo axctl template apply web-server
axctl policy check              # validate BEFORE applying

# 3) Apply
sudo axctl reload --mode enforcing

# 4) What is happening?
axctl status
axctl logs --limit 20

# 5) Write your own rule
nano ~/.axlinux/policy.yaml
axctl policy check && sudo axctl reload
```

A rule looks like this:

```yaml
version: 1
mode: enforcing
rules:
  - id: r1
    name: "nginx must not read shadow"
    subject: nginx
    object: /etc/shadow
    action: file.read
    effect: deny
```

`subject` is the process name, `object` is the path (or the port), `action`
is what is to be done, `effect` is permission or prohibition.

---

## 5. Command reference

| Command | What it does |
|---|---|
| `axctl init [--force]` | Creates the `~/.axlinux/` directory and an empty policy |
| `axctl status [--json]` | LSM status, hooks, counters, health |
| `axctl reload [--mode M] [--force-empty]` | Compiles and applies the policy |
| `axctl mode enforcing\|permissive\|disabled` | Changes the mode |
| `axctl logs [--json] [--subject S] [--action A] [--effect E] [--filter K=V] [--since 1h] [--limit N] [--follow]` | Audit records |
| `axctl label add NAME DRIVER...` | Defines a label (multiple processes) |
| `axctl label ls` | Lists the labels |
| `axctl label rm NAME` | Removes the label |
| `axctl learn start [--days N]` | Starts learning mode |
| `axctl learn stop` | Stops learning |
| `axctl learn report [--format text\|json]` | Observation report + suggested YAML |
| `axctl template ls` | Lists the ready-made templates |
| `axctl template apply NAME` | Applies the template to the policy |
| `axctl policy edit` | Opens the policy in an editor |
| `axctl policy check [-f FILE]` | Validates (before applying!) |
| `axctl policy simulate [-f FILE] [--format json]` | Simulates the effect |

### Exit codes

Scripts rely on these:

| Code | Meaning | Example |
|---|---|---|
| `0` | success | — |
| `1` | **application-level rejection by the daemon** | `axctl learn start` a second time → "learning mode already active" |
| `2` | **policy error** *or* **command-line error** | `policy check` on broken YAML; `axctl mode bogus`; unknown command/option/argument |
| `4` | **infrastructure error** — check the machine | daemon down, no socket |
| `5` | configuration / template error | `axctl template apply nonexistent` |
| `130` | the user cancelled with Ctrl+C | — |

> **The code `2` combines two things:** both a corrupt policy and a
> mistyped command return `2`. To tell them apart, look at the message: if
> it is `axctl: no such option` / `no such command`, it is a
> **command-line** error; a policy validation message means a **policy**
> error.
> The important distinction is `1` ↔ `4`: `1` means "you typed the command
> correctly, the daemon rejected it", `4` means "there is a problem in the
> system".

---

## 6. Actions and hooks

| Action | LSM hook | Key |
|---|---|---|
| `file.read` | `file_open` | path |
| `file.write` | `file_open` | path |
| `file.execute` | `bprm_check_security` | path |
| `process.exec` | `bprm_check_security` | process (pathless) |
| `net.connect` | `socket_connect` | `p:PORT` |
| `net.bind` | `socket_bind` | `p:PORT` |

Path length limit: **up to 8 components**, 32 bytes per component. A deeper
path, or one with longer components, is not accepted — such a rule does not
fit into the eBPF key and **silently matches nothing**.

In network rules `port` is mandatory. It cannot be given together with
`object`.

---

## 7. Protected processes

The following **31 processes** **are not subject to any rule**: `swapper`, `migration`, `systemd`, `systemd-logind`, `systemd-userdbd`, `systemd-udevd`, `systemd-journald`, `systemd-oomd`, `init`, `kthreadd`, `sshd`, `sshd-session`, `login`, `agetty`, `getty`, `sudo`, `su`, `doas`, `dbus-daemon`, `dbus-broker`, `polkitd`, `rtkit-daemon`, `NetworkManager`, `wpa_supplicant`, `gdm3`, `gdm-session-worker`, `bash`, `sh`, `dash`, `zsh` and `fish`.

These are the login and recovery path; blocking them makes the system
unusable. **If you write a rule for these processes the policy is
rejected** — because it can be proven that the rule would not work, and
remaining silently ineffective is the most dangerous outcome in a security
tool.

Write the rule against the **application**: `firefox`, `nginx`,
`redis-server`, `curl`, `postgres`.

---

## 8. Learning mode

Observes what the system normally does and produces a starting policy.

```bash
sudo axctl learn start --days 3
# ... your normal work ...
axctl learn report
sudo axctl learn stop
```

`learn start` runs for the given number of days and then shuts itself down.
The observations come from the enforcement hooks **at the moment the event
is produced**; they accumulate even if you do not query anything.

The suggestion block at the bottom of the report is **directly pasteable
YAML**. Check it with `axctl policy check` before applying.

---

## 9. Audit

Every enforcement decision is written to permanent disk as JSONL:

```
/var/log/axlinux/audit-YYYY-MM-DD.jsonl        (today)
/var/log/axlinux/audit-YYYY-MM-DD.jsonl.gz     (compressed older days)
```

`axlog` is a separate service. If the record chain breaks, it is not
swallowed silently: `axctl status` shows `audit_healthy: false`.

```bash
axctl logs --effect deny --limit 50      # denials only
axctl logs --subject nginx               # all actions of one process
axctl logs --action file.read --json     # machine-readable
```

If you do not filter on a field, `axctl` **warns** you — "a filter I did
not apply" is not swallowed silently, because "I think I filtered the
denials, I see the allow records and assume it works correctly" is a
typical mistake.

---

## 10. Modes

| Mode | Behaviour |
|---|---|
| `enforcing` | the violation is blocked **and** recorded |
| `permissive` | the violation is recorded, not blocked (for testing) |
| `disabled` | no restriction at all |

### Emergency shutdown

If you lock yourself out because of a wrong policy:

```bash
sudo axctl reload --force-empty --mode disabled
```

This command is the **emergency recovery path** and works in every
situation: an empty policy is considered valid, the rule count is not
checked.

> `sudo axctl mode disabled` is also an emergency exit. Both can be used
> together; in an emergency try them one after the other.

### Lockout protection

Accidentally closing your own session while writing a policy is prevented:
`bash`, `sh`, `sudo`, `sshd`, `login`, `systemd` and 23 more processes are
always protected (see §7). Nevertheless, **try the first policy in
`permissive` mode on a live system**:

```bash
sudo axctl reload --mode permissive
# observe, then make it enforcing
```

---

## 11. Verification

After the installation, run your own verification:

```bash
# quick: one command
sudo axctl status

# comprehensive: 8 named sections (K–R), 732 checks
# (THE TEST SCRIPT DOES NOT RUN ON A PHYSICAL MACHINE; the product itself
#  works on physical machines — see the note below)
sudo bash tests/deep_verify.sh

# single section
sudo bash tests/deep_verify.sh -k D
```

`deep_verify.sh` declines to run on a physical machine, because a test that
deliberately denies access can lock the machine you are working on. This
guard can be disabled with `AXLINUX_ALLOW_PHYSICAL=1`, but **do not do
that**.

This is a property of the **test harness**, not a limitation of the
product: AXlinux itself works on physical machines. Neither `install.sh`
nor `axctl` contains a virtual-machine check. Override the guard only if
you have console access and a known way out.

Source development:

```bash
make test          # Go + static + guard + silent error + Python (164 tests)
make verify        # compile and check eBPF
make clean
```

---

## 12. Limits (an honest list)

You have to accept these deliberately:

- **`net.accept` is not supported.** There is no corresponding
  `socket_accept` hook in the LSM; writing a rule would therefore also be
  meaningless. Auditing incoming connections is done with `socket_bind` +
  the application layer.
- **Path depth is 8 components, component length is 31 bytes.** Deeper
  paths cannot be written as a rule (they do not work silently — they are
  rejected).
- **`subject` is a process name, not a user.** `curl` is the same for all
  users.
- **This applies to the root filesystem.** The policy speaks about the
  process, not about the user who runs it.
- **A full desktop was not installed on Pardus.** The verification system
  was installed from the official archive of Pardus
  (`bilgemdepo.pardus.org.tr`, signed) with
  `base-files 13.8+pardus25.2.1`; `pardus-backgrounds`,
  `pardus-bilge-grub-theme`, `desktop-base` are installed. The kernel,
  libraries and tools that AXlinux needs to run are complete; the XFCE/GNOME
  desktop itself was not installed because AXlinux is not a desktop
  application.
- **`lsm=bpf` is a kernel parameter.** If a different boot parameter is
  required (`lsm=...,bpf` in GRUB), configure it separately.

---

## 13. Removal

```bash
sudo systemctl disable --now axdaemon axlog
sudo make uninstall
```

Remaining: `~/.axlinux/policy.yaml`, `/etc/axlinux/`,
`/var/log/axlinux/`, `/usr/lib/tmpfiles.d/axlinux.conf`.
If you want to keep your policy, back up `policy.yaml` beforehand.

---

## 14. How it works (brief)

```
  axctl (Python)          axdaemon (Go)                kernel
       │                        │                          │
       │  JSON-RPC socket       │                          │
       ├───────────────────────►│                          │
       │  compiled policy       │  writes to eBPF maps     │
       │                        ├─────────────────────────►│
       │                        │                          │ LSM
       │  JSON-RPC socket       │  audit event             │ hooks
       ├───────────────────────►│  ◄───────────────────────┤ are triggered
       │                        │                          │
 axlog (Go) ◄───────────────────┤  JSONL to disk           │
```

- `axctl` reads the policy YAML, validates it and **compiles it into an
  internal form**.
- `axdaemon` writes this form into the eBPF maps; the hooks are effective
  immediately.
- When a hook is triggered, the decision drops into the audit queue.
- `axlog` drains the queue and writes it to the permanent JSONL file.
- The mode (`enforcing`/`permissive`/`disabled`) is kept in a separate map
  and can be changed immediately.

Detailed design: `docs/architecture.md`,
`docs/policy-language.md`, `docs/cli-reference.md`.

---

## 15. Archived version

The source archive that accompanies this document:

```
/home/mami/axlinux-kaynak-20261001-1715.tar.gz
```

sha256 verification and a restore test were performed (140 files; 164
tests pass when it is restored).

---

## Before putting it on a live system

Version 1.0.0; verified end to end on three distributions. Still, if this is
your first installation, go in order:

1. Start in `permissive` mode and observe for a while:
   `sudo axctl reload --mode permissive`
2. Verify that the records in `/var/log/axlinux/` are actually being filled
   (`axctl logs`). If there are no records, the system is not enforcing as
   you think.
3. **Test the emergency recovery command once:**
   `sudo axctl reload --force-empty --mode disabled`
   You need to know that it works before you need it.
4. Set the mode to `enforcing` and read the audit records of the first day.

If you run into a policy error, first:

```bash
sudo axctl reload --force-empty --mode disabled   # leave the system open
axctl policy check                                 # find the error
```

The output of `axctl policy check` gives the rule identity and the reason;
this information is useful if you want to share it in `CHANGELOG.md` or as
an issue.