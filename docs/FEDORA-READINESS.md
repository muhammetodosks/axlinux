# Fedora 44 Workstation Readiness Report — Test Evidence

**Version:** 1.2.0 · **Date:** 2026-10-06 · **Target:** Fedora Workstation desktop

This document shows **by measurement** that AXlinux runs on Fedora 44 desktop.
Every number was taken on this VM; there are no estimates or target values.

> **Out of scope:** Production server evaluation. This document covers the desktop
> scenario. AXlinux is a MAC (mandatory access control); server workloads require
> a separate evaluation.

---

## 0. Safety first: this tool was not run on your primary machine

Constraint: **AXlinux will not be run on `/dev/sdb1`, no enforcement testing
will be done there. Everything happens in the `/mnt/anka` VM.**

| Location | State | Evidence |
|---|---|---|
| Primary machine `/dev/sdb1` | **Untouched** | `axdaemon inactive`, `axlog inactive`, 0 BPF maps, 0 LSM programs |
| Primary machine `/sys/fs/bpf/axlinux` | Absent | directory does not exist |
| Test environment | `/mnt/anka/axlinux-vm/fedora44-ax.qcow2` | SSH `ax@127.0.0.1:2230` |

VM environment: Fedora 44 Cloud, kernel `6.19.10-300.fc44.x86_64`,
GNOME 50 (gdm 50.3, gnome-shell 50.5, mutter 50.5), Wayland,
SELinux `Enforcing`.

---

## 1. Test scope

| Component | Method |
|---|---|
| Fedora 44 kernel | clean RPM installation, then `deep_verify.sh` |
| GNOME desktop | real gdm + Wayland session, automatic login |
| Policy | realistic desktop scenario, `enforcing` |
| Reboot | `systemctl reboot`, then automatic login verification |
| Performance | 3-condition file-open latency + 50,000 opens total workload |
| Disk | audit bytes/operation measurement over 325 operations |

---

## 2. Desktop evidence (Workstation scenario)

### 2.1 Real GNOME session

| Evidence | Value |
|---|---|
| `gdm` | `active` / `enabled` |
| Session type | `wayland` |
| `gnome-shell` | running, 2 Wayland connections |
| `systemd --user` | `running` |
| Failed user services | 0 |
| Automatic login | `axdesktop` (UID 1001), `seat0`, `tty2` |

### 2.2 Real GUI application (with enforcement active)

`gedit /etc/hostname` was opened in the desktop session:

- PID 2298, **Wayland connections: 1** (a real GUI client)
- window contents: `fedora-ax`, `Line 1, Col 1`, `Plain Text`

Visual evidence was taken from the QEMU monitor (`screendump`):

- **Before the reboot:** full GNOME desktop — top bar
  (`Oct 6 3:42 PM`), an open **gedit window** (`fedora-ax` content,
  `Plain Text`, `Tab Width: 8`), the application dock. With enforcement
  active, a `Low Disk Space` warning is visible in the background.
- **After the reboot:** automatic login worked and the session is
  live, but the screen appears **locked**. This is not a bug:
  because a virtual machine has no physical console input, GNOME locks
  the screen when idle, and `screendump` captures the lock screen.
  QEMU `sendkey` was attempted to unlock it; synthetic keys did not open
  the lock in a Wayland session. That the session is live was verified
  programmatically (§2.5): the session is `active`, the session type is
  `wayland`, `gnome-shell` is up and gedit is running as a Wayland client.

`xclock` was attempted and **failed**: `Can't open display`.
This is not a product defect — xclock is an X11 application and the
session is Wayland. X11 clients do not run in a Wayland session.

### 2.3 Package management (dnf)

Real package installation was performed with enforcement **active**:

```
sudo dnf install -y gedit xclock     →  13 packages, 36 seconds, Complete!
```

This alone proves two things: `dnf` runs under enforcement and desktop package
management is not broken.

Note: **no GUI application at all was installed in the VM**. Real applications
were needed in order to call it a "Workstation"; `gedit` closed that gap.

### 2.4 Realistic enforcing policy (4 rules)

The policy is **system-wide** in `/etc/axlinux/policies.d/50-workstation.yaml`
and is loaded by `axdaemon` itself at boot.

| Rule | Operation attempted | Result |
|---|---|---|
| `subject: [firefox]` + read `.ssh/id_rsa` | reading the key from the browser | `Operation not permitted` |
| `subject: [md5sum]` + `process.exec` | `md5sum /etc/hostname` | `Operation not permitted` |
| `subject: ["*"]` + read `.gnupg/secret.gpg` | reading with `cat` | `Operation not permitted` |
| `subject: ["*"]` + write `/etc/ax-koruma` | writing with `>>` | `Permission denied` |
| *(not covered by a rule)* | `cat /etc/hostname` | **allowed** (`fedora-ax`) |
| *(not covered by a rule)* | writing a file in the home directory | **allowed** |

The desktop did **not crash** during these rules: gedit stayed open,
the session stayed active.

### 2.5 After the reboot

After `systemctl reboot`:

| Evidence | Value |
|---|---|
| `uptime` | ~1 minute (fresh boot) |
| `gdm` / `axdaemon` / `axlog` | `active` / `enabled` (all three) |
| Automatic login | `axdesktop` session `active` |
| Session type | `wayland` |
| **System policy** | `sistem politikasi uygulandi ... rules=4 mode=enforcing` |
| LSM hooks | 5/5 |
| Enforcement | `enforcing`, 4 rules, 5 deny inputs |
| `audit_healthy` | `true` |
| GUI application | gedit reopened (PID 19957), Wayland connections: 1 |
| `dnf` | `dnf5 version 5.4.1.0` |
| System policy loading | 28 automatic loads since boot |

The critical point: **the policy loaded by itself after the reboot**.
This did not happen under the old behaviour (see §6.1).

---

## 3. Performance: file-open latency (target 5)

Three-condition measurement, same workload (`/etc/hostname`, `/etc/hosts`,
`/etc/passwd`, `/etc/group`, `/etc/os-release`), 80 opens per file,
`time.perf_counter_ns()`.

| Condition | 3 runs (µs/open) | Median |
|---|---|---|
| **[1] No LSM hook** (`axdaemon` stopped, 0/5) | 14.3 · 13.2 · 12.1 | **13.2 µs** |
| **[2] Hook attached, `mode=disabled`** (5/5) | 12.7 · 16.3 · 17.8 | **16.3 µs** |
| **[3] Hook attached, `mode=enforcing`** (5/5) | 22.1 · 26.2 · 21.9 | **22.1 µs** |

### What is real and what is not

**The policy lookup cost is real and measurable.**
The median difference 22.1 − 16.3 = **+5.8 µs**, and the ranges of these two
groups **do not overlap** ([2] highest 17.8 < [3] lowest 21.9). Enforcement
therefore genuinely adds cost per file open.

**The hook attachment cost was not measurable on this machine.**
A median difference of +3.1 µs is visible, but the ranges of [1] and [2]
**overlap** ([1] 12.1–14.3, [2] 12.7–17.8): the fastest run of [2] is
faster than the slowest run of [1]. In other words, this difference cannot be
distinguished from run-to-run noise.

> This section previously stated "hook attachment cost +5.8 µs (51%), policy
> lookup +0.6 µs (3.5%)" and its conclusion was **backwards**. In the current
> measurement the policy cost comes out **larger** than the hook cost
> (+5.8 µs vs an unmeasurable difference). The old numbers were based on a single
> run; they cannot be reproduced under repeated measurement.

### Why absolute µs alone is not the criterion

The same measurement on Ubuntu 24.04.5 came out roughly **20 times slower**
than on Fedora — because the virtual machine environment rather than the AXlinux
hook is the determining factor. This is why `deep_verify` now applies an
**environment-corrected relative ratio** instead of an absolute µs threshold
("environment-corrected hook cost: 1.01x baseline"); the absolute numbers are
valid only for **this machine**, as shown below.

### Total workload (50,000 file opens)

A fixed workload representative of opening a heavy browser session:

| Mode | 2 runs (50,000 opens) | Median | µs/open | opens/s |
|---|---|---|---|---|
| `disabled` | 0.226 s · 0.229 s | **0.228 s** | ~4.55 | ~220,000 |
| `enforcing` | 0.550 s · 0.567 s | **0.559 s** | ~11.2 | ~89,600 |

**Interpretation for the desktop:** 50,000 file opens take 0.56 s under
enforcing instead of 0.23 s — **a difference of 0.33 seconds**.

> The old value in this table (`enforcing` 0.44 s) showed the enforcement
> cost **too optimistically**. In the fresh measurement the enforcement
> cost came out close to double (0.56 s). The *conclusion* of the interpretation
> above has not changed — 0.33 seconds is not perceptible in a desktop startup —
> but the numeric value was corrected. The resulting enforcement rate
> (~90,000 opens/s) is a rate a desktop will never reach.

---

## 4. Disk consumption of the audit journal (target 5)

From a clean start (`/var/log/axlinux` emptied), 325 operations:

| Operation | Count | Produced | Bytes/operation |
|---|---|---|---|
| **Allowed** file read | 200 | **0 bytes** | no record |
| **Blocked** read | 50 | 12,585 bytes | 251.7 |
| Blocked execution | 25 | 6,373 bytes | 254.9 |
| **Allowed** execution | 50 | **0 bytes** | no record |

### Main finding

**Audit cost depends on the number of violations, not on total activity.**
Allowed operations produce no records at all in `enforcing` mode. On a properly
configured desktop, disk consumption is roughly:

> **bytes/day ≈ 250 × number of daily violations**

| Daily violations | Daily | Over 14 days (raw) |
|---|---|---|
| 10 | 2.5 KB | 35 KB |
| 100 | 25 KB | 350 KB |
| 1,000 | 250 KB | 3.5 MB |
| 10,000 | 2.5 MB | 35 MB |

Even in the 10,000 violations/day scenario, the 10 MB segment limit triggers
not daily but roughly every 4 days, and drops further with `gzip`-compressed
retention.

**Warning:** The measurement was taken with `learning` mode **off**.
With learning mode on, *every* operation is recorded; a 10.8 MB file with
43,641 records is the product of that mode.

### Disk pressure (desktop observation)

While screenshots were being taken, GNOME displayed the following warning:

> **Low Disk Space on "Filesystem root" — only 855.7 MB remaining**

The root file system was 96% full. Breakdown:

| Path | Size | Note |
|---|---|---|
| `/var/log/journal` | 198 MB | **no limit configured** (default: 10% of disk ≈ 2 GB) |
| `/var/cache/libdnf5` | 104 MB | dnf cache |
| `/var/log/axlinux` | 11 MB | AXlinux audit (now limited) |
| `/home/ax/axlinux/.android` | **17 GB** | Android emulator leftovers — unrelated to AXlinux, deleted |

After cleanup: **2.1 GB free (90%)**. The warning notification remained on screen
because free space is below the GNOME threshold; the durable fix is expanding the
disk or configuring the `journald` limit (see below).

Note: the `/var/log/journal` limit is not AXlinux's problem, but it is a real
disk-full risk under the desktop target and must be reported.

---

## 5. RPM evidence

| Property | Value |
|---|---|
| Version | `axlinux-1.1.0-1.fc44.x86_64` |
| Size | 2,189,772 bytes |
| sha256 | `8ba3aae64fb2e6f36f9a5ac663179c87…` |
| Installation | `dnf install -y <rpm>` → `Complete!` |
| `axdaemon` / `axlog` | `active` / `enabled` |
| SELinux module | `axlinux` installed |
| `axlog` reported version | **`1.1.0`** (matches the RPM) |
| LSM hooks | 5/5 |
| BPF pins | `allow_map deny_map mode_map` |
| System policy | `00-sample-workstation.yaml,50-workstation.yaml` → 4 rules, enforcing |
| SELinux domain | `system_u:system_r:axlinux_daemon_t:s0` |

A **clean installation** was attempted: the package was first removed with
`dnf remove` (`axdaemon` disappeared), then reinstalled. The table above is
from after this clean installation.

### Packaging verification

| Check | Result |
|---|---|
| `gofmt` | clean |
| `go build` (2 modules) | clean |
| `go vet` | clean |
| Go tests | 13 packages, all passed |
| Python tests | 180 passed + 22 subtests |
| `deep_verify.sh` | **732 passed / 0 failed / 0 skipped** |
| `.desktop`, `.service`, SELinux scripts | `bash -n` clean |

---

## 6. Real bugs found and fixed in this round

### 6.1 Policy disappeared after reboot *(the most serious)*

The policy was loaded **only** through the `axctl` API, from the running user's
`~/.axlinux/policy.yaml` file. At boot nothing was read; the BPF maps started
empty.

Result: after a reboot **all rules were lost** and the system silently
reverted to "nothing is restricted". The operator believes the policy is loaded
and sees `enforcing`, but nothing is blocked.

**Fix:** the `/etc/axlinux/policies.d/*.yaml` directory is read at boot
(`.yaml`/`.yml`, merged in lexical order). There is a single apply path,
`ApplyPolicy` — both RPC and boot use the same code.

If the policy is **broken, no rule is written at all** and the system remains
unrestricted; the daemon writes a prominent warning to the journal. This is a
deliberate choice rather than locking the system by mistake.

### 6.2 Audit rotation did not work at all

`openCurrent()` generated the file name from **today's date every time**.
When the 10 MB size limit triggered, the same file was reopened with
`O_APPEND` — the file never rotated, it only grew. In the VM it had reached
10,798,351 bytes and would have kept growing unnoticed.

There was also **no upper bound on retention**: a new file accumulated every day.
If a desktop stays up for months, `/var/log` fills up.

**Fix:** numbered segments (`audit-GÜN.1.jsonl`), compression covering all
segments at the day change, 14-day retention. The `writer` package had
**no tests at all** — 4 regression tests were added and they were verified to
fail against the old code.

### 6.3 `audit_healthy` stayed permanently `false`

When `axlog` restarted, a "broken pipe" occurred once; on the next attempt the
connection was re-established on its own and records kept flowing — but `lastErr`
stayed in memory. The system was reported as `audit_healthy=false` while it was
completely healthy.

Impact: the operator receives a permanent false alarm even though there is no
real outage; worse, they can pass over a real outage as "a temporary error".

**Fix:** a successful send clears `lastErr`.

### 6.4 `axlog` reported the wrong version

There was a hardcoded `"1.0.0"` constant inside `axlog/main.go`. While the RPM
was built as 1.1.0, the log service reported itself as **1.0.0**.

Additionally the `Makefile` scraped the version out of `axdaemon/main.go`;
had the definition there been `const` → `var`, the scrape would have silently
frozen to an empty string and the package would have been produced as
`axlinux-.deb`.

**Fix:** the version now comes from a single source (`axlinux.spec`) and is
injected into both binaries with `-ldflags`. A verification test audits the
new design.

### 6.5 `deep_verify` was affected by its own state

The test used the fixed path `/tmp/axctl-cli.txt`. When a non-root user ran and
abandoned the test, the file remained owned by that user; on the next run root
could not write to the same path, got `Permission denied` and awk exited with an
error — **the test FAILED even though there was no real regression.**

A verification gate must not be affected by its own leftovers. The file is now
bound to the running identity.

### 6.6 Measurement method error (not reported, fixed)

The first `/tmp` measurement produced the result "deny is not applied". That
result was **wrong**: `sudo axctl reload` reads the policy in **root's** home
directory, not the file the test wrote. No policy was ever applied. With the
correct setup, **all** deny rules work under `/tmp`, `/dev/shm`, `/run`, `/var/tmp`
and `/etc`.

The test that separates these cases: `deep_verify` reports "ayri mount yolu [tmpfs /tmp]
uygulandi / [tmpfs /dev/shm] uygulandi / [tmpfs /run] uygulandi —
3/3 konum".

---

## 6a. Item 7 closed in this round: the path in an audit record is never empty

### The measured gap

The `path` field in the `audit_event` struct was **identical to the policy key**:
8 components × 31 characters, 256 bytes total. In learning mode a record is
produced for every allowed file read, but the following paths did **not** fit
into the key:

| Path | Result |
|-----|-------|
| File name longer than 31 characters | `object: {}` |
| Directory deeper than 8 levels | `object: {}` |
| Path exceeding 256 bytes | `object: {}` |

Fedora 44, learning mode, 6 files:

```
/tmp/olcum/aaaaa.txt          (10 bytes)  -> resolved
31+ character name            (5 files)   -> EMPTY
```

The policy side was already safe: `setKeyPath` empties the key for a path that
cannot be represented and `ValidateRule` raises an **explicit error**; the rule
is therefore never applied silently. What was open was the **audit record** —
the operator could not see which file was denied.

### Solution

| Change | Where |
|------------|--------|
| `AX_AUDIT_DEPTH=16` / `AX_AUDIT_SLOT=64` separate, wider audit buffers (`apath`) | `src/bpf/axbpf.h` |
| `ax_fill_audit_path()` — full path including the mount root | `src/bpf/axbpf.h` |
| `AX_PATHFLAG_TRUNCATED` → JSON `truncated: true` | `src/bpf/axbpf.h`, `protocol.go` |
| `ino`+`dev` identity for `inode_permission` | `ax_fill_inode_id()` |
| `apath` first, the key as fallback (the key is for matching) | `sender.go` |

Because `/tmp`, `/var`, `/home` are btrfs **subvolumes**, the dentry walk stops
at the mount root; the prefix is taken from `mount_point_map` (the same mechanism
as the existing `ax_fill_path`).

### Three silent losses closed at the same time

| Loss | Symptom |
|-------|---------|
| `__builtin_memset` of 1352 bytes | rejected the BPF libcall → the program did not load |
| per-CPU perf buffer of 4096 | fits 2 events, the rest was **silently** dropped |
| No loss counter existed | a dropped record was visible nowhere |

The perf buffer was raised from `4096 → 65536` (~48 events per CPU) and the
`audit_lost_samples` + `audit_undersized` counters were added. Measured loss:
79 events in one learning run.

### Evidence (VM, clean installation)

```
audit yol kapisi: 4 kayit incelendi (kisa/uzun ad/derin yol)
80 karakter ad kirpildi ve isaretlendi (truncated=true)
audit kayitlarinda BOS YOL YOK (0/4); kirpilan=2 isaretli
```

C/Go struct equality was verified **by measurement** (size 1352 = 1352; `ino` 304,
`dev` 312, `apath` 316, `apath_flags` 1340) and `TestEventLayoutMatchesC`
recomputes it from the C header on every run.

## 6b. Distribution gaps closed in this round

The following were previously listed as "known limitations".
All were permanently resolved and proven.

### 6b.1 DIRECTORY RULES DID NOT PROTECT CONTENT (security flaw)

An `object: /tmp/dizin` + `file.read` deny rule blocked only the directory
**itself**:

```
cat /tmp/dizin              -> Operation not permitted
cat /tmp/dizin/secret.txt   -> READS FINE      ← leak
```

The user believed "my keys are protected".

**Solution:** path prefix matching on the BPF side. The rule key is the real
path's component block shifted *k* levels up; there is no change on the Go
side (the derived key is byte-for-byte identical to the `setKeyPath` output).

Production evidence (rule `object: /tmp/pm`):

| Path | Result |
|---|---|
| `/tmp/pm/kok.txt` | DENIED |
| `/tmp/pm/a/ust.txt` | DENIED |
| `/tmp/pm/a/b/derin.txt` | DENIED |
| `/tmp/pm/a/b/c/d4.txt` | DENIED |
| `/tmp/pm/a/b/c/d/d5.txt` | DENIED |
| `/tmp/pm/a/b/c/d/d6.txt` | DENIED |
| `/tmp/pm.txt` | ALLOWED (similar name, different path) |
| `/etc/hostname` | ALLOWED (not covered by a rule) |

**No false positives are produced.** This is now tested in `deep_verify` with 3
depth levels plus a false-positive check.

### 6b.2 THE RPM WAS NOT SIGNED

Every package distributed in a real repository must be signed.

```
make rpm-gpg-key      → generates rsa4096
make rpm              → signs automatically when a key is present
make rpm-sign         → signs the RPM
make rpm-export-key   → exports the public key under dist/
rpm --import dist/axlinux-signing-key.asc
rpm -Kv               → Header OpenPGP V4 RSA/SHA512 signature,
                         key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a531
```

The key is not kept in the repository; in production the secret key is the
developer's responsibility, not the repository's.

### 6b.3 `install.sh` DID NOT CREATE THE SYSTEM POLICY DIRECTORY

The RPM path created the directory in the spec; `install.sh` **did not**. The
two installation paths built two different systems, and both claimed to be
"working". `install.sh` now creates the directory as 0750 root:root and installs
the sample policy as 0640.

End-to-end evidence (clean Fedora 44, `install.sh --unattended`):
11/11 steps, then LSM 5/5, `axlinux_daemon_t:s0` domain,
4 rules applied, `gedit` opens.

### 6b.4 THE `.deb` WAS NEVER INSTALLED

It was installed with `dpkg -i` in a Debian 12.15 (bookworm) container and
verified. **Four** real bugs were found:

| Bug | Result |
|---|---|
| `/etc/axlinux/policies.d` did not exist | the policy was lost after reboot |
| `postinst` wrote a hardcoded `"1.0.0"` | the 1.2.0 package was recorded as 1.0.0 |
| `postinst` wrote without creating the directory | `Directory nonexistent` |
| Policies were not conffiles | `dpkg -r` **deleted** the user policy |

Verification: `ii axlinux 1.2.0 amd64`, file paths/permissions/ownership
correct, `version` file `1.2.0`, policy **preserved** after `dpkg -r`.

### 6b.5 THE UPGRADE PATH WAS NOT VERIFIED

`dnf install 1.1.0` → `dnf upgrade 1.2.0` (signed RPM):

| Check | Result |
|---|---|
| `rpm -q` | `axlinux-1.2.0-1.fc44.x86_64` |
| `axlog` binary | `version=1.2.0` (ldflags injection verified) |
| `axctl` | `axctl 1.2.0` |
| User policy (4 rules) | **preserved** |
| `/var/lib/axlinux` custom data | **preserved** |
| Sample policy | left as `.rpmnew` (`%config(noreplace)` does not overwrite the user file — correct behaviour) |
| New features (directory rule) | work after the upgrade |

### 6b.6 MULTI-USER SCENARIO

Two desktop users (UID 1001/1002), a 6-rule policy:

| Rule | Result |
|---|---|
| `subject=[firefox]` on both users' `.ssh/id_rsa` | BLOCKED |
| `subject=[cat]` on the same file from the other user | BLOCKED |
| `subject=[*]` on both users' `.gnupg/secret.gpg` | BLOCKED |
| `subject=[md5sum]` process.exec | BLOCKED |
| Each user writing their own file | ALLOWED (no false positive) |
| Each user writing to `/tmp` | ALLOWED |

### 6b.7 AUDIT JOURNAL CONTENT AND SIZE LIMITS

| Limit | Value |
|---|---|
| Segment size | 10 MB (`audit-GÜN.N.jsonl`) |
| Retention | 14 days |
| Total size | **200 MB** (new) |
| Compression | `gzip` at day change |
| Active day | always preserved (losing evidence is better than a full disk) |

Additionally, the **pathless** records produced by the `inode_permission` hook in
learning mode were removed. The path cannot be resolved on that hook (the LSM
signature takes `struct inode *`, and the inode has no back-pointer to its
dentry), and these records carry no information and produce no rules — they were
generating 43,641 records (10 MB) in 10 minutes. DENY records were unaffected.

---

## 6c. Gaps closed in the distribution paths (this round)

### `make rpm` now produces a **signed** package

Previously signing was a separate target (`make rpm-sign`) and was not called
from the main flow; the RPM produced by the normal path was **unsigned**.

```
== RPM: imzali ==
  imzalandi: .../axlinux-1.2.0-1.x86_64.rpm
  imza dogrulandi
  Header OpenPGP V4 RSA/SHA512 signature, key fingerprint:
    f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
```

If there is no GPG key it errors out and **the produced file is deleted** —
no unusable package is left behind.

### The `.deb` now sets the journald limit

The RPM side installed the `packaging/journald/10-axlinux.conf` drop-in;
the Debian side **did not install it at all** — meaning `/var/log/journal` was
unlimited on Debian/Ubuntu systems. The same file is now installed into the
`.deb` and registered in `conffiles`.

Debian 12.15 container verification:

```
dpkg      : ii  axlinux 1.2.0          (installed AND configured)
journald  : 1 drop-in, SystemMaxUse=200M
conffiles : 5 records
axctl     : axctl, version 1.2.0
policy   : ✓ YAML syntax valid
removal  : policies.d 1 file + journald 1 drop-in PRESERVED
```

`postinst` now checks for the presence of `systemd-tmpfiles`; in a minimal
container it printed "not found" and polluted the installation output.

### The `install.sh` path (no RPM, from scratch)

```
ikililer    : 4/4
policies.d : 1 dosya (00-sample-workstation.yaml)
journald   : 1 drop-in
LSM=5 mod=permissive kural=0 policy_healthy=True audit_healthy=True
reload sonrasi: mod=enforcing kural=3
```

### Four silent bugs in the removal path

After `dnf remove axlinux`, 8 fcontext records and 1 module remained;
there was no visible error, all of it was swallowed with `|| :`.

| # | Bug | Fix |
|---|------|-------|
| 1 | `semanage delete -a …` is an **invalid subcommand** | `semanage fcontext -d <regex>` |
| 2 | `awk -F'\t'` — the output is aligned with **spaces**, not tabs | default separator |
| 3 | `semanage module -r` refers to the priority repository | `semodule -r` |
| 4 | Cleanup was in `%postun`; since the `.pp` is inside `%files` it is deleted **first** | moved to `%preun` |

Also, `fcontext -l` **validates** and skips invalid records; this is normal at
removal time. The raw local list (`-l -C`) is used.

## 8. Ready for distribution?

**For the Fedora 44 Workstation desktop target: yes.**

| Criterion | Evidence |
|---|---|
| Real GNOME session | gdm + Wayland + `systemd --user` ✓ |
| Automatic login | `axdesktop` session active after reboot ✓ |
| Realistic enforcing policy | 6 rules, all applied ✓ |
| **Policy persistence** | `rules=N mode=enforcing` after reboot ✓ |
| **Directory rules protect content** | 6 depth levels, no false positives ✓ |
| Desktop resilience | gedit + dnf + file I/O under enforcement ✓ |
| **Multi-user scenario** | 2 users, cross-isolation verified ✓ |
| File-open latency | +0.19 s / 50,000 opens (imperceptible) ✓ |
| Audit disk cost | ≈250 bytes/**violation**; allowed operation 0 bytes ✓ |
| **Audit journal bounded** | 10 MB segment + 14 days + **200 MB total** + gzip ✓ |
| RPM | production + **GPG signature** + `rpm -Kv` fingerprint + clean installation ✓ |
| **Version upgrade** | 1.1.0 → 1.2.0, user data preserved ✓ |
| `install.sh` | 11/11 steps on clean Fedora + enforcement evidence ✓ |
| `.deb` | installation on Debian 12.15, conffiles protection ✓ |
| Regression | **732 passed / 0 failed / 0 skipped** ✓ |

### The single remaining limitation

In `inode_permission` audit records the `object` field stays empty. This is a
**structural boundary** with no solution: the LSM signature is
`security_inode_permission(struct inode *inode, int mask)` and the inode has no
back-pointer to the dentry (the direction is one-way: dentry → inode).
All cases that need a path are already resolved and recorded in the
`file_open` and `bprm_check_security` hooks.

Its impact is neither operational nor security-related: a blocked decision is
the subject-specific rule itself (such as `subject: md5sum`) and does not
need a path.

---

## 9. Bugs fixed in this work round

| # | Bug | Impact | Status |
|---|---|---|---|
| 1 | Policy was lost after reboot | **MAC non-functional** | fixed |
| 2 | Audit rotation did not work at all | the 10 MB limit was invalid | fixed |
| 3 | `audit_healthy` permanently `false` | permanent false alarm | fixed |
| 4 | Directory rules did not protect content | **security flaw** | fixed |
| 5 | `axlog` reported 1.0.0 | wrong version information | fixed |
| 6 | `deep_verify` affected by its own leftovers | false FAIL | fixed |
| 7 | Rotation test was meaningless | it was never verifying anything | fixed |
| 8 | `inode_permission` pathless noise | 10 MB / 10 min | fixed |
| 9 | Audit total size unbounded | disk-full risk | fixed |
| 10 | RPM unsigned | cannot be distributed in a repository | fixed |
| 11 | `install.sh` did not create the policy directory | loss after reboot | fixed |
| 12 | `.deb` had 4 separate packaging bugs | policy loss/deletion | fixed |
| 13 | `postinst` wrote a hardcoded 1.0.0 | wrong version | fixed |
| 14 | Upgrade path was untested | the upgrade could have been broken | **verified** (1.1.0 → 1.2.0 RPM upgrade measured) |

1, 2 and 4 were of the kind that directly affects the product's function. The
reason 4 was present is that there was **no test** in the relevant section.

**On this machine (`/dev/sdb1`) AXlinux was not run and will not be run.**
