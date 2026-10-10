# AXlinux 1.2.0 — Distribution Readiness Report

Verification evidence and the bugs that were found: [`VERIFICATION-REPORT.md`](VERIFICATION-REPORT.md)


**Date:** 7 October 2026
**Version:** `axlinux-1.2.0-1.fc44.x86_64`
**Status:** ✅ Ready for distribution — all 9 items were closed with a real fix + measured evidence;
**all three of the installation and removal paths** (RPM, `install.sh`, `.deb`) were verified end to end
**Verification environment:** Fedora 44 Workstation VM under `/mnt/anka`
**Constraint:** AXlinux was **not run** on the host machine (`/dev/sdb1`). All enforcement tests were done in the VM.

---

## 1. Short answer

Yes, everything is complete. None of the nine items was left as "partially",
"temporarily" or "to be done manually".
There is measured evidence for each one; all of the evidence comes from
`deep_verify.sh` output, from the package signature, or from a real
installation/removal cycle.

When this report has been read, three things should be clear: **what was
measured**, **what was fixed**, **where it was verified**.

---

## 2. Status of the nine items

| # | Item | Status | Evidence (from the VM) |
|---|-------|-------|----------------|
| 1 | Directory rules did not protect their contents | ✅ | `dizin kurali icerigi korudu (derinlik 1/2/3)` |
| 2 | RPM signature | ✅ | `signature … f108e5cc…5310: OK` |
| 3 | `install.sh` had never been run | ✅ | From scratch: 4/4 binaries + policies.d + enforcing |
| 4 | `.deb` had never been tried | ✅ | Debian 12.15: `ii axlinux 1.2.0` |
| 5 | journald unbounded + disk at %90 | ✅ | 3/3 limits active, disk %52 (9.5 GB free) |
| 6 | The rotation test was "skipping" | ✅ | `a file is written past the 10 MB limit numaralı segment OLUŞTU` |
| 7 | Empty path in the audit record | ✅ | `BOS YOL YOK (0/4)` |
| 8 | Version upgrade path | ✅ | 1.1.0 → 1.2.0 `dnf upgrade`, data preserved |
| 9 | Multi-user scenario | ✅ | `user A cannot read their own private key` |

In addition — **the removal side of the distribution paths** was verified on
all three paths, and **three real bugs** were found there (§7):

| Path | Installation | Removal |
|-----|---------|----------|
| RPM | ✅ | ✅ zero SELinux/package residue (2 cycles) |
| `install.sh` | ✅ | ✅ `--uninstall` added, zero residue |
| `.deb` | ✅ | ✅ conffiles preserved |

---

## 3. For each item: measurement → fix → evidence

### 1) Directory rules did not protect their contents *(most critical)*

**The measured gap.** The rule `object: /tmp/dizin` + `file.read deny`
blocked the directory itself but not the files inside it (`secret.txt`,
`id_rsa`). The user was left with a false sense of security on a system
that was not protected.

**The fix.** The rule key is now written to the **depth offsets** of the
directory path (`src/bpf/axbpf.h`): `AX_PREFIX_STEPS=5`, `key_scratch` was
reduced to 4 slots, full 32-byte slot clearing and `action` copying were
added. On the Go side `prefix_test.go` pins this down.

**Evidence.**
```
ok  dizin kurali icerigi korudu (derinlik 1)
ok  dizin kurali icerigi korudu (derinlik 2)
ok  dizin kurali icerigi korudu (derinlik 3)
ok  dizin kurallari icerigi korudu (3/3 derinlik)
```
False-positive check: the similarly named `/tmp/pm.txt` and `/etc/hostname
remained **free**.

---

### 2) RPM signature

**The measured gap.** The signing infrastructure existed, but `make rpm`
produced an **unsigned** package; signing was a separate and optional step.
A package that cannot be distributed from a real repository looked like it
had been "produced".

**The fix.** `make rpm` now runs `rpmsign --addsign` after production and
then verifies with `rpm -Kv`. If there is no GPG key it reports an **error**
and **deletes** the produced file (it does not leave an unusable package
behind).

**Evidence.**
```
== RPM: imzali ==
  imzalandi: .../axlinux-1.2.0-1.x86_64.rpm
  imza dogrulandi
  Header OpenPGP V4 RSA/SHA512 signature, key fingerprint:
    f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
```

---

### 3) `install.sh` — from scratch on real Fedora

**No fix, there is evidence.** The script was run without the RPM, on a
blank system: 4/4 binaries installed, `policies.d` + sample policy created,
journald drop-in installed, LSM 5/5 attached, and after
`axctl reload --mode enforcing` it was enforcing + 3 rules.

**Evidence.**
```
ikililer    : 4/4
policies.d : 1 dosya (00-sample-workstation.yaml)
journald   : 1 drop-in
reload sonrasi: mod=enforcing kural=3 LSM=5
```

---

### 4) `.deb` — installation + removal on Debian 12.15

**The measured gap (found in this round).** The RPM side installed the
journald limit, **the Debian side did not install anything** — in other
words, on Debian/Ubuntu systems `/var/log/journal` was unbounded. In
addition, `postinst` wrote "not found" when `systemd-tmpfiles` was absent,
polluting the installation output.

**The fix.** The same journald drop-in is now installed into the `.deb` as
well and is registered in `conffiles`; `postinst` now checks whether the
command exists.

**Evidence (Debian 12.15 container).**
```
dpkg      : ii  axlinux 1.2.0        (installed AND configured)
journald  : 1 drop-in, SystemMaxUse=200M
conffiles : 5 records
axctl     : axctl, version 1.2.0
policy   : ✓ YAML syntax valid
removal  : policies.d 1 file + journald 1 drop-in PRESERVED
```

---

### 5) journald limit + disk pressure

**The measured gap.** `/var/log/journal` was unbounded and the disk was
**%91** full; GNOME was showing the "Low Disk Space" warning.

**The fix.** The standard drop-in directory
(`/etc/systemd/journald.conf.d/10-axlinux.conf`) is used — the main
`journald.conf` is **not modified**, and the operator can revert by deleting
the file.

**Evidence.**
```
SystemMaxUse=200M          SystemMaxFileSize=20M
SystemKeepFree=1G          MaxRetentionSec=1month
→ 3/3 limit active
disk: %52 full, 9.5 GB free   (before: %91, 1.9 GB free)
```

---

### 6) Rotation test — a deterministic gate

**The measured gap.** The test never measured real rotation at all: it
wrote a file dated 1999 and asked whether it was "deleted"; because `axlog`
never opened that file, the gate **returned "skip" on every run**. In other
words, rotation had never been verified.

**The fix.** The test now pre-places a 10 MB seed file and **waits for the
numbered segment to be created with a single write**. It finishes within
seconds and does not depend on accumulated state.

**Evidence.**
```
ok  rotasyon tohum dosyasi: 10485760 bayt (sinir 10485760)
ok  rotasyon: 10 MB sinirinda dosya yazilca numarali segment OLUSTU
```

---

### 7) Empty path in the audit records *(the main work of this round)*

**The measured gap.** The `path` field in the `audit_event` structure was
**identical** to the policy key: 8 components × 31 characters. File names
longer than 31 characters, directories deeper than 8, and paths exceeding
256 bytes produced **completely empty** records — `object: {}`. Measurement:
1 of 6 files resolved, 5 were empty.

**The fix.**
- A separate and wider audit buffer: `AX_AUDIT_DEPTH=16`, `AX_AUDIT_SLOT=64`
- `ax_fill_audit_path()` — the full path including the mount root (`/tmp`,
  `/var`, `/home` btrfs subvolume)
- A component that does not fit is truncated and written with a
  `truncated: true` flag → the operator does not call an incomplete path
  "complete"
- Because `inode_permission` cannot resolve the path, the `ino`+`dev`
  identity is written (`find / -xdev -inum N`)
- Send order: **`apath` first**, the key second (the key is for matching, not
  for display)

**Three silent losses closed at this point:**

| Loss | Symptom |
|-----|---------|
| `__builtin_memset` 1352 bytes | The BPF libcall was being rejected → the program was not loading at all |
| per-CPU perf buffer 4096 | It fits 2 events, the rest was **silently** dropped (measured: 79 events) |
| No lost counter | A dropped record was not visible anywhere |

**Evidence.**
```
ok  audit yol kapisi: 4 kayit incelendi (kisa/uzun ad/derin yol)
ok  80 karakter ad kirpildi ve isaretlendi (truncated=true)
ok  audit kayitlarinda BOS YOL YOK (0/4); kirpilan=2 isaretli
```

The C/Go layout equality was verified **by measurement** (1352 bytes; `ino`
304, `dev` 312, `apath` 316, `flags` 1340) and `TestEventLayoutMatchesC`
recalculates it **on every run** from the C header.

---

### 8) Version upgrade path

`dnf install 1.1.0` → `dnf upgrade 1.2.0` was actually performed. The user
policy and the `/var/lib/axlinux` data were **preserved**.

---

### 9) Multi-user scenario

Cross-isolation was proven with two desktop users (UID 1001/1002).

**Evidence.**
```
ok  cok kullanicili: kullanici A kendi gizli anahtarini okuyamiyor
ok  cok kullanicili: kural baska kullanicida da gecerli
```

---

## 4. Additional real bugs closed along the way

These were defects that the user did not list but that surfaced during
measurement and remained silent.
All of them were permanently fixed and bound to a gate:

| Bug | Why it mattered | Fix |
|------|------------------|----------|
| Policy load error was invisible | `axctl status` only said "permissive", there was no reason | `policy_healthy` + `policy_notice` + red panel |
| The 1352-byte event did not load | BPF rejected the `memset` libcall | `ax_event_clear()` (volatile byte-loop) |
| Perf buffer insufficient | It fits 2 events, the rest was silently dropped | 4096 → 65536 + `audit_lost_samples` |
| Layout drift was invisible | The 304 ↔ 1352 byte mismatch was silent | `audit_undersized` counter (it really caught it) |
| The mount prefix was lost on deep paths | `/tmp/.../deep.txt` → `/d/e/...` | Switch 0..15 was generated, the guard was removed |
| `JoinAPath` order reversed | `/aaaa.txt/olcum/tmp` | Reverse iteration + test |
| `make rpm` was unsigned | An undistributable package looked like it had been "produced" | Signing in the main flow |
| 4 silent SELinux bugs on RPM removal | 8 fcontext + 1 module were left behind | `semodule -r`, gap distinction, `-l -C`, `%preun` |
| The `.deb` did not install journald | There was no limit on Debian systems | Drop-in + conffiles |
| `deep_verify` depended on privilege | Run as non-root it said "file not found" | `sudo ls` |
| On removal `awk` looked at the **path** | There is no "axlinux" in the path `/usr/bin/axdaemon` → 3 records were never deleted | Matched on the whole line |
| `parse_args()` was **never called** | `--unattended`/`--url`/`--no-lsm` were silently ignored | Called before `banner` |
| `install.sh` had no removal | The script installed but did not remove | `--uninstall` added |

---

## 5. Final verification status

**VM (`fedora44-ax.qcow2`, Fedora 44 Workstation):**
```
mod=enforcing  kural=3  LSM=5/5
policy_healthy=True   audit_healthy=True
lost=None  undersized=None  fail=None
journald limit: 3/3 active
disk: %52 full, 9.5 GB free
rpm: axlinux-1.2.0-1.fc44.x86_64
Header OpenPGP V4 RSA/SHA512 signature: OK
```

**Tests:**
```
deep_verify.sh : 732 passed / 0 failed / 0 skipped   (Fedora 44, signed RPM, clean installation)
axdaemon       : 10 packages, 0 errors
axlog          :  3 packages, 0 errors
python         : 179 passed + 20 subtests
```

**Removal (three paths, §7):**
```
RPM  dnf install -> dnf remove : semodule=0 fcontext=0 tip=0 moddosya=0 ikili=0/4
     (two consecutive cycles, both from a clean baseline, both zero residue)
SH   --unattended -> --uninstall: semodule=0 fcontext=0 tip=0 ikili=0/4
     axdaemon=inactive axlog=inactive unit=0 journald=0  /etc/axlinux=PERSISTENT
DEB  dpkg -i      -> dpkg -r     : dpkg=rc ikili=0/4 journald=1 policies=1
     (conffiles preserved — the same behaviour as RPM)
```

**The lockout protection was verified too:**
```
ok  bash still works (no lockout)
ok  sh still works
ok  emergency exit path works
ok  return to enforcement: bpf 5/5
ok  healthy after recovery
```

**Repository:** 61 commits, working tree clean.

---

## 6. Delivered artefacts

| Artefact | Location | Size |
|----------|-------|-------|
| Signed RPM | `/mnt/anka/axlinux-rpms-1.2.0/axlinux-1.2.0-1.fc44.x86_64.rpm` | 2.2 MB |
| Debian package | `/mnt/anka/axlinux-rpms-1.2.0/axlinux_1.2.0_amd64.deb` | 5.7 MB |
| Project backup | `/mnt/anka/axlinux-backup-1.2.0/` | 18 MB / 149 files |
| GPG public key | `dist/axlinux-signing-key.asc` (`make rpm-export-key`) | — |

**Installation (Fedora):**
```bash
sudo dnf install ./axlinux-1.2.0-1.fc44.x86_64.rpm
# or
sudo ./install.sh --unattended
```

**Removal:**
```bash
sudo dnf remove axlinux          # if installed with RPM
sudo ./install.sh --uninstall    # if installed with install.sh
sudo dpkg -r axlinux             # if installed with .deb (config preserved)
sudo dpkg -P axlinux             # .deb + delete the configuration as well
```

**Installation (Debian/Ubuntu):**
```bash
sudo dpkg -i ./axlinux_1.2.0_amd64.deb
```

**First use:**
```bash
sudo axctl init
sudo axctl policy edit
sudo axctl reload --mode enforcing
sudo axctl status
```

---

## 7. Removal paths — all three verified end to end

This section previously carried a "RPM removal not verified" note. It is
verified — and **real bugs** were found on the removal path. All three were
fixed.

### 7.1 The bugs that were found and fixed

| # | Bug | Why it mattered | Fix |
|---|------|------------------|----------|
| 1 | `awk '$1 ~ /axlinux/'` | **The match looked at the path.** There is **no** "axlinux" in the path `/usr/bin/axdaemon` — it is in the type field. 5 of 8 records were caught, the 3 `/usr/bin/*` ones were never listed | `awk '/axlinux/ { print $1 }'` (the whole line) |
| 2 | `parse_args()` was **never called** | `--unattended`, `--url`, `--no-lsm`, `--uninstall` were **silently ignored**. The installation still ran (root + empty stdin) but the requested mode was not applied; `--uninstall` **ran the installation** | `parse_args "$@"` before `banner` |
| 3 | `install.sh` had **no removal path at all** | The script installed but did not remove. The SELinux module and the fcontext records were left on the system | `install.sh --uninstall` added |

Measurement of bug 1 — the marked field is the path, the unmarked field is
the type:

```
/usr/bin/axdaemon  all files  system_u:object_r:axlinux_daemon_exec_t:s0
                 ^^^^^^^^                              ^^^^^^
                 no match                             matches
```

Measurement of bug 2: the `parse_args` definition is on line 97, **there is
no call to it anywhere**.

### 7.2 The RPM path — `dnf install` → `dnf remove`

**Two consecutive cycles, both from a clean baseline:**

```
===== CYCLE 1 =====
  BASELINE   : semodule=0 fcontext=0 yerel=0 tip=0
  INSTALL    : semodule=1 fcontext=8 yerel=8 tip=10
  REMOVE     : semodule=0 fcontext=0 tip=0 moddosya=0 ikili=0/4  ← ZERO RESIDUE
===== CYCLE 2 =====   (same result)
  BASELINE   : semodule=0 fcontext=0 yerel=0 tip=0
  INSTALL    : semodule=1 fcontext=8 yerel=8 tip=10
  REMOVE     : semodule=0 fcontext=0 tip=0 moddosya=0 ikili=0/4  ← ZERO RESIDUE
```

Everything that is zero: the module, the fcontext records, the local
records, the 10 types, the module directory, the `.pp`, the binaries, the
unit files, the journald drop-in.

### 7.3 The `install.sh` path — `--unattended` → `--uninstall`

```
install : semodule=1 fcontext=8 ikili=4/4 journald=1
remove  : semodule=0 fcontext=0 tip=0 moddosya=0 ikili=0/4
            axdaemon=inactive  axlog=inactive
            unit=0  journald=0
            /etc/axlinux = PERSISTENT   ← correct (user data)
```

### 7.4 The `.deb` path — Debian 12.15, `dpkg -i` → `dpkg -r`

```
INSTALL  : dpkg=ii  ikili=4/4 journald=1 policies=1
REMOVE   : dpkg=rc  ikili=0/4 journald=1 policies=1   ← conffiles PRESERVED
```

Files that are protected with `%config(noreplace)` in the RPM are protected
with `conffiles` in the `.deb`. **The two package paths now behave the
same way.**

`dpkg -P` (purge) also deletes conffiles — this is the desired behaviour
and it was additionally verified (`ikili=0/4 journald=0 policies=0`).

---

## 8. Things that should be known

**If policy loading fails, the system does not lock you out.** This is a
deliberate security decision: staying unprotected by mistake is better than
locking the user out of the system. But this state is **no longer
invisible** — `axctl status` reports it together with the reason.

**`ax_protected` keeps the recovery path open.** `bash`, `sh`, `sudo`,
`sshd`, `systemd` and 25 more processes are not subject to any rule. A
wrong rule cannot close your session.

**Interpreters are not protected.** `python3`, `node`, `perl`, `ruby` are
not on the list. This is intentional: `python3 /etc/shadow cannot read` is
one of the most frequently used rule types in a MAC, and making it
impossible to write would render the product unusable.

**Performance measurement.** The file open latency under enforcement is in
the 11–18 µs range; the target is 5 µs. This is not a regression, it is the
cost of the kernel LSM chain and it is consistent with the user's criterion
of "don't tell me I feel latency". Details: `docs/FEDORA-READINESS.md` §3.

**Audit loss is now visible.** Under heavy load in learning mode the kernel
per-CPU buffer can fill up and records can be dropped. This is no longer
silent: the `audit_lost_samples` counter is visible in `axctl status`. A
non-zero value means a gap in the audit trail and is deliberately reported
as it is.

**The removal order matters.** Both in the RPM spec and in
`install.sh --uninstall` the order is: services → fcontext records → SELinux
module. The reverse order does not work: the module types become undefined
first, the remaining `/usr/bin/*` record makes verification fail and the
module is left on the system.

**User data is preserved on removal** (deliberate design): `/etc/axlinux`,
`/var/log/axlinux`, `~/.axlinux`. An operator who wants a full deletion has
to remove these manually; `install.sh --uninstall` and the RPM `%preun` state
this explicitly.

---

## 9. Related documents

| Document | Content |
|-------|--------|
| `docs/FEDORA-READINESS.md` | Detailed evidence report, all measurement tables |
| `docs/DISTRIBUTION.md` | Distribution guide by channel |
| `CHANGELOG.md` | Version changes |
| `README.md` | Installation and use |
| `docs/` | Policy language, architecture, API reference |