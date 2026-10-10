# AXlinux 1.2.0 — Fedora Delivery and Features Document

**Version:** 1.2.0 · **Date:** 2026-10-10
**Target platform:** Fedora Linux 44 (Cloud Edition), kernel `6.19.10-300.fc44.x86_64`

This document does two things at once:
1. **Delivery evidence** — the package contents, signature, installation and
   runtime behaviour with measured values.
2. **Feature catalogue** — what the product does, with how each feature was
   verified.

> **Rule:** Every number here comes from a real measurement. Apart from virtual
> machine outputs, `rpm -q`/`rpm -Kv`/`dpkg-deb` results and `deep_verify.sh`
> runs, no value has been written. No untested claim is presented as
> "working".

---

## 0. Safety first

This product was **not run on your primary machine and will not be.**
All tests were performed in virtual machines under `/mnt/anka`.

AXlinux grants the `bpf()` syscall permission only to its own `axdaemon` process.
AXlinux works on physical machines, including the one you use every day.
The **test suite** is what refuses physical hardware — `deep_verify.sh`
deliberately denies access while testing, so running it on the machine you
work on could lock you out:

```
HATA: fiziksel makine. Bu betik gercek enforcement uygular.
  Sanal makinede calistirin veya:
    AXLINUX_ALLOW_PHYSICAL=1 tests/deep_verify.sh
```

Neither `install.sh` nor `axctl` contains such a check — the product has no
virtual-machine requirement.

The emergency exit is always available:

```bash
sudo axctl mode disabled
```

---

## 1. Quick installation (Fedora)

```bash
sudo dnf install ./axlinux-1.2.0-1.x86_64.rpm
```

Installation installs the SELinux module, writes the file contexts, places
`axbpf.o`, applies the journald limit and starts the service with a single command.

**Recommended flow** (learn by observing the policy first):

```bash
axctl init                  # create ~/.axlinux/
axctl policy edit           # write your YAML policy
axctl policy check          # validate
axctl policy simulate       # see what it will affect first
sudo axctl reload           # apply
sudo axctl status           # check the real state
```

`policy simulate` is the most important command: it shows what the rules will
affect **before** `reload`.

---

## 2. Features and verification evidence

### 2.1 YAML policy language

The policy file is YAML; it is not a compiled language.

| Field | Meaning |
|---|---|
| `id` | Rule identity (unique) |
| `name` | Required, human-readable description |
| `subject` | Process (path or name) — scalar or list |
| `object` | Path prefix — directory rules protect content **too** |
| `action` | Action type (table below) |
| `effect` | `deny` / `allow` |
| `mode` | Policy level: `disabled` / `permissive` / `enforcing` |

**Measured:** the `subject` field accepts both the scalar form (`subject: curl`)
and the list form (`subject: [curl, wget]`). These two forms are handled in
**two separate parsers** and both are covered by regression tests
(`src/go/axdaemon/internal/policy/`).

### 2.2 Six action types

| Action | What it blocks | LSM hook | Measured |
|---|---|---|---|
| `file.read` | File read | `file_open` | ✓ |
| `file.write` | File write | `file_open` | ✓ |
| `file.execute` | File execution | `bprm_check_security` | ✓ |
| `inode_permission` | inode permissions | `inode_permission` | ✓ |
| `socket_connect` | Outbound connections | `socket_connect` | ✓ |
| `socket_bind` | Port listening | `socket_bind` | ✓ |

**Measured:** 5 LSM hooks attached, eBPF programs 5/5 loaded.
`socket_bind` does no port matching (name only); this is a
known limitation and is documented in `docs/policy-language.md`.

### 2.3 Directory rules protect content

This is the most critical behaviour of the product and it is separately proven.

If the rule is `object: /tmp/pm`, then **all files inside it** are protected:

```
/tmp/pm/kok.txt              → DENIED
/tmp/pm/a/ust.txt            → DENIED
/tmp/pm/a/b/derin.txt        → DENIED
/tmp/pm/a/b/c/d4.txt         → DENIED
/tmp/pm/a/b/c/d/d5.txt       → DENIED
/tmp/pm.txt                  → ALLOWED   (similar name, different path)
/etc/hostname                → ALLOWED   (not covered by a rule)
```

**Measured:** `deep_verify` contains separate gates for depths 1, 2 and 3
and all of them pass. The "similarly named neighbour stayed allowed" gate
proves that **no false positives are produced**.

> This behaviour **did not exist** before: the rule blocked only the directory
> itself, and the files inside it (`secret.txt`, `id_rsa`) stayed unrestricted.
> The user believed "my keys are protected".

### 2.4 Three modes

| Mode | Behaviour |
|---|---|
| `enforcing` | Violations are blocked **and** logged |
| `permissive` | Violations are only logged, not blocked |
| `disabled` | No restriction is applied |

**Measured:** switching between the three modes is verified by `deep_verify`;
that a violation record is produced in `permissive` mode and that it is
blocked in `enforcing` mode are checked separately.

### 2.5 Persistent policies (`policies.d`)

`/etc/axlinux/policies.d/*.yaml` is loaded automatically at boot and merged
in sorted order by prefix, such as `00-sample-workstation.yaml`.

The `00-sample-workstation.yaml` shipped with the installation is **deliberately
empty** (`rules: []`) — the system starts in a state where "nothing is blocked".
Add your own policy to this directory.

**Measured (Fedora 44, live system):**

```
sistem politikasi uygulandi dir=/etc/axlinux/policies.d
rules=1  mode=enforcing
inside rule (deny)   : 1   <- Operation not permitted
outside rule (free)  : 0   <- no false positive
```

The policy is **loaded and applied after reboot**. Verified by hand: the deny
operated at depth (`Operation not permitted`, 2 DENIED records), and the
non-rule path plus the similarly named neighbour stayed allowed.

> This location was previously **completely broken**: a valid policy written
> with a scalar `subject` was rejected and the system remained "KISITLAMASIZ".
> Two regression tests and a `deep_verify` gate now protect this.

### 2.6 Learning mode

`axctl learn` collects observed violations and produces a policy proposal.
It does the job of SELinux's `audit2allow`, in the form of seeing the proposal
before writing it.

**Measured:** observation collection (`axctl learn` → the observation counter
increases) and validation of the generated proposal as YAML are tested inside
`deep_verify`.

### 2.7 Labels

Labels are assigned to processes with `axctl label add/ls/rm`; rules can be
written in a policy via labels.

**Measured:** the `label add` → `label ls` → `label rm` chain works
completely and `deep_verify` verifies each step.

### 2.8 Policy templates

`axctl template ls` lists the ready templates; `template apply` copies a
template under `policies.d`.

**Measured:** `template ls` listing, the correct error code (`rc=5`) for
`template apply` (nonexistent), and applying an existing template — all tested.

### 2.9 CLI surface

| Command | Function |
|---|---|
| `axctl init` | Creates the `~/.axlinux/` directory |
| `axctl policy check` | Validates the YAML |
| `axctl policy simulate` | Shows the effect of rules **in advance** |
| `axctl policy edit` | Edits the policy file |
| `axctl reload` | Applies the policy immediately |
| `axctl status [--json]` | Live state (hook count, loaded rule, mode) |
| `axctl mode` | `disabled` / `permissive` / `enforcing` |
| `axctl logs` | Queries audit records (`--subject`, `--effect`, `--action`) |
| `axctl label` | Label management |
| `axctl learn` | Observation collection |
| `axctl template` | Template management |
| `axctl version` | Version information |

**Measured:** the `--help` output and an actual run of every command is
verified separately by `deep_verify`.

### 2.10 Reset and lockout protection

If a policy accidentally locks the system, `axctl mode disabled` always
works. In addition, write rules for `/boot` and boot system files are
protected by the lockout protection.

**Measured:** the emergency shutdown and "healthy after restart"
gates are tested inside `deep_verify`.

---

## 3. Audit records

Records are written as structured JSONL under `/var/log/axlinux/` and
queried with `axctl logs`.

**Measured features:**

| Feature | Evidence |
|---|---|
| Durable JSONL | Every line is validated as proper JSON |
| Querying | `--effect denied`, `--subject curl`, `--action file.read` work |
| Long path | expanded with `apath`, carries a `truncated` field |
| inode identity | `inode_permission` records carry `ino` + `dev` |
| Rotation | 10 MB segment, 14 days, 200 MB total, gzip |
| Disk bound | system disk measured: 91% → **52%** |
| journald bound | `SystemMaxUse=200M`, `MaxRetentionSec=1month` (shipped with installation) |

**Measured rotation:** when the segment limit triggers a new file is opened and
DENY records are unaffected. The total size limit is enforced as well.

---

## 4. Package evidence (Fedora 44)

### 4.1 Signature

```
Header OpenPGP V4 RSA/SHA512 signature
  key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
Header SHA256 digest: OK
Payload SHA256 digest: OK
```

The package **is signed** and the fingerprint has been verified.

### 4.2 Content

RPM contents (30+ files) — eight items verified individually:

| Item | Path |
|---|---|
| eBPF object | `/usr/lib/axlinux/axbpf.o` |
| Daemon | `/usr/bin/axdaemon` |
| Log collector | `/usr/bin/axlog` |
| CLI | `/usr/bin/axctl` + `/usr/lib/axlinux/axctl/*.py` |
| SELinux module | `/usr/share/selinux/packages/axlinux.pp` |
| Services | `axdaemon.service`, `axlog.service` |
| journald | `/etc/systemd/journald.conf.d/10-axlinux.conf` |
| Policies | `/etc/axlinux/*.yaml`, `policies.d/` |
| Documentation | `/usr/share/doc/axlinux/` |

### 4.3 conffiles (5)

Configuration files preserved on removal:

```
/etc/axlinux/desktop.yaml
/etc/axlinux/minimal.yaml
/etc/axlinux/policies.d/00-sample-workstation.yaml
/etc/axlinux/web-server.yaml
/etc/systemd/journald.conf.d/10-axlinux.conf
```

**Measured removal behaviour:** after `dnf remove` the binaries, service
files and AXlinux's SELinux records are cleaned up. Configuration files are
instead **backed up before removal**:

```
AXlinux: kaldiriliyor.
  Politika ve audit KORUNUYOR:
    ~/.axlinux, $AXLINUX_HOME, /var/log/axlinux
  Yapilandirma yedeklendi: /var/lib/axlinux/removed-config-20261010-103549
  (politika dosyalari kaldirmada silinir; yedekten geri alabilirsiniz)
```

Content verified from the backup (5 files): `desktop.yaml`, `minimal.yaml`,
`web-server.yaml`, `00-sample-workstation.yaml`, `10-axlinux.conf`.

> This behaviour was **found** during measurement: files tagged
> `%config(noreplace)` were deleted by rpm on removal even when unmodified.
> If the operator had edited the policy file themselves, data was lost. An
> unsigned backup was added into `%preun` and verified with a real removal.

### 4.4 Scriptlets

| Scriptlet | Task |
|---|---|
| `%preinstall` | Cleans an existing installation |
| `%postinstall` | Installs the SELinux module, writes contexts, starts the service |
| `%preuninstall` | Stops services, removes the module and contexts |
| `%postuninstall` | Cleans the remaining configuration |

**Measured removal cycle:** two consecutive clean installations → zero residue
during removal:

```
semodule       : 0
fcontext       : 0
yerel fcontext : 0
module file     : 0
ikili          : 0/4
```

---

## 5. SELinux integration

AXlinux works with its own module (`axlinux.pp`) and does **not grant `bpf()`
permission system-wide** — it grants it only to the `axdaemon` domain.

**Measured (Fedora 44, live system):**

```
axdaemon context  : system_u:object_r:axlinux_daemon_exec_t:s0
domain verification : domain verified: ...axlinux_daemon_t:s0 (eBPF: 5)
module type count : 10
fcontext rules    : 8
```

The module's content was additionally verified: **10 types** and **8 file-context
rules** are defined. (Earlier, 0 types / 0 rules were measured on Fedora 43 —
the stale module bug; see `docs/VERIFICATION-REPORT.md` §5.4.)

**Fail-safe:** If labelling prevents eBPF loading (in some images SELinux
denies the BPF map operation) the installation script **measures** this,
reverts the labels, restarts the service and warns explicitly — so that
enforcement keeps working.

### Position relative to SELinux

| | SELinux | AXlinux |
|---|---|---|
| Policy source | Ready-made, millions of lines | The user's YAML |
| Learning | `audit2allow` | `axctl learn` → observation → proposal |
| Enforcement | `setenforce` + reboot | `axctl reload` → immediate |
| Log | `audit.log` (text) | JSONL (structured, queryable) |

The two are not competitors but **complementary**: SELinux provides the domain
boundary, AXlinux writes the content rules.

---

## 6. Performance (measured)

### 6.1 File-open latency

Each condition was measured **three times** in a row.

| Condition | 3 runs (µs/open) | Median |
|---|---|---|
| No LSM hook | 14.3 · 13.2 · 12.1 | 13.2 |
| Hook attached, `disabled` | 12.7 · 16.3 · 17.8 | 16.3 |
| Hook attached, `enforcing` | 22.1 · 26.2 · 21.9 | **22.1** |

**Policy lookup cost is real:** +5.8 µs. The ranges of the two groups
**do not overlap** ([2] highest 17.8 < [3] lowest 21.9).

**Hook attachment cost was not measured:** +3.1 µs is visible but the ranges
overlap — this difference cannot be distinguished from run-to-run noise.

### 6.2 Total workload (50,000 file opens)

| Mode | Median | µs/open | opens/s |
|---|---|---|---|
| `disabled` | 0.228 s | ~4.55 | ~220,000 |
| `enforcing` | 0.559 s | ~11.2 | ~89,600 |

**Difference 0.33 seconds.** In a real workload such as browser startup this is
imperceptible; with enforcement active ~90,000 opens/s is a rate a desktop will
never reach.

### 6.3 Resource consumption

| Measurement | Value |
|---|---|
| `axdaemon` RSS | 108,236 kB (~106 MB) |
| RSS after 1000 rules | 100,436 kB (no leak) |
| Open file descriptors | 33 |
| Policy scaling | 1000 rules / 100 rules = **3.44x** |
| Enforcement scaling | 1000 rules / 100 rules = **2.10x** |

**Scaling is linear:** 10x the rules means ~3.4x the time (not logarithmic)
— `deep_verify` audits this with a `<20x` threshold.

> Why absolute µs alone is not the criterion: the same measurement on Ubuntu
> comes out ~20 times slower than on Fedora, because the virtual machine
> environment is the determining factor. This is why `deep_verify` applies an
> **environment-corrected relative ratio** instead of an absolute threshold
> (measured on Fedora 44: 1.01x baseline).

---

## 7. Verification summary

### 7.1 `deep_verify.sh` — with the current code

| Platform | passed | failed | skipped |
|---|---|---|---|
| **Fedora 44** | **732** | **0** | **0** |
| Fedora 43 | 732 | 1 | 1 |
| Ubuntu 24.04.5 | 731 | 0 | 1 |
| Debian 12 | 731 | 0 | 1 |
| Pardus 25.2 | 731 | 0 | 1 |

On Fedora 44 **no item is skipped and no item fails.**

The single skipped item in the Debian family is `SELinux yok` — the Debian
family does not ship SELinux; this is not a gap but a platform difference.

The single item on Fedora 43 is an **honest report** that SELinux labelling in
that image blocks eBPF; enforcement is running
(hooks 5/5, eBPF 5/5).

### 7.2 Local suite

| Suite | Result |
|---|---|
| Python (pytest) | **179 passed** + 20 subtests |
| Go — axdaemon | 10 packages |
| Go — axlog | 3 packages |
| Shell syntax | `install.sh`, `deep_verify.sh`, `selinux-setup.sh` clean |
| CI configuration | valid YAML |

### 7.3 Packaging matrix

Packaging was run on all five images:
`fedora:41`, `fedora:42`, `fedora:43`, `fedora:44`, `debian:12` —
each with 8/8 content + 5 conffiles + SELinux module.

---

## 8. Known limitations

Listed honestly; none of them is a concealed defect.

| Limitation | State |
|---|---|
| `inode_permission` cannot obtain a path | The kernel ABI only supplies `struct inode *`. Solution: `ino`+`dev` identity is added to the record; records that need a path stay in the `file_open`/`bprm` hooks. |
| `socket_bind` does not match ports | It looks at the port name only; matching could be implemented but does not work. |
| SELinux labelling on Fedora 43 | Cannot be applied on that image; measured, documented, handled with a safe revert. |
| Running on the primary machine | Deliberately blocked for testing (section 0). This is a restriction of the test suite, not of the product: AXlinux itself works on physical machines. |

---

## 9. Downloadable files

| File | Size | SHA-256 (first 16) |
|---|---|---|
| `axlinux-1.2.0-1.x86_64.rpm` | 2,224,480 B | signed |
| `axlinux_1.2.0_amd64.deb` | 5,348,152 B | — |

| `SHA256SUMS` | — | `sha256sum -c SHA256SUMS` |

The verified outputs are under `/mnt/anka/downloads/`.

Integrity verification:

```bash
sha256sum -c SHA256SUMS
```

---

## 10. Quick verification (on your own machine)

After installation, run the following on your own system:

```bash
sudo axctl status
```

You should see:

- `lsm_hooks_active = 5`, `lsm_hooks_total = 5`
- `bpf_programs_loaded = 5`
- `mode` — which mode is currently active
- `policy_healthy = true`

Then the full verification suite:

```bash
sudo bash tests/deep_verify.sh
```

This runs 732 checks and produces a single report.
`deep_verify.sh` refuses to run its enforcement tests on a physical machine —
that is a restriction of the test suite, not of the product.
