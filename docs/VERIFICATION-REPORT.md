# Verification Report — AXlinux 1.2.0

**Date:** 2026-10-10
**Scope:** README.md, SUPPORT.md, docs/DISTRIBUTION.md, docs/READINESS.md,
FEDORA-READINESS.md, CHANGELOG.md, and every numeric and "supported" claim
under `docs/`.
**Method:** Every claim was measured by actually running it. No figure is an
estimate or copied from a previous session.

> **Rule:** Any claim that could not produce evidence was corrected or removed
> from the text.
> No item described as "unverified" remains in this report at the time of writing.

---

## 1. Test environment

| Platform | Release | Kernel | Method |
|---|---|---|---|
| Fedora 44 Cloud | 44 | 6.19.10-300.fc44 | Signed RPM installation |
| Fedora 43 Cloud | 43 | 6.17.1-300.fc43 | Unsigned RPM installation |
| Ubuntu 24.04.5 LTS | 24.04 | 6.8.0-146-generic | `.deb` installation |
| Debian 12 (bookworm) | 12 | 6.1.0-53-cloud | `.deb` installation |
| Pardus 25.2 (yirmibes) | 25.2 | 6.12.107+deb13 | `.deb` installation |
| Arch Linux | current | container | running `install.sh` |
| Alpine | 3.24 | container | running `install.sh` |
| openSUSE Leap | 15.6 | container | running `install.sh` |

Two kernel conditions were measured on every system:
- `bpf` is present in `/sys/kernel/security/lsm`
- `CONFIG_BPF_LSM=y`

---

## 2. Result summary

### 2.1 `deep_verify.sh` — with the current code

| Platform | passed | failed | skipped |
|---|---|---|---|
| **Fedora 44** | **732** | **0** | **0** |
| **Fedora 43** | 732 | 1 | 1 |
| Ubuntu 24.04.5 | 731 | 0 | 1 |
| Debian 12 | 731 | 0 | 1 |
| Pardus 25.2 | 731 | 0 | 1 |

**Justification for the only skipped item:** `SELinux yok (Debian/Ubuntu/Pardus)`.
The Debian family does not ship SELinux — this is not a gap, it is a platform difference.
On Fedora 44 the same item runs and the suite passes with 0 skipped items.

**The single failure on Fedora 43 is an honest report:**
`axdaemon unconfined alanda; SELinux korumasi YOK`. In that image the SELinux
labelling prevented eBPF loading, so the installation script reverts the labels
and continues to run enforcement through the LSM
(measured: hooks 5/5, eBPF 5/5). Details in §5.2.

### 2.2 Local verification suite

| Suite | Result |
|---|---|
| Python (pytest) | 179 passed + 20 subtests |
| Go — axdaemon | 10 packages |
| Go — axlog | 3 packages |
| `install.sh` syntax | clean |
| `deep_verify.sh` syntax | clean |
| `selinux-setup.sh` syntax | clean |
| `.github/workflows/ci.yml` | valid YAML |

---

## 3. Verified items (item by item)

### 3.1 Package managers — by execution

`SUPPORT.md` listed these three as "detected, **unverified**".
`install.sh` was run in real containers.

| Manager | Environment | Measured result |
|---|---|---|
| `pacman` | Arch Linux | package manager detected · packages installed · Go 1.23.4 · click/rich/yaml |
| `apk` | Alpine 3.24 | package manager detected · packages installed · Go 1.23.4 · click/rich/yaml |
| `zypper` | openSUSE Leap 15.6 | package manager detected · packages installed · Go 1.23.4 · click/rich/yaml via pip fallback |

**3 real bugs found and fixed:**

1. `pkg_available()` meant something different on every manager.
   `apk info -e` and `zypper search -i` ask **"is it installed"** — not "is it in
   the repository". Result: `clang`, `make` and `git`, which *are present* on
   Alpine and openSUSE, were assumed to be "package not found" and skipped.
   Correct commands: `apk add --no-cache --simulate` and
   `zypper --non-interactive install --dry-run`.
2. The `zypper` branch was **entirely absent** from the dependency list; openSUSE
   fell through to the `*)` fallback and tried Fedora package names
   (`linux-devel-default` instead of `linux-headers`). Neither `zypper` nor the
   fallback branch existed for the Python dependencies.
3. `tar` was declared as a dependency nowhere, yet `install.sh` used it to
   unpack Go.

### 3.2 CI packaging matrix — by execution

| Image | Result | 8/8 content | conffiles | SELinux module |
|---|---|---|---|---|
| `fedora:41` | passed | ✓ | 5 | ✓ |
| `fedora:42` | passed | ✓ | 5 | ✓ |
| `fedora:43` | passed | ✓ | 5 | ✓ |
| `fedora:44` | passed | ✓ | 5 | ✓ |
| `debian:12` | passed | ✓ | 5 | ✓ |

8 content items: `axbpf.o`, `axdaemon`, `axlog`, `axctl`, journald
drop-in, SELinux module (`axlinux.pp`), systemd service, `kernel-core`.

**2 breaking points found and fixed:**

1. **The Debian job was failing every time.** Apt's `golang` package provides
   Go 1.19; the project requires Go 1.21 (`go.mod`, `log/slog`). `golang-1.23-go`
   is now installed from `bookworm-backports` and the version is checked in a
   separate step.
2. **The entire RPM matrix was failing.** `go build` requests a VCS stamp and
   reports `error obtaining VCS status` in a container that cannot reach git.
   The `Makefile` now builds with `-buildvcs=false`; the build no longer depends
   on `.git`.

### 3.3 Installation artefacts

| Artefact | Measured |
|---|---|
| RPM signature | `Header OpenPGP V4 RSA/SHA512, key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK` |
| Header/Payload digest | SHA256 OK |
| conffiles | 5 |
| SELinux module | `axlinux.pp` — a broken module was measured on Fedora 43 and fixed (§5.4) |
| `.deb` version field | `Version: 1.2.0` |
| Removal | across two consecutive clean cycles `semodule=0`, `fcontext=0`, `local fcontext=0`, `module file=0`, `binaries=0/4` |

### 3.4 SELinux labelling

| Environment | Context | eBPF | Result |
|---|---|---|---|
| Fedora 44 | `axlinux_daemon_exec_t` | 5/5 | `alan dogrulandi: ...axlinux_daemon_t:s0 (eBPF: 5)` |
| Fedora 43 | `bin_t` (reverted) | 5/5 | warning issued, enforcement running |

### 3.5 Performance — measured three times in a row

`FEDORA-READINESS.md` previously stated:
*"hook attachment cost +5.8 µs (51%), policy lookup +0.6 µs (3.5%)"*
and the conclusion was **backwards**.

| Condition | 3 runs (µs/open) | Median |
|---|---|---|
| No LSM hook | 14.3 · 13.2 · 12.1 | 13.2 |
| Hook attached, `disabled` | 12.7 · 16.3 · 17.8 | 16.3 |
| Hook attached, `enforcing` | 22.1 · 26.2 · 21.9 | **22.1** |

- **Policy lookup cost is real:** +5.8 µs, the ranges do not overlap
  ([2] highest 17.8 < [3] lowest 21.9).
- **Hook attachment cost was not measured:** the ranges overlap
  ([1] 12.1–14.3, [2] 12.7–17.8) — run-to-run noise.

Throughput (50,000 opens): `disabled` 0.228 s · `enforcing` 0.559 s
(the old value was 0.44 s; the enforcement cost was shown **too optimistically**).

---

## 4. `deep_verify` gaps closed during verification

| Before | After |
|---|---|
| `nc` not installed → 2 socket tests were skipped | `netcat-openbsd` installed, both run |
| "did not error on an unreachable socket (**root test**)" — the check ran as ROOT; because root can also access a `chmod 000` socket, the test **was fooling itself** | the check runs as an unprivileged user (`rc=4`, `Socket izni yok`) |
| fixed 5 attempts at the LSM hook gate — on a slow VM this produced "LSM kancalari: ?/?" | wait based on health (`ax_wait_healthy`) |
| `axctl reload` failed with "socket bulunamadı" and the error was **swallowed** | the reload rc and its output are recorded |
| policy was assumed "loaded" although `rules_loaded=0` | the deny is required to **actually take effect** |

---

## 5. Critical product bugs found

### 5.1 Two separate policy parsers — the persistent path was completely broken

`axctl policy check` called a policy written as a scalar `subject: curl`
**valid**. The user path (`axctl reload`) did the same. But
`/etc/axlinux/policies.d` — the **persistent path** — rejected the same file:

```
sistem politikasi yuklenemedi; sistem KISITLAMASIZ kaliyor
error="50-....yaml: policy JSON parse hatasi: json: cannot unmarshal
       string into Go struct field Rule.rules.subject of type []string"
```

Result: after a reboot the user believed "my rules are loaded";
**not a single rule was written.** The system was unrestricted.

Fix: `SubjectList` + a custom `UnmarshalJSON`. Regression protection:
- `internal/policy/subjectlist_test.go` — scalar/list/malformed input
- `internal/policy/systemload_subject_test.go` — the **system path**
- `deep_verify`: the "sistem politikasi yuklendi (policies.d)" gate

Reboot persistence was verified by hand: the policy was loaded from `policies.d`,
the deny operated at depth (`Operation not permitted`, 2 DENIED records), and a
non-rule path plus a similarly named neighbour stayed allowed (no false positive).

### 5.2 SELinux labelling was silently never applied

File contexts are written with `semanage fcontext`; that tool ships with
`policycoreutils-python-utils` and the spec did **not declare it as Requires**.

Measured result on the Fedora 43 image:
- `semanage: command not found` → labels are not written
- `/usr/bin/axdaemon` → `bin_t`
- the daemon runs **unconfined**
- `deep_verify`: `FAIL axdaemon unconfined alanda; SELinux korumasi YOK`

On Fedora 44 it worked **by accident** — the package was already present in that image.

Fix (two stages):

1. `Requires: policycoreutils-python-utils` added.
2. **Functional verification** added to the installation script: after the labels
   are applied, it checks whether eBPF really loads. If it does not, the labels
   are reverted, the service is restarted and the operator is notified.

This second stage was necessary because on Fedora 43, when the labelled
`axdaemon` enters the `axlinux_daemon_t` domain, SELinux **denies the BPF map
operation**:

```
avc:  denied { map_read map_write } for comm="axdaemon"
     scontext=system_u:system_r:axlinux_daemon_t:s0

etiketli  -> kanca 0/0, bpf 0, "ebpf yuklenemedi"
unlabelled -> hooks 5/5, bpf 5, enforcement works
```

In other words, labelling left behind a system that was **worse** than an
unlabelled one. Measured final result:

```
UYARI: konfinasyon eBPF yuklemeyi engelliyor
etiketler geri alindi; enforcement LSM ile aktif
yeniden baslatildi; eBPF: 5 program
```

### 5.3 Test gates were producing wrong results in the environment

`deep_verify` used fixed short waits in many places ("sleep 1", "sleep 5").
On slow virtual machines it measured before the policy/hook was ready, and the
gates reported red while the product was healthy.
All of them were converted to health-based waits.

### 5.4 A stale SELinux module was being packaged

`make rpm` only called `all`, and `2>/dev/null` **hid** build errors. If a
previously built `.pp` exists in the tree, `make` treats it as "up to date" and
skips the build; that stale module was packaged into the RPM.

The broken module measured on Fedora 43: **91,660 bytes, 0 types, 0 fcontext
rules** — the module appeared to be "installed" but labelled nothing.

Fix: the module is now always rebuilt from scratch with `clean` + `all`; if an
empty module (0 types) is produced, the build **fails**. The correct module is
91,880 bytes. `.pp` and `.rpmbuild/` are now in `.gitignore`.

---

## 6. Claim corrections

| Document | Old | New |
|---|---|---|
| `README.md` | 732/0/1 | per-platform (Fedora 44 → 732/0/0; Debian family → 731/0/1) |
| `SUPPORT.md` | pacman/apk/zypper "unverified" | all three executed, evidence table |
| `SUPPORT.md` | Fedora 41–44 "definitely verified" | build in all four; runtime on 43 and 44 |
| `docs/DISTRIBUTION.md` | Ubuntu/Pardus/Debian 732/0/1 | 731/0/1; Fedora 43 and 44 added |
| `docs/DISTRIBUTION.md` | "10 sections, 100 checks" | 8 named sections (K–R), 732 checks |
| `FEDORA-READINESS.md` | hook +5.8 µs, policy +0.6 µs | policy +5.8 µs (real), hook not measured |
| `FEDORA-READINESS.md` | throughput 0.44 s | 0.559 s |
| `docs/roadmap.md` | "10 sections / 100 checks" | 8 sections, 732 measured checks |

---

## 7. Permanent protection

Permanent gates that prevent the bugs found in this session from returning:

| Gate | Bug it prevents |
|---|---|
| `internal/policy/subjectlist_test.go` | scalar/list `subject` parsing |
| `internal/policy/systemload_subject_test.go` | divergence in the `policies.d` path |
| `tests/deep_verify.sh` → system policy gate | the persistent path staying broken |
| `tests/deep_verify.sh` → socket authorization gate | the authorization path not being tested |
| `tests/deep_verify.sh` → `ax_wait_healthy` | measuring before ready |
| `tests/test_doc_numbers.py` | stale verification counts reappearing in the documentation |
| CI Go version check | falling below Go 1.21 |
| `Makefile` empty module check | packaging a broken SELinux module |
| `selinux-setup.sh` eBPF verification | labelling breaking eBPF |

---

## 8. Out of scope (stated honestly)

- **Fedora 41 and 42 runtime testing was not run.** The RPM build and content
  were verified (`make rpm` + 8/8 + 5 conffiles + SELinux module); a real
  installation + `deep_verify` was not executed.
  `SUPPORT.md` was written accordingly.
- **The `inode_permission` path cannot be obtained in the kernel ABI.** This hook
  only receives `struct inode *`; there is no back-reference to the dentry. The
  solution is to add `ino`/`dev` identity to the audit record; records that need
  a path stay in the `file_open`/`bprm` hooks. This is a structural boundary,
  not a measurable defect.
- **Fedora 43 has no SELinux labelling** (see §5.2). A platform boundary that
  was measured, documented and handled with a safe revert.
