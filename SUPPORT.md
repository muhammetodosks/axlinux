# Supported Systems

**AXlinux 1.2.0**

This document states which distribution and kernel versions actually
work. "Supported" means the package genuinely builds, installs, and
**enforcement is really applied**.

AXlinux runs on physical machines as well as virtual ones. Nothing in
this document restricts it to VMs — see
[Why it is safe on a physical machine](README.md#why-it-is-safe-on-a-physical-machine).

---

## 1. Verified distributions

| Distribution | Version | Package | What was verified |
|---------|-------|-------|---------------|
| **Fedora** | **44** | RPM | Full install + enforcement + audit + rotation + multi-user isolation |
| Fedora | 43 | RPM | Full install + enforcement; SELinux confinement unavailable on this image (see §2) |
| Fedora | 41, 42 | RPM | Package builds, 8/8 content + 5 conffiles + SELinux module |
| Debian | 12 (bookworm) | `.deb` | `dpkg -i` + `axctl` + policy validation + removal |
| Ubuntu | 24.04.5 LTS | `.deb` | Same scope |
| Pardus | 25.2 (yirmibes) | `.deb` | Same scope |

**Fedora 44 is the primary target.** On the Fedora side it is tested
under SELinux **Enforcing** — the hardest mode for the product.

Verification environment:

```
Fedora Linux 44 (Cloud Edition)
kernel : 6.19.10-300.fc44.x86_64
LSM    : lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm
BTF    : /sys/kernel/btf/vmlinux  → PRESENT
SELinux: Enforcing
```

`deep_verify.sh` result: **732 passed / 0 failed / 0 skipped**.

---

## 2. Fedora version support

**Verified on Fedora 41, 42, 43 and 44.**

For all four, the RPM genuinely builds and passes the content check:

| Fedora | RPM | Size | conffiles | SELinux module | 8/8 content |
|---|---|---|---|---|---|
| 41 | `axlinux-1.2.0-1.x86_64.rpm` | 2,291,285 B | 5 | ✓ | ✓ |
| 42 | `axlinux-1.2.0-1.x86_64.rpm` | 2,335,203 B | 5 | ✓ | ✓ |
| 43 | `axlinux-1.2.0-1.x86_64.rpm` | 2,401,474 B | 5 | ✓ | ✓ |
| 44 | `axlinux-1.2.0-1.x86_64.rpm` | 2,224,480 B | 5 | ✓ | ✓ |

Eight content items: `axbpf.o`, `axdaemon`, `axlog`, `axctl`, journald
drop-in, SELinux module (`axlinux.pp`), systemd unit, `kernel-core`.

> **Scope difference — read this.** Packaging (build + content +
> conffiles) is proven on all four versions. Runtime verification
> (`deep_verify.sh`, enforcement under SELinux Enforcing) was run on two:
>
> | Version | deep_verify | Result |
> |---|---|---|
> | **Fedora 44** | 732 / 0 / 0 | Full: SELinux confinement active, eBPF 5/5 |
> | **Fedora 43** | 732 / 1 / 1 | LSM enforcement works (hooks 5/5); SELinux confinement cannot be enabled on this image (below) |
>
> Fedora 41 and 42 were not run at runtime. For those, buildability and
> correct contents are proven; enforcement on those kernels was not
> measured.

#### Why SELinux confinement is unavailable on Fedora 43

This is a measured platform limit, not a gap, and the installer reports
it visibly. The measured chain:

1. The package writes file contexts with `semanage fcontext`; that tool
   comes from `policycoreutils-python-utils` and is **now a declared
   dependency**. (It previously was not, so SELinux labels were silently
   never applied — the daemon ran unconfined. That was a real bug, fixed
   and covered by a regression gate.)
2. On the Fedora 43 cloud image, a labelled `axdaemon` entering the
   `axlinux_daemon_t` domain is **denied BPF map operations**:

   ```
   avc: denied { map_read map_write } for comm="axdaemon"
        scontext=system_u:system_r:axlinux_daemon_t:s0
   ```

   - labelled → hooks 0/0, eBPF 0, "eBPF failed to load"
   - unlabelled → hooks 5/5, eBPF 5, enforcement works
3. Confinement would therefore leave a **worse** system than no
   confinement. The installer measures this, reverts the labels,
   restarts the service and says so explicitly:

   ```
   WARNING: confinement prevents eBPF from loading
   labels reverted; enforcement active via LSM
   restarted; eBPF: 5 programs
   ```

   Measured result: `hooks 5/5, eBPF 5` — enforcement works.
   `deep_verify.sh` also reports it honestly:
   `axdaemon runs in the unconfined domain; NO SELinux protection`.

On Fedora 44 the same code path **verifies and keeps** the confinement:
`domain verified: ...axlinux_daemon_t:s0 (eBPF: 5)`.

**Fedora 40 and earlier are not supported.** See the requirements above
for the reason.

---

## 3. Package managers recognised by `install.sh`

| Manager | Status |
|-------------|-------|
| `apt-get` | Verified (Debian 12, Ubuntu 24.04) |
| `dnf` / `yum` | Verified (Fedora 44) |
| `pacman` | Verified (Arch Linux container) |
| `apk` | Verified (Alpine 3.24 container) |
| `zypper` | Verified (openSUSE Leap 15.6 container) |

The last three were verified by **actually running** `install.sh` in
containers. For each, the measured result was: correct manager
detected, dependencies installed, Go 1.23.4 installed, and
`click`/`rich`/`yaml` installed.

Three real bugs were found and fixed during that verification:

1. `pkg_available()` meant different things per manager.
   `apk info -e` and `zypper search -i` ask *"is it installed"*, not
   *"is it available"*. Result: on Alpine and openSUSE, packages that
   genuinely exist — `clang`, `make`, `git` — were reported as "not
   found" and skipped.
2. The dependency list had **no `zypper` branch**; openSUSE fell through
   to the generic fallback and tried Fedora package names. The Python
   dependency block had no `zypper` branch either.
3. `tar` was never declared as a dependency, although `install.sh` uses
   it while unpacking Go.

A package that cannot be found does not abort the installation — the
script skips it, reports which one, and continues.

Whatever the package manager, AXlinux's own runtime dependencies
(`click`, `rich`, `PyYAML`) must be present.

---

## 4. Other platform requirements

| Item | Requirement |
|-------------|-------|
| Architecture | `x86_64` (limited by the RPM `BuildArch`) |
| Kernel | BPF LSM + BTF (see above) |
| Root | required for enforcement |
| SELinux | **Enforcing** recommended on Fedora; the module grants `bpf()` to the `axdaemon` domain only |
| Filesystem | works independently when `bpf` LSM is attached; sub-volumes handled via `mount_point_map` |

The SELinux module does **not** grant `bpf()` system-wide — only to the
`axdaemon` domain. This narrows the module's scope deliberately.

---

## 5. Keeping this document current

The CI packaging matrix is the contract behind the table above:

- `fedora:41`, `fedora:42`, `fedora:43`, `fedora:44` → RPM genuinely
  builds; 8/8 content + conffiles + SELinux module verified
- `debian:12` → `.deb` genuinely builds; contents verified
- If the matrix breaks, the "verified" claim here falls with it

> The matrix was itself broken while this document claimed "verified".
> Verification found **two** breakages, both fixed:
> 1. The Debian job installed apt's `golang` package → **Go 1.19**, while
>    the project requires Go 1.21 (`go.mod`, `log/slog`). The job always
>    failed with "log/slog is not in GOROOT". It now installs
>    `golang-1.23-go` from bookworm-backports and checks the version in a
>    separate step.
> 2. `go build` wanted a VCS stamp and failed with "error obtaining VCS
>    status" in a container without git access, which broke the **entire
>    RPM matrix**. `Makefile` now builds with `-buildvcs=false`.

**Content verification (`deep_verify.sh`) does not run in CI** — it
requires a virtual machine. This is a deliberate limit and is emitted as
a `::warning::` in CI output. Content verification is done separately on
a Fedora 44 VM under `/mnt/anka`.

> That is a limit of the **test harness**, not of the product. AXlinux
> itself runs on physical machines without restriction.

---

## 6. Known platform limits

| Limit | Impact |
|-------|------|
| `net.accept` not supported | no LSM counterpart; the action cannot be implemented |
| Dynamic port rules such as `p:8080` | no prefix in the policy key; can be compiled but never matches |
| Custom (out-of-tree) kernel | `/sys/kernel/security/lsm` and the BTF directory must be present; otherwise install refuses |
| Full desktop not installed on Pardus | verification was performed from the official archive via CLI, not from a full desktop session |

Details: [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) — "Known limits".