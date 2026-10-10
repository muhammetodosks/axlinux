# Installation

This document covers every installation path, the mandatory kernel
prerequisite, and how to verify the result.

> AXlinux runs on physical machines as well as virtual ones. The only
> restriction in this document is that the **test suite** needs a virtual
> machine, because those tests deliberately deny access.

---

## 1. Prerequisites

### 1.1 The `bpf` LSM must be active

AXlinux enforces policy inside LSM hooks. If `bpf` is not in the kernel's
active LSM chain, nothing can be enforced.

```bash
cat /sys/kernel/security/lsm
```

If the output contains `bpf`, you are ready. If it does not, add it to
the kernel command line:

```bash
# /etc/default/grub  ->  GRUB_CMDLINE_LINUX_DEFAULT
lsm=apparmor,bpf
sudo update-grub && sudo reboot
```

After the reboot:

```bash
cat /sys/kernel/security/lsm
# expect bpf to be present
```

### 1.2 Kernel BTF must exist

The BPF program is compiled against kernel type information extracted
from BTF.

```bash
ls -la /sys/kernel/btf/vmlinux
```

If this file is missing, your kernel was built without
`CONFIG_DEBUG_INFO_BTF=y` and BPF cannot be built for it.

### 1.3 Package requirements

| Component | Version |
|---|---|
| Kernel | 5.15+ with `CONFIG_BPF_LSM=y` |
| clang | 12+ (must support `-target bpf`) |
| Go | 1.21+ (**build only**) |
| Python | 3.9+ with `click`, `rich`, `PyYAML` |

---

## 2. Install from the RPM (Fedora)

```bash
sudo dnf install ./axlinux-1.2.0-1.x86_64.rpm
```

Verify the signature first if you received the package from a third
party:

```bash
rpm -Kv axlinux-1.2.0-1.x86_64.rpm
# Header OpenPGP V4 RSA/SHA512 signature,
#   key fingerprint: f108e5cc55806bbb4fc42afa6a2e2989448a5310: OK
```

What the package does automatically:

1. Installs the SELinux module (`axlinux.pp`) and loads it
2. Writes file contexts so `axdaemon` runs in its own confined domain
3. Places the compiled BPF object at `/usr/lib/axlinux/axbpf.o`
4. Installs a journald limit (`SystemMaxUse=200M`)
5. Enables and starts `axdaemon.service` and `axlog.service`

If SELinux confinement turns out to prevent eBPF from loading on your
system, the installer detects it, reverts the labels, restarts the
service and reports it. Enforcement continues on LSM alone.

---

## 3. Install the .deb (Debian, Ubuntu, Pardus)

```bash
sudo apt install ./axlinux_1.2.0_amd64.deb
```

If you use `dpkg` directly, resolve dependencies afterwards:

```bash
sudo dpkg -i axlinux_1.2.0_amd64.deb
sudo apt-get -f install
```

---

## 4. Install from source

```bash
git clone https://github.com/muhammetodosks/axlinux.git
cd axlinux
sudo ./scripts/install.sh
```

`install.sh` detects your package manager and installs the right
packages. It has been verified on all six supported managers: `apt-get`,
`dnf`/`yum`, `pacman`, `apk` and `zypper`.

### 4.1 Options

| Option | Effect |
|---|---|
| `--unattended` | do not prompt |
| `--url URL` | fetch sources from a URL |
| `--no-lsm` | skip the LSM chain check (advanced) |
| `--uninstall` | remove AXlinux |

### 4.2 Build dependencies

Fedora:

```bash
sudo dnf install golang clang llvm bpftool make gcc rpm-build rpm-sign \
  python3-devel python3-setuptools python3-click python3-rich \
  python3-yaml selinux-policy-devel systemd-rpm-macros kernel-core
```

Debian / Ubuntu:

```bash
sudo apt install golang clang llvm make dpkg-dev python3-dev \
  python3-setuptools python3-click python3-rich python3-yaml \
  linux-headers-amdbook-$(uname -r)
```

> **Debian note:** the distribution's `golang` package is Go 1.19, but
> this project requires Go 1.21 (`go.mod` and the use of `log/slog`).
> On Debian 12 install `golang-1.23-go` from bookworm-backports.

Arch:

```bash
sudo pacman -S --needed clang llvm libbpf libbpf-devel linux-headers \
  python-pytest base-devel git rsync curl tar netcat-openbsd
```

Alpine:

```bash
apk add clang llvm libbpf-dev linux-headers py3-pytest \
  build-base git rsync curl tar
```

openSUSE:

```bash
sudo zypper install clang llvm libbpf libbpf-devel \
  linux-devel-default python3-pytest gcc make git rsync curl \
  ca-certificates tar bpftool netcat-openbsd
```

---

## 5. Verify the installation

```bash
sudo axctl status
```

A healthy installation reports:

```
lsm_hooks_active    : 5
lsm_hooks_total     : 5
bpf_programs_loaded : 5
policy_healthy      : true
```

Then run the full verification suite:

```bash
sudo bash tests/deep_verify.sh
```

This runs 732 checks and produces one report.

> `deep_verify.sh` refuses to run on a **physical** machine, because it
> deliberately denies access while testing and could lock the machine
> you are working on. Run it inside a VM. If you have console access and
> a known way out, override with:
>
> ```bash
> AXLINUX_ALLOW_PHYSICAL=1 sudo bash tests/deep_verify.sh
> ```

This restriction applies to the test harness only. AXlinux itself
installs and runs on physical machines without limitation.

---

## 6. Your first policy

```bash
axctl init                  # create ~/.axlinux/
axctl policy edit           # write rules
axctl policy check          # validate
axctl policy simulate       # preview the effect
axctl mode permissive       # observe first
axctl reload                # apply
axctl status                # confirm
```

Start from an example:

```bash
cp examples/50-guvenli-baslangic.yaml ~/.axlinux/policy.yaml
axctl policy check
axctl policy simulate
```

---

## 7. Uninstall

```bash
sudo axlinux-remove        # or: sudo ./scripts/install.sh --uninstall
```

Measured removal result (two consecutive clean cycles):

```
semodule        : 0
fcontext        : 0
local fcontext  : 0
module file     : 0
binaries        : 0/4
```

Configuration files are **backed up before removal** to
`/var/lib/axlinux/removed-config-<timestamp>/` and the path is printed.
(RPM normally deletes `%config(noreplace)` files during removal, which
would lose operator edits.)

Your policy and audit data are preserved:

- `~/.axlinux` (or `$AXLINUX_HOME`)
- `/var/log/axlinux`

Remove them by hand if you want a completely clean system.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `lsm_hooks_active: 0` | `bpf` not in the LSM chain | add `bpf` to the kernel command line, reboot |
| `bpf_programs_loaded: 0` | BTF missing, or SELinux denies `bpf()` | check `/sys/kernel/btf/vmlinux`; see §2 |
| `policy_healthy: false` | a policy file failed to load | `journalctl -u axdaemon` names the offending file |
| "system policy could not be loaded" | one broken file in `policies.d/` breaks **all** of them | run `axctl policy check -f <file>` on each |
| Service will not start | stale BPF maps | `sudo systemctl stop axdaemon axlog`, remove `/sys/fs/bpf/axlinux`, restart |

### Diagnosing policies

```bash
sudo journalctl -u axdaemon -f
sudo axctl logs --limit 50
axctl policy check -f /etc/axlinux/policies.d/50-mine.yaml
```

The `cmd/mapdump` and `cmd/mapcmp` tools in `src/go/axdaemon/cmd/`
compare raw BPF map bytes. They are the only way to tell whether the
kernel produced exactly the key Go wrote.

---

## Further reading

- [docs/policy-language.md](docs/policy-language.md) — policy reference
- [docs/cli-reference.md](docs/cli-reference.md) — all commands
- [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) — distribution paths
- [SECURITY-NOTICE.md](SECURITY-NOTICE.md) — safety notes