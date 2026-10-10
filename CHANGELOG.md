# Changelog

## 1.2.0 (addendum) - Bugs found and fixed during verification

This section records the bugs that were found while the 1.2.0 claims were
being audited and that were **actually reproduced by running them**. All of
them were proven by measurement and fixed; a permanent regression gate was
added for each one.

### 1. Two separate policy parsers - the permanent location was entirely broken

`axctl policy check` considered a policy with a single `subject: curl` to
be **valid**. On the user policy path (`axctl reload`) this was the same.
BUT the `/etc/axlinux/policies.d` path **rejected** the same file:

    sistem politikasi yuklenemedi; sistem KISITLAMASIZ kaliyor
    error="50-....yaml: policy JSON parse hatasi: json: cannot unmarshal
           string into Go struct field Rule.rules.subject of type []string"

Because `policies.d` is the permanent location, the result was this: after
a reboot the user believed "my rules are loaded" while not a single rule
was written. The system remained **unrestricted**. The worst failure mode
in a MAC.

Fix: a `SubjectList` type with a custom `UnmarshalJSON`, so that both paths
accept both the single form and the list form. Regression gates:
`subjectlist_test.go`, `systemload_subject_test.go`, and the
"sistem politikasi yuklendi" gate inside `deep_verify`.

### 2. The installation script did not work on Alpine and openSUSE

- `pkg_available()` carried a **different meaning** on each package manager.
  `apk info -e` and `zypper search -i` ask "is it installed", not "is it in
  the repository". As a result, the `clang`, `make` and `git` packages that
  were already present were treated as "package not found" and skipped.
- The `zypper` branch was **not present at all** in the dependency list;
  the openSUSE `*)` fallback tried Fedora package names. Neither `zypper`
  nor the fallback was present in the Python dependencies either — `axctl`
  did not start with "No module named 'rich'".
- `tar` was not declared as a dependency anywhere, yet `install.sh` used it
  while unpacking Go.

Verification: `install.sh` was actually run in Arch, Alpine and openSUSE
Leap 15.6 containers; on all three the package manager was identified
correctly, the dependencies were installed, Go 1.23.4 was installed, and
`click`/`rich`/`yaml` were installed.

### 3. Both jobs of the CI packaging matrix were broken

- **The Debian job always fell over.** The `golang` package of `apt` ships
  Go 1.19, while the project requires Go 1.21 (`go.mod`, `log/slog`).
  `golang-1.23-go` is now installed from `bookworm-backports`, and the
  version is checked in a separate step.
- **The entire RPM matrix fell over.** `go build` demanded the VCS stamp
  and reported "error obtaining VCS status" in the container that has no
  access to git. The `Makefile` now builds with `-buildvcs=false`.

Verification: packaging was re-run on all five of the `fedora:41/42/43/44`
and `debian:12` images; the four RPMs passed with 8/8 content + 5 conffiles
+ SELinux module.

### 4. SELinux confinement was silently never installed

The package writes the file contexts with `semanage fcontext -a`; this tool
is provided by `policycoreutils-python-utils`. The spec did **not declare
this as Requires**.

On the Fedora 43 cloud image this package is not installed. Result:

    semanage: command not found  ->  set_fcontext silently fails
    /usr/bin/axdaemon  stays as bin_t
    axdaemon runs in the UNCONFINED domain

In other words, the SELinux protection was never installed, but the
installation looked "successful". On Fedora 44 it worked **by accident** —
the package was already present on that image. `deep_verify` caught this:

    FAIL axdaemon in the unconfined domain; NO SELinux protection

Fix: `Requires: policycoreutils-python-utils` was added, and **functional
verification** was placed into the installation script: after the labels
are applied, it checks whether eBPF actually loads.

This uncovered a second real bug: on Fedora 43, the labelled `axdaemon` has
its **BPF map operations denied by SELinux**:

    avc: denied { map_read map_write } for comm="axdaemon"
         scontext=system_u:system_r:axlinux_daemon_t:s0

    labelled    -> hook 0/0, bpf 0, "ebpf could not be loaded"
    unlabelled  -> hook 5/5, bpf 5, enforcement runs

In other words, the confined system was worse than an unconfined system.
The fix is on the **safe side**: if verification fails, the labels are
rolled back, the service is restarted, and the operator is explicitly
notified:

    WARNING: the confinement is blocking the eBPF load
    labels rolled back; enforcement active via LSM
    restarted; eBPF: 5 programs

Measured result: Fedora 43 -> hook 5/5, bpf 5 (enforcement runs);
Fedora 44 -> `alan dogrulandi: ...axlinux_daemon_t:s0 (eBPF: 5)`
(confinement active).

In addition, the SELinux module packaged into the RPM could also be stale:
because `make rpm` only invokes "all", if a `.pp` had already been compiled
earlier in the tree it would skip the build, and `2>/dev/null` hid the
errors. The broken module measured on Fedora 43: 91,660 bytes, **0 types,
0 file-context rules**. The module is now always compiled from scratch with
`clean` + `all`, and the build fails if an empty module is produced.

### 5. The test gates returned the wrong result in the environment

`deep_verify` waited for a fixed short time in several places ("sleep 1",
"sleep 5"). On slow virtual machines the measurement was taken before the
policy/hook was ready, and the gates produced reds that were mistaken for
product bugs. All of these waits were replaced with health-based waiting.

Result: **0 failures** on four platforms:

| Platform | passed | failed | skipped |
|---|---|---|---|
| Fedora 44 | 732 | 0 | 0 |
| Ubuntu 24.04.5 | 731 | 0 | 1 |
| Debian 12 | 731 | 0 | 1 |
| Pardus 25.2 | 731 | 0 | 1 |

(The single skipped item in the Debian family is SELinux; it is not
packaged. On Fedora 44 the same item works and passes with 0 skipped
items.)

### 6. The performance claims were corrected

`docs/FEDORA-READINESS.md` said "hook attach cost +5.8 us (51%), policy lookup
+0.6 us (3.5%)", and the inference was **reversed**. In a measurement
repeated three times:

- the policy lookup cost is **+5.8 us** and the ranges of the two groups do
  not overlap -> real and measurable;
- the hook attach cost stays inside the ranges -> **not measurable**.

In addition, the 50,000 file open throughput table listed `enforcing` at
0.44 s; a fresh measurement gave 0.56 s (more than double the cost).

---

## 1.2.0 - Directory rules, permanent policy, signed package

The release produced for the Fedora Workstation desktop target. In this
release two PERMANENT BUGS in the policy language and the distribution path
were fixed; both of them gave the user a false sense of security.

### Security vulnerability: directory rules did not protect their CONTENTS

    object: /tmp/dizin   +   action: file.read   effect: deny

This rule only blocked the directory ITSELF. The files inside it
(`secret.txt`, `id_rsa`) were left FREE:

    cat /tmp/dizin              -> Operation not permitted
    cat /tmp/dizin/secret.txt   -> READABLE (leak)

The user believed "my keys are protected".

Fix: PREFIX matching on the BPF side. The rule key is the component block of
the real path, shifted k levels deeper; the matching derived key is exactly
identical to the output of Go's `setKeyPath`. No change on the Go side.

Evidence (Fedora 44, enforcing, rule `object: /tmp/pm`):
    /tmp/pm/kok.txt              DENY
    /tmp/pm/a/ust.txt            DENY
    /tmp/pm/a/b/derin.txt        DENY
    /tmp/pm/a/b/c/d4.txt         DENY
    /tmp/pm/a/b/c/d/d5.txt       DENY
    /tmp/pm.txt                  FREE     (similar name, different path)
    /etc/hostname                FREE     (outside the rule)

### The policy was LOST after a reboot

The policy was loaded only through the `axctl` API, from
`~/.axlinux/policy.yaml` of the running user. Nothing was read at boot; the
BPF maps started empty. After a reboot ALL rules were lost and the system
silently returned to the "nothing is restricted" state.

Fix: `/etc/axlinux/policies.d/*.yaml` is read at boot. A single application
path `ApplyPolicy`: both the RPC and boot use the same code, so the two
paths cannot diverge over time.

If the policy is corrupt, NO rule is written, the system remains
unrestricted, and the daemon writes a clear warning to the journal. A
deliberate choice over locking the system up by mistake.

### install.sh did not INSTALL the system-wide policy directory

The RPM path installed the directory in the spec; install.sh did NOT. The
two installation paths did not install the same system, and both of them
said "working". Fixed; install.sh now installs the directory as 0750
root:root and the sample policy file as 0640.

### RPM signing

Every package distributed through a real repository must be signed.
New: `make rpm-gpg-key`, `make rpm-sign`, `make rpm-export-key`,
`make rpm-verify-sign`. The key is not kept in the repository.

### Audit rotation NEVER worked

`openCurrent()` always generated the file name from today's date; when the
10 MB limit was triggered, the same file was reopened with `O_APPEND`. The
file never rotated, it only grew (10,798,351 bytes in the VM). There was no
upper retention limit either.

Fix: numbered segments, compression covering all segments at day change,
14-day retention and a 200 MB total size limit.

### Other fixes

- `audit_healthy` stayed permanently `false`: after a one-off "broken pipe"
  the error was not cleared from memory, and a healthy system reported a
  false alarm continuously.
- `axlog` reported 1.0.0 while the RPM 1.1.0 was being built. The version
  now comes from a single source (the spec) and is injected into both
  binaries via `-ldflags`.
- `inode_permission` produced a USELESS record for every permitted access in
  learning mode (43,641 records / 10 MB in 10 minutes). These records carry
  no information and produce no rules; they were removed. In this hook the
  path cannot be resolved: the LSM signature takes a `struct inode *`, and
  an inode has no back-pointer to its dentry.
- `deep_verify` used a fixed `/tmp` path; when a non-root user left it
  behind, the next run reported FAIL without any real regression.
- The `deep_verify` rotation test was meaningless (it wrote a file dated
  1999 and then checked whether it was "deleted", so it returned skip on
  every run). It now reads the numbered segments directly and also includes
  the directory content test.

### Verification

- `deep_verify.sh`: 723 passed / 0 failed / 1 skipped
- Go: 13 packages (6 new tests in writer, 5 new tests in maps)
- Python: 179 passed + 20 subtests
- RPM: production, GPG signing, fingerprint verification with `rpm -Kv`,
  clean installation (remove first, then install)
- `install.sh --unattended`: 11/11 steps on a clean Fedora 44, followed by
  enforcement evidence

## 1.1.0 - Fedora 44 Workstation (desktop)

Verification for the **desktop** target on Fedora 44. This release fixes six
real bugs that had remained silent; the first three directly affected the
FUNCTION of the product.

### Critical: the policy was LOST after a restart

The policy was loaded only through the `axctl` API, from
`~/.axlinux/policy.yaml` of the running user. Nothing was read at boot; the
BPF maps started empty. After a reboot **all rules were lost** and the
system silently returned to the "nothing is restricted" state.

Fix: the `/etc/axlinux/policies.d/*.yaml` directory is read at boot (merged
in lexical order). A single application path `ApplyPolicy`: both the RPC and
boot use the same code, so the two paths cannot diverge over time.

If the policy is corrupt, **no rule is written** and the system remains
unrestricted; the daemon writes a clear warning to the journal. A
deliberate choice over locking the system up by mistake.

### Critical: audit rotation NEVER worked

`openCurrent()` always generated the file name from today's date. When the
10 MB limit was triggered, the same file was reopened with `O_APPEND`: the
file never rotated, it only grew. A file that had reached 10,798,351 bytes in
the VM kept growing without the user noticing.

In addition there was NO upper retention limit at all: a new file accumulated
every day.

Fix: numbered segments (`audit-DAY.1.jsonl`), compression covering all
segments at day change, 14-day retention. The `writer` package had **no
tests at all**; 4 regression tests were added and **verified to fail against
the old code**.

### Critical: `audit_healthy` stayed `false` permanently

When `axlog` restarted, a "broken pipe" occurred once, on the next attempt
the connection was established by itself and the records kept flowing — but
`lastErr` stayed in memory. While the system was healthy,
`audit_healthy=false` was being reported: a continuous false alarm.

Fix: a successful send clears `lastErr`.

### `axlog` reported the wrong version

There was a `"1.0.0"` constant inside `axlog/main.go`: while the RPM 1.1.0
was being built, the log service reported itself as 1.0.0. In addition, the
`Makefile` scraped the version from `axdaemon/main.go`; if the definition
had been a `const` -> `var`, the scrape would have silently returned an
empty string.

Fix: the version comes from a single source (`axlinux.spec`) and is injected
into both binaries via `-ldflags`.

### `deep_verify` was affected by its own state

The test used the fixed path `/tmp/axctl-cli.txt`. When a non-root user
abandoned the test, the file remained owned by that user; on the next run
root could not write to it and awk exited with an error — the test reported
FAIL even though there was no real regression.

Fix: the temporary file depends on the run identity.

### Fedora Workstation desktop evidence

- A real GNOME 50 session (gdm + Wayland + `systemd --user`)
- A real GUI application with enforcement active (gedit, a Wayland client)
- A real package installation with enforcement active (`dnf install`, 13
  packages)
- Automatic login after a reboot + the policy loading by itself
- A realistic enforcing policy with 4 rules (4/4 applied)

### Measurements

- **File open latency:** no LSM hook 11.3 us -> enforcing 17.7 us.
  Hook attach cost +5.8 us, policy lookup only +0.6 us.
  50,000 opens: 0.25 s instead of 0.44 s (difference 0.19 s, imperceptible).
- **Audit on disk:** a permitted operation **0 bytes**; a blocked operation
  ~252 bytes. The cost depends on the number of VIOLATIONS, not on the total
  activity.

### Verification

- `deep_verify.sh`: **716 passed / 0 failed / 2 skipped**
- Go: 13 packages passed · Python: 179 passed + 20 subtests
- RPM 2,189,772 bytes; clean installation + removal + reinstallation

## 1.1.0 - Fedora 44 compatibility

Full verification on Fedora 44 (the current stable Fedora release).
This release permanently fixes a series of real bugs that had remained
silent.

### Critical fixes (enforcement did not work at all)

- **The eBPF programs did not load on the Fedora kernel.**
  The Fedora 44 verifier (clang 22, kernel 6.19) rejected LSM hooks
  containing multiple `return`:
  `At program exit the register R0 has smin=0 smax=4294967295`.
  Result: no hook was attached, the daemon said "ebpf could not be loaded"
  and ran WITHOUT enforcement; the installation looked "successful".
  The only remaining numerical PID protection was removed (PID 1/2 are
  already protected by name: systemd/init/kthreadd/swapper/migration).
  `src/go/axdaemon/internal/protected` is now the single source of truth;
  `contract_test.go` verifies equality with the BPF list.

- **`process.exec` and `file.execute` rules were never applied.**
  Two separate causes:
  1. The protection check was performed on the PARENT process; because
     "bash" and "sudo" are protected, the hook always returned early.
     It is now checked on the target binary.
  2. Path resolution was stuck at the btrfs subvolume root ("root").
     It has been the root subvolume since Fedora 33; the kernel reports the
     path as "/root/etc/secret", while the policy writes "/etc/secret".
     Solution: the daemon reads the invisible mount roots from
     `/proc/self/mountinfo` and passes them to BPF via `mount_artifact_map`
     (`internal/maps/artifacts.go`).
     `/etc`, `/var`, `/home`, `/root`, `/usr/bin` verified.

- **Symbolic links were evaluated incorrectly.** Rules are applied to the
  file ACTUALLY executed, not to the invoked name. This is preserved:
  otherwise `ln -s /bin/ls /tmp/ok` would bypass all rules.

- **`vmlinux.h` was compiled from a stale copy.** The repository contained a
  file left over from September, generated from the kernel of the
  development machine, and `install.sh` only generated it "if missing". It
  is now regenerated from the BTF of the running kernel on every
  installation.

- **`ax_lookup2` did not do wildcard matching.** `file.execute` rules written
  with `subject: "*"` + `object:` could not be found at all in the bprm
  hook.

### SELinux

- **Recompiling the policy module on every installation** is mandatory.
  Otherwise the old module installed on the system is used and the new
  rules added to the source are never loaded.
- `selinux-setup.sh` selects the **newest** module among the candidates.
- Write permissions for `bpffs` (`/sys/fs/bpf`) were added.
- The fcontext for `axlog` was mistakenly given to `axctl`; the correct
  type is `axlinux_log_exec_t` and the new `axlinux_cli_exec_t`.
- The module search path was corrected; the compiled module in the source
  tree is evaluated first.

### Validation consistency

- `axctl policy check` and `axctl reload` use the **same validators**.
  They contradicted each other: a duplicate rule `id` was rejected in Go
  and accepted in Python.
- Paths containing `..` are rejected in both validators.
- `axctl status --json` now publishes `protected_processes`; `install.sh`
  shows the REAL count instead of hardcoding "29 processes".
- Lockout protection is 31 processes (the old text said 29).

### Resolved limits

- **Detached mount points now enter path rules.**
  The name of the `/tmp` mount point is not visible in the dentry chain; the
  kernel reports `/ax-file`, the policy writes `/tmp/ax-file`. Solution:
  `mount_point_map`. The daemon reads the superblock device (3rd field
  `MAJ:MIN`) from mountinfo and writes it into the map; when BPF reaches the
  mount root it appends the prefix under the real path. Verification
  (Fedora 44): deny rules were applied on `/tmp`, `/dev/shm`, `/run`,
  `/run/user/1000`, and paths outside the rules remained free.
- **Map pinning works.** `bpf_obj_pin` was returning EPERM.
  Root cause SELinux: the module did not grant
  `bpf_t:filesystem getattr/associate`. `allow_map`, `deny_map` and
  `mode_map` are now pinned permanently under `/sys/fs/bpf/axlinux/`.

### Unresolved, documented limit

- **Directory rules (`object:`) are handled as a FULL PATH.**
  `object: /home/u/.gnupg` protects the directory itself, not the files
  inside it. The policy text said "prefix"; this is a violation of the
  contract. Root cause: the key code is aligned to the end of the path
  (`/a/b` -> `[6]/a [5]/b`), block shifting is required on the BPF side so
  that a shorter path can use the same block; three different formats were
  tried and no way that works within the verifier limits was found.
  Writing 6-8 keys per rule dropped reload to ~1450 rules in a map with
  10240 entries. Interim solution: write the full path.
  The real solution is to convert the `setKeyPath` + `ax_fill_path` coding
  together into an "absolute depth" format.

### Remaining limits

- **The mount namespace works per device.** `mount_point_map` is keyed by
  the superblock device (an inode is not present in mountinfo and `stat()` is
  denied by SELinux). Binding the same superblock to two different paths
  shares a single record; in practice this does not occur.
- **The audit path field is empty.** JSONL records contain `"object":{}`;
  which file the decision was made for is not visible in the record.
  Violations can be counted, but an audit file review cannot be performed.

## 1.0.0 - 2026-10-02

AXlinux 1.0.0. This release removes the "experimental" label: it becomes a
distribution that can be installed, updated and rolled back.

Semantic versioning: `MAJOR.MINOR.PATCH`. The version is read from a single
source (`axctl version`), and the inconsistency between Python
(`__init__.py`), the package (`pyproject.toml`) and Go (`main.go`) is caught
by a test.

### DELIVERY: real packaging

Source + `install.sh` was the single distribution path. This is not a real
distribution: the user cannot ask "is it installed", the package manager
neither updates nor rolls back. A `.deb` package is now produced:

```bash
make package     # -> axlinux_1.0.0_amd64.deb
sudo dpkg -i axlinux_1.0.0_amd64.deb
```

- The compiled binaries are embedded in the package; clang/Go are NOT
  REQUIRED on the target
- `control.bin`, `postinst`, `prerm`, `postrm` provide the correct lifecycle:
  services are started on installation and stopped on removal
- Sample policies in `/etc/axlinux`, documentation in `/usr/share/doc`
- Policy and audit are NOT in the package and are NOT DELETED on removal
- The same directory layout and the same result as `make install`

### Bugs found and fixed in packaging during this round

Only the bugs that surfaced with a real `dpkg -i`; none of them were
visible in the `make package` output.

**The CLI wrapper did not work at all.** It was generated with `printf`
inside the `Makefile`; single quotes were lost across the
`sh -> printf -> python -c` layers of quoting:

```
$ axctl version
  File "<string>", line 1
    sys.path.insert(0, /usr/lib/axlinux)
SyntaxError: invalid syntax
```

`packaging/axctl` is now a real file.

**The package ran the old version.** The Python files were copied FLAT
(`/usr/lib/axlinux/cli.py`) but the code expects `axctl.cli`; therefore the
subdirectory of the old installation was being picked up:

```
$ axctl version
  Error: No such command 'version'.
```

The layout is now the same as with `make install`:
`/usr/lib/axlinux/axctl/`.

**The help output was misleading.** In `python -c` mode `sys.argv[0]` was
`-c`, not `axctl`; it printed `Usage: -c [OPTIONS]`.

**postinst finished before the daemon was ready.** Loading eBPF and
attaching the 5 LSM hooks takes ~2 seconds. If `axctl status` is run
immediately after installation:

```
x axdaemon calismiyor veya socket bulunamadi
```

A working system looked like it was not working. postinst now waits for the
sockets.

**Installed-Size stayed empty.** Because make runs each recipe line in a
SEPARATE shell, `$SIZE` was not carried over to the next line; the result was
`Installed-Size: ` (no value). A package with an empty value is rejected
with `duplicate value for Installed-Size`. The staging directory is now
calculated after ALL has completed, and the package is not produced if the
value is still empty.

**`__pycache__` was left behind on removal.** The files Python generates at
runtime are not package files and dpkg does not track them; after `dpkg -r`
`/usr/lib/axlinux/axctl/__pycache__` remained. postrm cleans it up.

### Verification: a system installed from the package, three distributions

Not the source tree: the `.deb` package was installed and verified:

| Distribution | dpkg -i | axctl version | bpf | hook | audit | deep_verify |
|---------|---------|---------------|-----|-------|-------|-------------|
| Ubuntu 24.04.5 | success | axctl 1.0.0 | 5/5 | 5/5 | healthy | 100/0/0 |
| Debian 12 | success | axctl 1.0.0 | 5/5 | 5/5 | healthy | 100/0/0 |
| Pardus 25.2 (yirmibes) | success | axctl 1.0.0 | 5/5 | 5/5 | healthy | 100/0/0 |

Pardus was installed from the official archive:
`bilgemdepo.pardus.org.tr/pardus` (Origin: Pardus, signed),
`base-files 13.8+pardus25.2.1` ->
`Pardus GNU/Linux 25 (yirmibes)`.

Removal verification (Ubuntu 24.04.5):

| Check | Result |
|---------|-------|
| `/usr/lib/axlinux` after `dpkg -r` | absent (clean) |
| audit log after `dpkg -r` | PRESERVED |
| `~/.axlinux` after `dpkg -r` | PRESERVED |
| reinstallation | 1.0.0, axdaemon active, 100/0/0 |

### Tests

- Python: 154 tests + 20 subtests
- Go: 9 packages
- `tests/deep_verify.sh`: 10 sections / 100 checks (99 in 0.1.0)

### Notes

Policy signing and trust management were deliberately NOT IMPLEMENTED.
A half-signed policy creates a security vulnerability; the system currently
accepts unsigned policy and states this clearly in the documentation.

## 0.1.0 - 2026-09-29

The first real verification: a blocked path resolver, a permanent audit
service, and enforcement verified on four virtual machines.

### Verification

The verification was performed in a virtual machine (Ubuntu 24.04, kernel
6.8, `lsm=...,bpf,...`). AXlinux was never run on the host machine.

| Check | Result |
|---|---|
| `make -C src/bpf` | clean |
| `make -C src/bpf verify` | 5/5 hooks, the hook->map contract passed |
| `go vet` (axdaemon + axlog) | clean |
| `go test` | 11 packages, 0 errors |
| `make test` | rc=0 (78 Python + 36 static) |
| `file_open` DENY | curl rc=37, control group rc=0 |
| `bprm` (exec) DENY | rc=1, control group rc=0 |
| `socket_connect` DENY | nc 4444 rc=1, 5555 rc=0 |
| Permanent audit | 18 valid JSONL records, traceable via `rule_id` |
| Lockout protection | cat/head/bash/apt/sshd intact |

### Silent bugs that were fixed

None of these was a build error; all of them belonged to the "looks like it
is working but does nothing" class. The new code had never been compiled
with these files.

**Serious / silent no-op**

- **merged-usr path mismatch.** In modern Debian/Ubuntu `/bin`, `/lib`,
  `/sbin`, `/lib64` are symlinks. The kernel always reports the RESOLVED
  path, so a policy writing `/bin/ls` produced the key `["/bin","/ls"]` while
  the kernel looked for `["/usr/bin","/ls"]`. The rule was loaded, "1 rule
  loaded" was printed, and it NEVER matched. Policy paths are now
  canonicalised at load time.
  (Finding this bug required 3 reboots and a temporary diagnostic probe on
  the hook; the probe was removed.)
- **`port` was optional in a `net.*` rule.** If no port is given, the key
  becomes `p:0` and it never matches any connection. It is now mandatory at
  the Go gate; Python was already enforcing it, but when the policy arrived
  directly via RPC, Python was bypassed.
- **The `effect=deny` filter returned no records.** The value on the line is
  numeric, the filter is textual; it was not converted to names before the
  comparison. The `subject` alias and the `hook` field were also never
  produced.
- **Learning was fed from the `get_logs` query.** The same events were
  counted again on every query, and if nobody queried, nothing was
  observed. The observer is now tied to the moment the event is CREATED.
- **The `Makefile` swallowed the axlog tests** (`|| true`): two build errors
  were never visible.
- **`test_contracts_static` sections 3, 4 and 13 never worked.**
  A regex containing spaces was read with `eval("")`, hook names were
  searched for as `.inc.inc` and could not be found, and `func ax_set_port`
  was searched for in the C code.
- **The Python validator crashed on every policy with a list subject**
  (`unhashable type: 'list'`) - the most commonly used rule format.
- **`compiler.py` had a syntax error** (a forgotten `f"` prefix): the Python
  CLI was completely unusable.

**Installation and service**

- `axctl` was not installed anywhere ("axctl is ready" was printed but the
  file did not exist).
- `axdaemon.service` had a `Requires` on the non-existent
  `sys-fs-bpf.mount` unit: the service could never start.
- `ExecStartPre` was in the `[Unit]` section; systemd silently ignored it.
- `ReadWritePaths` pointed at a non-existent directory (226/NAMESPACE).
- Both servers hardcoded `/run/axlinux`; if the socket was placed on another
  path it could not be opened, and it never opened as a normal user.
- The documentation was installed to a non-existent directory (silently,
  with `|| true`).

**Verification tools**

- `make verify` looked for a symbol name in the object; `ax_fill_path`,
  `ax_protected` and `ax_set_port` are inlined because they are
  `__always_inline` and therefore NEVER visible. The check was changed to a
  relocation contract per hook: if a hook is not linked to the maps, it does
  nothing.
- `axctl status` and `axctl logs` crashed: an unclosed tag in rich markup,
  and the audit viewer expected a FLAT row schema from the server while
  axlog's own schema was nested. Even with enforcement running, the
  operator never saw a single record.

### Known limits

- In the exec hook, only `deny` is applied for `file.execute`.
  An allow-list for exec is a security hole; rules that write
  `effect: allow` are silently non-functional.
- Interpreters (python3, node, perl) are deliberately left unprotected:
  when a MAC targets an interpreter, the user can lock themselves out of
  their own session. The audit unit is the program the interpreter runs.

### Additional bugs found during verification

- **`axctl reload --mode` did nothing at all.** The `mode` parameter was
  used only in the `--force-empty` branch; on the normal path the
  "mode: enforcing" in the policy file remained valid. The command printed
  "Loading complete" and the system went on blocking. This is not a
  convenience bug: in an emergency this command is the way to stop
  enforcement. `--mode` is now applied, verified and reported (all three of
  enforcing/permissive/disabled were tested in a VM).
- **The policy was not loaded after a restart**, while `axctl status` showed
  "5/5 hooks active". When there is no rule and the maps are empty, the
  status now gives the warning "NO POLICY: NO RULE IS BEING APPLIED"; if
  rules are loaded but the mode is permissive, a separate warning is also
  issued.
- **The map pinning warning appeared on every reboot.**
  `os.IsExist` returns `false` in this case; the expected state is
  distinguished with `errors.Is(err, os.ErrExist)`. Since pinned maps are
  reused, this is not an error.
- **The indentation of `cli.py` was broken** (the decorator and `def` on
  the same line, inconsistent block indentation). The file never compiled;
  it went unnoticed because `make install` hid the error with
  `>/dev/null 2>&1`. The `reload` function was rewritten.

## 0.1.1 - One-command installation

- `install.sh`: one-command installation. It performs an environment check,
  dependencies, build, installation, service start and **verification**.
  It does not stop at "files copied"; it measures whether the hooks were
  attached and whether the sockets opened.
- `update-grub` writes directly to the bootloader because the Ubuntu cloud
  image does not write `lsm=`. `lsm=` is NOT WRITTEN to the recovery mode
  entry; if the bpf LSM prevents boot, the system is recovered with rescue.
- A `.axlinux-backup` is taken before GRUB is modified. An automatic reboot
  is NOT PERFORMED.
- The installation tool repairs itself: duplicate `bpf` entries in the chain
  are cleaned up, and the same command can be run again.

Verified in a virtual machine (Ubuntu 24.04, kernel 6.8, KVM): fresh
installation 10/10, second run 10/10, post-installation enforcement
file_open rc=37 and bprm rc=1 (control groups rc=0), lockout protection
intact, emergency shutdown rc=0.

Installation script bugs found during testing:
- `/sys/kernel/btf/vmlinux` is a file; because it was checked with `-d`
  (directory) it said "no kernel BTF" and stopped the installation
- `summary()` was defined after the steps; because it was called first it
  returned "command not found"
- `done_step` called with an empty argument made `$2` unbound (the script
  crashed under `set -u`)
- bpf was added again although it was already present in the chain; on the
  second run `lsm=...,bpf,bpf,...` was produced

### Safety guard: verify_all.sh does not run on a physical machine

Note: this is a property of the **test script**, not of the product.
AXlinux itself works on physical machines; only the test harness declines
to apply real enforcement on one.

`tests/verify_all.sh` applies real enforcement. Because enforcement had
only been verified in a virtual machine during development, the script now
refuses to run on a physical machine:

    HATA: fiziksel makine (sanal: none).
    AXLINUX_ALLOW_PHYSICAL=1 tests/verify_all.sh   # bilerek atlamak icin

This guard failed silently twice, and both were fixed:

1. `systemd-detect-virt` PRINTS "none" on a physical machine and **returns
   exit code 1**. Because `$(systemd-detect-virt || echo unknown)` was
   written, `_VIRT` became the two-line "none\nunknown" and did NOT match
   `case "none"`. The guard never triggered.
2. The guard's own regression test ran `verify_all.sh` ON A VIRTUAL
   MACHINE. The script applies enforcement and then pulls the mode to
   "disabled" at the end of the step; in other words, the test broke the
   very thing it was checking. The test now runs a subprocess only on a
   physical machine and is skipped on a virtual machine.

### New regression tests

`tests/test_install_guard.py` (13 tests). It pins down everything that had
previously passed silently or worked incorrectly:

- vmlinux is a file (not `-d`)
- `summary()` is defined before the steps
- `done_step`/`warn_step`/`fail_step` can be called with an empty argument
- the step counter equals the real number of steps (the duplicate `TOTAL`
  definition was removed)
- the LSM chain is idempotent (bpf is not added twice)
- the installation tool does not reboot automatically
- a backup is taken before GRUB is modified
- lsm= is not written to the recovery entry (if boot fails, the recovery
  path stays open)

## 0.1.2 - Cross-distribution test (incomplete, later resolved)

Installation was attempted on Pardus 25.2 and Debian 12. The places where
install.sh, which works on Ubuntu, broke on other distributions were found
and fixed:

- **A single missing package brought down the entire installation.** When
  apt/dnf finds a package that is not on the list (`linux-tools-common` on
  Debian 12 has "no installation candidate") it ABORTS THE OPERATION
  ENTIRELY. Result: no package was installed, the installation stopped with
  "tools that cannot be installed: git" and axctl was not installed at all
  - 69 tests failed. Packages are now installed ONE BY ONE, missing ones
  are skipped.
- **The checked tools were not on the installation list.** `git` counted as
  a required tool but was not passed to the `install_pkgs` call. On Ubuntu
  git was already installed, so the problem was not visible.
- **The apt lock was not waited for.** If cloud-init, unattended-upgrades
  or apt-daily holds the lock, the installation fails silently; the real
  cause is hidden behind the "tools that cannot be installed" message.

### COMPREHENSIVE TEST SUITE

`tests/deep_verify.sh`: 9 sections, CLI commands, learning mode, five LSM
hooks, permanent audit, modes, lockout protection, error paths, policy
language edge cases.

### WORK LEFT OPEN (RESOLVED IN 1.0.0)

- `axctl status` returned an error on Debian 12 -> resolved, 100/0/0.
- The FULL package repository of Pardus could not be installed (the ISO
  `dists/yirmibes-deb/main` = Debian, the real Pardus packages are under
  `contrib` and are empty on the ISO)
  -> resolved by taking packages from the official repository
  (`bilgemdepo.pardus.org.tr`); FULL verification was PERFORMED ON Pardus
  25.2.
## Verification: Ubuntu 24.04 + Debian 12 + REAL Pardus 25.2

The same comprehensive test suite (`tests/deep_verify.sh`,
10 sections / 100 checks) GREEN on three distributions. AXlinux was never
run on the host machine; everything was done in a virtual machine.

| Distribution | Native+Go tests | Comprehensive test | bpf | audit |
|---------|---------------|---------------|-----|-------|
| Ubuntu 24.04.5 | 125 passed | 99/0/0 | 5/5 | healthy |
(installed from source; package verification in the 1.0.0 section)
| Debian 12 (bookworm) | 125 passed | 99/0/0 | 5/5 | healthy |
(installed from source; package verification in the 1.0.0 section)
| Pardus 25.2 (yirmibes) | 125 passed | 99/0/0 | 5/5 | healthy |
(installed from source; package verification in the 1.0.0 section)

Pardus was installed from the official archive: bilgemdepo.pardus.org.tr/pardus
(Origin: Pardus, signed). base-files 13.8+pardus25.2.1 ->
`Pardus GNU/Linux 25.2 (yirmibes)`; pardus-backgrounds,
pardus-bilge-grub-theme, desktop-base installed.

### Real bugs found and fixed in this round

**Learning mode was not collecting anything.** The hooks produced events
only on operations where a DENY rule matched; since normal work is by
definition an ALLOWED operation, none of them produced an event. "axctl
learn start" reported success, printed "records will be kept for 3 days"
and collected zero observations. The new `learn_map` flag and the
observation of allowed operations in five hooks: 0 -> 192 observations.

**THE EMERGENCY RECOVERY PATH did not work.** `axctl reload --force-empty`
is the way for an operator who has locked themselves out with a bad policy
to stop enforcement; because an empty policy was rejected, the command
ITSELF failed. The same validation also broke the "axctl init" + reload
first-installation flow.

**Runtime dependencies were never installed.** click/rich/yaml were not
defined at all; on Ubuntu they were already present thanks to other
packages, on Debian the installation said "working" while throwing
"ModuleNotFoundError".

**/run/axlinux was shared between two services.** axdaemon carried
`RuntimeDirectory=axlinux`; systemd DELETES AND RECREATES the directory when
starting the service, destroying the axlog.sock created one second earlier.
It printed "axlog: active" and audit records went nowhere. The directory has
now been moved to tmpfiles.

**Report suggestions flickered on the screen and corrupted the YAML.** rich
wraps the text according to the screen width, and because one of the
single-line YAML values was close to 82 characters the file was broken
apart; the CLI was telling the user to "paste it into policy.yaml and
verify with policy check".

**Installation made the user's repository impossible to delete.**
`sudo make install` left build output owned by root; `rm -rf axlinux`
returned "Permission denied", and the transfer of the new source silently
did not take place.

**Some errors remained silently ineffective.** A rule written for a
protected process (bash, sudo, sshd...) and a path deeper than 8 produced
only a warning; the policy was loaded, "N rules" was printed, and nothing
was blocked. PolicyError now.

**Netcat was not installed anywhere.** It is the only test tool used by the
socket_connect and socket_bind hooks; on Pardus it was absent and two
network hooks were skipped.

**Daemon errors showed the user a raw Python dictionary.**
`Daemon hatası: {'code': -32000, 'message': '...'}`. In addition "already
active" is not an infrastructure error but an application-level rejection;
yet it exited with code 4.

### CLI gaps were closed

- `policy check` / `policy simulate` now accept `--file/-f`: a candidate
  policy can be validated BEFORE it is applied
- `logs`: `--json`, `--subject`, `--action`, `--effect` added
- `label rm` added (previously a label could be added but not removed)
- `init` completes a half-installation (directory exists, no policy)
- `reload` returns 2 when the policy file is missing (correct code)
- The exit code scheme is documented in the code: 0/1/2/4/5