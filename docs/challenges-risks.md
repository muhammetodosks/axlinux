# AXlinux Challenges and Risks

## Critical Risk: System Lockout

**This is AXlinux's most dangerous failure mode, and it is sealed shut by design.**

If a rule is applied to a critical process such as `bash`, `sudo`, `sshd`
or `systemd`, the system locks itself: every child process of that process
is blocked, the session is terminated and the user can no longer reach the
system. Recovery from a shell is impossible; only a physical reboot will do.

**Countermeasure** (`ax_protected`, `src/bpf/axbpf.h`):

The following processes are **subject to no rule at all**; programs return
`0` for them directly. Even if a policy says "bash must not run /bin/echo":

- `bash`, `sh`, `dash`, `zsh`, `fish` — the user session stays open
- `sudo`, `su`, `doas` — the mode can still be changed and intervened with
- `sshd`, `login`, `agetty` — remote/local connection remains possible
- `systemd`, `dbus-daemon`, `polkitd`, `NetworkManager` — the session and
  the network keep working

The list is **deliberately short**: it covers the **recovery path** only.
Every candidate has to pass this question:

> "If I block it, can I still reach the system again?" → if no, it is kept.

Why this question is sufficient on its own: **language runtimes are not
protected.** `python3`, `node`, `perl`, `ruby`, `npm` are not on the list.

Because most real applications run from an interpreter. Protecting them
would make it impossible to write the rules MAC systems are used for most
often — such as "python3 cannot read /etc/shadow" or "node cannot reach
the network" — and the product would become unusable. And the gain would
be zero: blocking an interpreter creates **no lockout**, because the user
already has a protected shell.

By the same token, applications such as `firefox`, `nginx` and `curl` are
not on the list either — they are targets in the first place.

**Verification**: `tests/test_protection.py` audits protected and
must-not-be-protected processes statically (in both directions);
`tests/verify_all.sh` proves it live in step 8.

**When writing a policy**: writing a process name such as `bash`, `sudo`
or `systemd` into the `subject` field **fails at load time with an error**;
the rule is not written at all. Writing an interpreter such as `python3` is
normal and the rules are enforced.

## Technical Challenges

### 1. eBPF LSM Requirements

**Challenge**: Requires `CONFIG_BPF_LSM=y` and kernel 5.15+.

**Solution**:
- Graceful fallback on kernel < 5.15: "AXlinux is running in audit mode only"
- Distribution-based pre-check: step 2 (environment audit) of `bash install.sh` and `axctl status`
- **Verified builds: Fedora 41, 42, 43, 44.** For Debian 12 and
  Ubuntu 24.04 the `.deb` package was actually installed and run.
  Evidence and details: [`SUPPORT.md`](../SUPPORT.md)
- **CAUTION:** This file previously stated "Ubuntu 22.04+, Fedora 35+,
  Debian 12+ are supported". Measurements were taken and the verified
  table is **Fedora 41–44** together with Ubuntu 24.04 / Debian 12.
  There is **no** build evidence for 35–40; they must not be added to the
  list of supported versions on the basis of an estimate.
- Installation looks at capability, not at the version **number**: whether
  BTF is present, whether `bpf` is in the LSM chain. If the capability is
  there, the version number is irrelevant.

**Risk**: Does not work on older distributions.

### 2. eBPF Map Size

**Challenge**: eBPF maps have a limited size (typically ~16MB).

**Solution**:
- Store only the active policy (not the whole system)
- Use LRU maps (evict the least recently used)
- Policy compression (gzip)

**Risk**: Very large policies (~10K+ rules) may not fit.

### 3. Process Name Collision

**Challenge**: `comm` is only 16 characters. `google-chrome` → `google-chrome` (exact), `nginx: worker` → `nginx`.

**Solution**:
- Prefix matching
- PID tracking (temporary)
- Alternative to labels: executable path (`/usr/bin/python3`)

**Risk**: Wrong process is matched.

### 4. Path Resolution

**Challenge**: Path resolution in eBPF is hard. The `~/.ssh` → `/home/user/.ssh` conversion cannot be performed in the kernel.

**Solution**:
- Pre-processing on the user side: `~` → home directory
- Prefix matching only in eBPF
- `realpath()` syscall hook (future)

**Risk**: Symbolic links and `..` path components may be skipped.

### 4.1. `bpf_d_path` Is Unusable (critical)

**Symptom**: Build and load succeed, 5/5 hooks are attached, the daemon
reports `enforcement_active: true` and says "1 rule loaded" — but **no
path rule ever matches**, and the audit log is empty.

**Root cause**: `bpf_d_path` is unusable in this project. libbpf 1.3.0
declares it as a global function pointer; when compiled as a call into
BPF, the write to the destination buffer **lands in two places at once**:

- at the correct offset (the path field)
- at a second location **242 bytes further on**

Result: `comm` and `action` are correct, the `path` field is garbage → the
hash never matches. The rule appears to be "loaded" but nothing is
blocked. This is the worst possible failure form in a MAC system:
**silent failure**.

The evidence was obtained by comparing, byte by byte, the 276 bytes
produced by the kernel with the 276 bytes written by Go; the two texts
looked identical (`comm=cat`, `path=/etc/hostname`) but the raw bytes
diverged from offset 242 onwards.

**Solution** (`ax_fill_path`, `src/bpf/axbpf.h`): the path field is split
into 8 fixed blocks (`char path[8][32]`), and each component is written to
its own block. Splitting and joining are performed on the Go side. The
total key size does not change: 16 + 8×32 + 4 = **276 bytes**.

**Design rules** (know these before you break this solution):

1. **Destination and size must be constant.** For
   `bpf_probe_read_kernel(dst, len, src)`, if `dst` and `len` are constant
   at compile time the verifier sees the bound. `dst[pos]` computed at
   runtime is rejected.
2. **Both passes must be unrolled.** With a runtime loop the verifier
   re-validates the loop body for every iteration; 63 × program size
   exceeds the 1M instruction limit. Nested unrolling, in turn, exceeds
   the 512 byte stack limit.
3. **Do not use `bpf_probe_read_kernel_str`.** It contains a hidden
   256-step unroll internally; called once per slot it inflates the
   program 40-fold. Fixed-size `bpf_probe_read_kernel` plus a manual NUL
   does the same job.
4. **The root component is not written.** The Go side does not generate
   root content, and neither does the eBPF side; otherwise `"//"` appears
   in block 0 and the keys do not match.
5. **No external pointer writes after `bpf_map_lookup_elem`.**
   The verifier marks the pointer as "unbounded". That is why the audit
   fields are populated **before** the map lookup.

**Contract lock**: the sizes of `struct policy_key` and `struct audit_event`
are computed independently on the C side and compared against the Go struct
(`internal/maps/contract_test.go`, `internal/audit/audit_test.go`). These
tests recognise both the flat (256 byte) and the blocked (8×32) array
layouts.

### 5. Performance

**Challenge**: An eBPF map lookup on every system call.

**Solution**:
- LRU cache map
- First-hit short-circuit
- Per-CPU maps (lock-free)

**Risk**: ~1-3% overhead is acceptable.

### 6. Audit Log Explosion

**Challenge**: Thousands of denies per hour in enforcing mode.

**Solution**:
- Rate limiting (max 1 log/sec per rule)
- Aggregate logging (same rule+object → one log entry)
- Ring buffer (last 10K records)

**Risk**: The log fills the disk.

## Security Challenges

### 7. User Error

**Challenge**: The user locks themselves out.

**Solution**:
- Simulate mode (always free)
- `axctl mode disabled` always works
- `axctl reload --force-empty` as emergency exit
- Config backup (before every reload)

**Risk**: The user can render the system unbootable.

### 8. eBPF Program Safety

**Challenge**: eBPF programs run inside the kernel core.

**Solution**:
- Verifier (the eBPF verifier already exists)
- Minimal C, LSM hooks only
- `CAP_BPF` privilege required

**Risk**: If the eBPF program has a bug, the kernel panics.

### 9. Privilege Escalation

**Challenge**: Root bypasses everything.

**Solution**:
- AXlinux is only meaningful for non-root users
- Audit logging only for root
- Without `CAP_BPF` the policy cannot be loaded

**Risk**: Root bypasses AXlinux.

### 10. Policy Integrity

**Challenge**: If the user modifies the policy file, AXlinux cannot detect it (after a reload).

**Solution**:
- Policy file hash (checked on every reload)
- Signature verification (future)
- Read-only policy file (optional)

**Risk**: The user can change their own policy and reload it (but that is already their own responsibility).

## Operational Challenges

### 11. Wrong Suggestion from Learning Mode

**Challenge**: 3 days of learning may suggest a wrong policy.

**Solution**:
- A suggestion is always a "suggestion", it is never applied automatically
- It is applied when the user approves it
- Developer mode: permissive + logging

**Risk**: A wrong suggestion can lead the user astray.

### 12. Compatibility

**Challenge**: Conflicts with existing SELinux/ApArmor policies.

**Solution**:
- AXlinux enforces only its own policy
- It can work alongside other MAC systems (stacked)
- Migration tool: SELinux → AXlinux (future)

**Risk**: Two MAC systems can work together, but complexity increases.

### 13. Distribution

**Challenge**: Installation, kernel module, daemon, CLI.

**Solution**:
- Single binary (axctl + axdaemon)
- `apt install axlinux` or `dnf install axlinux`
- systemd unit: `axdaemon.service`

**Risk**: Distribution-specific differences.

## Restrictions (1.0.0)

This table lists **what actually works in 1.0.0**. It was previously
labelled with version numbers, and once the version was 1.0.0 that left
the wrong impression: the table said "user-based rule ✗ 1.0" while we
were already at 1.0.0.

| Feature | Status | Note |
|---------|-------|-----|
| File hook | ✓ | `file_open`, `inode_permission` |
| exec hook | ✓ | `bprm_check_security` |
| Network hook | ✓ | `socket_connect`, `socket_bind` |
| Signal hook | ✗ | absent, no LSM counterpart is attached |
| `net.accept` | ✗ | `socket_accept` hook is not attached |
| `file.delete` / `file.create` | ✗ | no delete/create hook |
| User-based rule | ✗ | a rule speaks in terms of the **process** name, not the user |
| Time/condition rule | ✗ | the policy language contains no conditions |
| Container scope | ✗ | scope is system-wide |
| Graphical interface | ✗ | CLI and YAML; no GUI |
| Signed policy distribution | ✗ | single policy source: your own file |

## Acceptable Risks

1. **eBPF overhead**: ~1-3% — acceptable
2. **Limited map size**: ~10K rules — sufficient
3. **Root bypass**: acceptable (root can already do anything)
4. **Kernel 5.15+ requirement**: acceptable (most distributions as of 2026)

## Unacceptable Risks

1. **Kernel panic**: an eBPF program must never cause a kernel panic.
2. **Data loss**: AXlinux never deletes data.
3. **Backdoor**: there must be no backdoor in AXlinux.
4. **Policy signing**: the user must always be able to change their own policy.