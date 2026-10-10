# AXlinux CLI Reference

## General Usage

```
axctl <command> [options]
```

## Commands

### init

Initialises AXlinux. Creates the `~/.axlinux/` directory and an empty policy
file.

```bash
axctl init [--force]
```

| Option | Description |
|--------|-------------|
| `--force` | Resets the existing directory |

### policy edit

Opens the policy file in the default editor.

```bash
axctl policy edit [--editor EDITOR]
```

| Option | Description |
|--------|-------------|
| `--editor` | Editor to use (nano, vim, code) |

### policy check

Validates the policy.

```bash
axctl policy check [--file FILE]
```

| Option | Description |
|--------|-------------|
| `--file` | Validate this file instead of the active policy |

**Output**:
- ✓ YAML syntax is valid
- ✓ Schema validation succeeded
- ✓ N rules, M labels found
- ✓ Applicability check: N rules
- ✓ No conflicts

### policy simulate

Simulates what the policy affects.

```bash
axctl policy simulate [--format text|json] [--file FILE]
```

| Option | Description |
|--------|-------------|
| `--format` | Output format |
| `--file` | Simulate this file instead of the active policy |

### reload

Compiles and applies the policy.

```bash
axctl reload [--mode MODE] [--force-empty]
```

| Option | Description |
|--------|-------------|
| `--mode` | enforcing, permissive, disabled |
| `--force-empty` | Load an empty policy (emergency escape hatch) |

### status

Shows the system status.

```bash
axctl status [--json]
```

### logs

Reads the audit log.

```bash
axctl logs [--follow] [--filter FIELD=VALUE] [--since TIME] [--limit N]
```

| Option | Description |
|--------|-------------|
| `--follow` | Live tail (like `tail -f`) |
| `--filter` | Filter (action=file.read, effect=deny) |
| `--since` | Since a point in time (1h, 1d, 1w) |
| `--limit` | Maximum number of records (default: 100) |
| `--json` | Raw JSON output |
| `--subject` | Filter by process name (e.g. curl) |
| `--action` | Filter by action (e.g. file.read) |
| `--effect` | Filter by effect (allow/deny) |

### learn start

Starts learning mode.

```bash
axctl learn start [--days N]
```

| Option | Description |
|--------|-------------|
| `--days` | Learning duration in days (default: 3) |

### learn stop

Stops learning mode.

```bash
axctl learn stop
```

### learn report

Shows the learning report.

```bash
axctl learn report [--format text|json]
```

### label ls

Lists the labels.

```bash
axctl label ls
```

### label add

Adds a label.

```bash
axctl label add LABEL PROCESS
```

### label rm

Removes a label. This is the way to remove a label without editing the
policy file by hand.

```bash
axctl label rm NAME
```

It returns an error on a non-existent label; it does not say "deleted" and
silently continue.

### mode

Changes the mode.

```bash
axctl mode enforcing|permissive|disabled
```

### template ls

Lists the templates.

```bash
axctl template ls
```

### template apply

Applies a template.

```bash
axctl template apply NAME
```

### version

Shows version information.

```bash
axctl version
```

## Exit Codes

Scripts rely on these codes.

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage error, or a request the daemon rejected at application level (e.g. "learning mode is already active") |
| 2 | Policy error — missing file, malformed YAML, schema violation |
| 3 | Not used |
| 4 | Infrastructure error — no socket, cannot connect, axdaemon is down |
| 5 | Configuration or template error |

The distinction between 1 and 4 is operationally important: 4 means "check
the machine", 1 means "fix the command".

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AXLINUX_HOME` | AXlinux directory (default: ~/.axlinux) |
| `AXLINUX_SOCKET` | Path to the axdaemon socket (default: /run/axlinux/axdaemon.sock) |

## Configuration

`~/.axlinux/config.yaml`:

```yaml
# AXlinux configuration
editor: vim
log_level: info
mode: enforcing
auto_reload: false
backup_count: 10
```

---

## Commands not yet implemented

The following are **not runnable**. This document used to list them as
ordinary commands; the user typed the command and got "No such command".
Their status is now stated explicitly.

| Command | Status | Note |
|---------|--------|------|
| `axctl trust add URL` | Absent | Trust for remote policy sources (signature key management). `docs/roadmap.md` |
| `axctl policy install NAME` | Absent | Download a policy from the community |
| `axctl policy verify NAME` | Absent | Policy signature verification |
| `axctl policy use NAME` | Absent | Activate a downloaded policy |

These four commands require remote code execution and signature
verification. A half-implemented security feature (fetching unsigned
policies) is **worse than having no such feature at all**, so they were
deliberately not implemented. There is currently a single policy source:
your own `~/.axlinux/policy.yaml` file.

Every command in this CLI reference is automatically audited against the
CLI itself (`tests/test_docs.py`). When a command is added here, it must
also exist in the CLI.