# AXlinux Component Design

## 1. axctl — Python CLI

The user's single point of contact. Based on Click/Typer, with coloured
output.

### Commands

```
axctl init
axctl policy edit
axctl policy check
axctl policy simulate
axctl reload
axctl status
axctl logs [--follow] [--filter ACTION] [--since TIME]
axctl learn start
axctl learn stop
axctl learn report
axctl label ls
axctl label add NAME PROCESS
axctl mode enforcing|permissive|disabled
axctl version
```

### Technical Details

- **Language**: Python 3.10+
- **Dependencies**: `click`, `rich`, `pyyaml`
- **Location**: `/usr/bin/axctl`
- **Communication**: Unix socket with axdaemon (`/run/axlinux/axdaemon.sock`)

### init

```bash
$ axctl init

Initialising AXlinux...
~/.axlinux/ created
~/.axlinux/policy.yaml created (empty policy, system unrestricted)
~/.axlinux/audit/ created
Mode: enforcing (empty policy = no restriction)

Ready. Write your policy with axctl policy edit.
```

### policy check

```bash
$ axctl policy check

✓ YAML syntax is valid
✓ Schema validation succeeded
✓ 5 rules, 3 labels found
✓ Applicability check: 5 rules
✓ No conflicts
✓ Priority ordering complete

Policy is valid. Apply it with axctl reload.
```

### policy simulate

```bash
$ axctl policy simulate

Policy Simulation
=================

Mode: enforcing
Total rules: 5
Labels: 3

[1] nginx may not read the shadow file
    subject: nginx, apache2, caddy
    object: /etc/shadow
    action: file.read
    effect: DENY
    ⚠ Specific rule, evaluated after [5]

Conflicts: None
```

### reload

```bash
$ axctl reload

Compiling policy...
✓ 5 rules, 3 labels
✓ Written to the eBPF maps
✓ LSM hooks updated

Load complete. Mode: enforcing
```

### status

```bash
$ axctl status

AXlinux Status
==============

Mode: enforcing
Uptime: 3 hours 24 minutes
Active policy: 5 rules, 3 labels
eBPF programs: 5/5 loaded
LSM hooks: 5/5 active
Last reload: 2 minutes ago

Audit log: 1.247 records (last 24 hours)
  deny: 23
  allow: 1.224
```

### logs

```bash
$ axctl logs --follow --filter deny

{"timestamp": "2026-09-27T14:23:01Z", "mode": "enforcing", "subject": "firefox", "object": "~/.ssh/id_rsa", "action": "file.read", "effect": "deny", "pid": 12345, "decision": "denied"}
{"timestamp": "2026-09-27T14:23:05Z", "mode": "enforcing", "subject": "nginx", "object": "/etc/shadow", "action": "file.read", "effect": "deny", "pid": 12346, "decision": "denied"}
```

### learn

```bash
$ axctl learn start

Learning mode started.
The system will be observed for 3 days.
After 3 days you can see the suggestions with axctl learn report.

Tip: during learning mode, carry on as usual. AXlinux will learn your habits.
```

---

## 2. axc — Python Compiler

```
axc compile policy.yaml → policy.json
axc validate policy.yaml → errors[]
axc simulate policy.yaml → simulation_result
```

### Stages

1. **Parse**: YAML → Python dict
2. **Validate**: Schema, conflicts, security check
3. **Normalize**: Expand the labels, order by priority
4. **Compile**: Python dict → JSON (internal policy format)
5. **Sign** (future): Optional signature

### Internal Policy Format

```json
{
  "version": 1,
  "mode": "enforcing",
  "labels": {
    "web_servers": ["nginx", "apache2", "caddy"]
  },
  "rules": [
    {
      "id": "rule_001",
      "name": "nginx may read web content",
      "subject": ["nginx", "apache2", "caddy"],
      "object": "/var/www",
      "action": "file.read",
      "effect": "allow",
      "port": null,
      "priority": 80
    }
  ]
}
```

---

## 3. axdaemon — Go Daemon

An always-running system service.

### Responsibilities

| Module | Description |
|--------|-------------|
| `policy` | Parses the JSON coming from axc |
| `maps` | Writes to / updates the eBPF maps |
| `lsm` | Loads and attaches the eBPF programs |
| `audit` | Produces the audit log via axlog |
| `server` | Unix socket / JSON-RPC server |
| `mode` | enforcing/permissive/disabled transitions |

### Go Package Layout

```
axdaemon/
├── cmd/axdaemon/main.go
├── internal/
│   ├── server/       # JSON-RPC over Unix socket
│   ├── policy/       # Policy loading and management
│   ├── maps/         # eBPF map manager
│   ├── lsm/          # LSM hook management
│   ├── audit/        # Audit log generation
│   └── mode/         # Mode transitions
└── pkg/
    └── protocol/     # request/response types
```

### Start-up Order

1. Load the eBPF programs (`axbpf.o`)
2. Attach the LSM hooks
3. Load the existing policy (if any)
4. Listen on the Unix socket
5. Start the axlog service
6. Apply the mode (default: enforcing)

---

## 4. axbpf — C eBPF Programs

Minimal C. Every program follows the same pattern:

```c
// file_open hook
SEC("lsm/file_open")
int BPF_PROG(file_open_hook, struct file *file)
{
    // 1. Get the PID and comm
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 2. Look it up in the eBPF maps
    // present in allow_map → ALLOW
    // present in deny_map  → DENY + audit

    // 3. Decide
    return 0; // ALLOW
    // return -EPERM; // DENY
}
```

### Hooks

| Hook | LSM Hook | Scope |
|------|----------|-------|
| `file_open` | `lsm/file_open` | File open |
| `inode_permission` | `lsm/inode_permission` | inode access |
| `bprm_check_security` | `lsm/bprm_check_security` | execve |
| `socket_connect` | `lsm/socket_connect` | Connection |
| `socket_bind` | `lsm/socket_bind` | Bind |

### eBPF Maps

| Map | Type | Content |
|-----|------|---------|
| `allow_map` | Hash | PID/comm → permitted operations |
| `deny_map` | Hash | PID/comm → blocked operations |
| `audit_map` | Perf Buffer | Audit log records |

---

## 5. axlog — Go Audit Service

### Format

```json
{
  "timestamp": "2026-09-27T14:23:01.123456789Z",
  "type": "audit",
  "mode": "enforcing",
  "hook": "file_open",
  "subject": {
    "pid": 12345,
    "comm": "firefox",
    "label": "browsers"
  },
  "object": {
    "path": "/home/user/.ssh/id_rsa",
    "inode": 123456
  },
  "action": "file.read",
  "effect": "deny",
  "decision": "denied",
  "rule_id": "rule_002",
  "rule_name": "firefox may not see ssh keys"
}
```

### Features

- JSON Lines format (`.jsonl`)
- Log rotation (daily, 10MB)
- Filtering API
- `--follow` support (like `tail -f`)

---

## 6. Template Manager

```
axctl template ls
axctl template apply minimal
```

Templates are predefined policy patterns:

- `minimal`: Protection for /etc/shadow only
- `web-server`: Full protection for Nginx/Apache
- `desktop`: Sensible defaults for the desktop
- `database`: Network protection for Postgres/MySQL

---

## 7. Community and Signing (FUTURE FEATURE — not present yet)

```
axctl trust add https://github.com/user/axpolicy
axctl policy install user/nginx-hardened
axctl policy verify user/nginx-hardened
```

Community policies provide trust through signing. AXlinux accepts unsigned
policies with a warning.