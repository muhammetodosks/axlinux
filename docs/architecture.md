# AXlinux Architecture Document

## Philosophy

**You write YAML, AXlinux enforces it.**

In SELinux the policy is handed to you and you adapt to it. In AXlinux the
policy belongs to you and you write it. Security should be in the user's
hands.

## Layers

```
┌─────────────────────────────────────────────────────────┐
│ USER                                                    │
│ ~/.axlinux/policy.yaml                                  │
└────────────────────────────┬────────────────────────────┘
                              YAML
└────────────────────────────▼────────────────────────────┘
│ axctl (Python CLI)                                      │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌─────────────┐   │
│  │init     │ │check    │ │simulate  │ │reload       │   │
│  └─────────┘ └─────────┘ └──────────┘ └─────────────┘   │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌─────────────┐   │
│  │status   │ │logs     │ │learn     │ │label        │   │
│  └─────────┘ └─────────┘ └──────────┘ └─────────────┘   │
└────────────────────────────┬────────────────────────────┘
                              compile
└────────────────────────────▼────────────────────────────┘
│ axc (Python Compiler)                                   │
│ YAML -> Validation -> Internal Policy Format (JSON)     │
└────────────────────────────┬────────────────────────────┘
                              JSON-RPC / Unix socket
└────────────────────────────▼────────────────────────────┘
│ axdaemon (Go)                                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │ eBPF Map Manager                                │    │
│  │   ┌──────────┐ ┌──────────┐ ┌──────────────┐    │    │
│  │   │ allow_map│ │ deny_map │ │ audit_map    │    │    │
│  │   └──────────┘ └──────────┘ └──────────────┘    │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │ Audit Service (axlog)                           │    │
│  └─────────────────────────────────────────────────┘    │
└────────────────────────────┬────────────────────────────┘
                              BPF syscall
└────────────────────────────▼────────────────────────────┘
│ axbpf (C) - eBPF LSM programs                           │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐   │
│  │file_open     │ │inode_perm    │ │bprm_check_sec  │   │
│  └──────────────┘ └──────────────┘ └────────────────┘   │
│  ┌───────────────┐ ┌───────────────┐                    │
│  │socket_connect │ │socket_bind    │                    │
│  └───────────────┘ └───────────────┘                    │
└─────────────────────────────────────────────────────────┘
                            │
└────────────────────────────▼────────────────────────────┘
│ Linux kernel (5.15+, CONFIG_BPF_LSM=y)                  │
└─────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Authoring and Applying a Policy

```
User → ~/.axlinux/policy.yaml
    ↓
axctl policy check
    ↓
axc compile
    ↓
Validation (schema, conflicts, security check)
    ↓
Internal policy format (JSON)
    ↓
axdaemon (JSON-RPC / Unix socket)
    ↓
Writes to the eBPF maps
    ↓
The eBPF LSM programs now make the decisions
```

### 2. Runtime Decision Flow

```
System call (open, connect, bind, ...)
    ↓
An eBPF LSM hook fires
    ↓
Lookup in the eBPF maps
    ↓
Present in allow_map → ALLOW
Present in deny_map  → DENY + audit log
Present in neither   → DEFAULT (generally ALLOW)
    ↓
The decision returns to the kernel
```

### 3. Audit Log Flow

```
eBPF program → perf buffer
    ↓
axlog (Go) → log in JSON format
    ↓
/var/log/axlinux/audit.json
    ↓
axctl logs → human-readable format for the user
```

## Component Details

### axctl (Python CLI)

The user's single point of contact. All commands:

| Command | Description |
|---------|-------------|
| `axctl init` | Creates the `~/.axlinux/` directory and an empty policy.yaml |
| `axctl policy edit` | Opens policy.yaml in the default editor |
| `axctl policy check` | YAML syntax and schema validation |
| `axctl policy simulate` | "What does this YAML affect?" simulation |
| `axctl reload` | Compiles the policy and forwards it to axdaemon |
| `axctl status` | System status, active policy, eBPF state |
| `axctl logs` | Reads and filters the JSON audit log |
| `axctl learn start` | Starts learning mode |
| `axctl learn report` | Shows the 3-day learning report |
| `axctl label` | File/process labelling helper |

### axc (Python Compiler)

Converts YAML into the internal policy format:

1. **Parse**: YAML → Python dict
2. **Validate**: Schema validation, conflict detection
3. **Compile**: Python dict → JSON (internal policy format)
4. **Sign**: Optionally signs the policy (future)

### axdaemon (Go)

The always-running system daemon:

1. **Policy Loader**: Parses the JSON coming from axc
2. **Map Manager**: Writes to / updates the eBPF maps
3. **LSM Hook Manager**: Loads and attaches the eBPF programs
4. **Audit Service**: Produces the audit log via axlog
5. **JSON-RPC server**: Communicates with axctl

### axbpf (C)

The eBPF LSM programs — minimal C:

- `file_open`: File open check
- `inode_permission`: inode access check
- `bprm_check_security`: execve check
- `socket_connect`: Connection check
- `socket_bind`: Bind check

Every program follows the same pattern:
1. Get the PID or comm (process name)
2. Look it up in the eBPF maps
3. Decide (ALLOW/DENY)
4. Write an audit log entry

### axlog (Go)

The JSON audit log service:

- Reads from the eBPF perf buffer
- Writes logs in JSON format
- Filtering and query API
- Log rotation

## Modes

| Mode | Description |
|------|-------------|
| `enforcing` | Policies are enforced, violation = block + log |
| `permissive` | Policies are enforced, violation = log only |
| `disabled` | No policy is enforced |

Instant switching: `axctl reload --mode=enforcing`

## Security Principles

1. **No default deny**: Anything the user does not write is allowed. Do not
   lock the user out of their own AXlinux installation.
2. **Simulation is always free**: `axctl policy check` and `simulate` always
   work, before the policy is loaded.
3. **Auditing is always on**: Logs are kept at least in permissive mode.
4. **The user can always get out**: `axctl reload --mode=disabled` always
   works.
5. **Policy signing (future)**: Community policies will be signed to
   establish trust.

## SELinux vs AXlinux

| Aspect | SELinux | AXlinux |
|--------|---------|---------|
| Policy source | Ready-made, millions of lines | User YAML |
| Learning | `audit2allow` | `axctl learn` → 3 days → suggestion |
| Application | `setenforce` + reboot risk | `axctl reload` → instant |
| Log format | `audit.log` (text) | JSON, structured |
| Learning curve | Wall | Stairs |
| Philosophy | You adapt | You write |