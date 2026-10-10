# AXlinux YAML Policy Language

## Philosophy

**You write YAML, AXlinux enforces it.**

A policy is a plain, readable, first-class YAML file. AXlinux has no hidden
syntax and no intermediate language. Whatever you write is what gets enforced.

## File Location

```
~/.axlinux/policy.yaml
```

## Syntax

```yaml
# AXlinux policy file
# You write, AXlinux enforces.

version: 1

# Mode: enforcing | permissive | disabled
mode: enforcing

# Labels: process/file groups
labels:
  web_servers:
    - nginx
    - apache2
    - caddy
  browsers:
    - firefox
    - chromium
    - google-chrome
  databases:
    - postgres
    - mysql
    - redis-server

# Rules
rules:
  # File access
  - name: "nginx may read web content"
    subject: web_servers
    object: /var/www
    action: file.read
    effect: allow

  - name: "nginx may not read the shadow file"
    subject: web_servers
    object: /etc/shadow
    action: file.read
    effect: deny

  - name: "firefox may not see ssh keys"
    subject: browsers
    object: ~/.ssh
    action: file.read
    effect: deny

  # Network access
  - name: "python may not connect to port 443"
    subject: python
    action: net.connect
    port: 443
    effect: deny

  - name: "redis-server may only bind to port 6379"
    subject: redis-server
    action: net.bind
    port: 6379
    effect: allow

  # Process exec
  - name: "nginx may not run bash"
    subject: web_servers
    action: process.exec
    object: /bin/bash
    effect: deny
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Policy format version (currently 1) |
| `mode` | No | Default: `enforcing` |
| `labels` | No | Process groups |
| `rules` | Yes | List of rules |

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Rule description (human readable) |
| `subject` | Yes | Who? (label or single process name) |
| `object` | No | What? (file, directory, process) |
| `action` | Yes | What is it doing? |
| `effect` | Yes | `allow` or `deny` |
| `port` | No | Port number (required for `net.connect` / `net.bind`) |

## Actions

The following table lists the actions that are **actually enforced**. Each
one has at least one LSM hook behind it; that hook produces the key and
returns the decision.

| Action | Description | LSM Hook | Path-based? |
|--------|-------------|----------|-------------|
| `file.read` | File read | `file_open` | Yes |
| `file.write` | File write | `file_open` | Yes |
| `file.execute` | File execute | `bprm_check_security` | Yes |
| `net.connect` | Outbound connection | `socket_connect` | No (port) |
| `net.bind` | Port listening | `socket_bind` | No (port) |
| `process.exec` | Process execute | `bprm_check_security` | No (process) |

The `inode_permission` hook additionally enforces **process-based**
`file.read` / `file.write` / `file.execute` rules (object left empty).

### Actions that are not yet supported

If these actions are written into a policy, `axctl` raises an **explicit
error**. Accepting them and letting them sit there inertly is the most
dangerous condition in a MAC system: the rule says "loaded" and nothing
ever happens.

| Action | Status | What to use instead |
|--------|--------|---------------------|
| `file.delete` | No hook | File system permissions (`chmod`, ACL) |
| `file.create` | No hook | Directory permissions (`chmod`) |
| `net.accept` | No hook | Audit on the listener side |
| `process.signal` | Not a valid action | — |

Deletion auditing requires the `lsm/inode_unlink_at` hook. This is a known
and documented shortcoming of AXlinux; it is not a surprising error but an
explicit scope boundary.

### Protected processes

AXlinux enforces **no** rule that targets a recovery-path process: `sshd`,
`login`, `sudo`, `bash`, `systemd` and similar. Such a rule would let the
policy lock the operator out of the machine, so the compiler rejects it at
compile time with an explicit error. Write rules against the applications
you want to control (`nginx`, `firefox`, `redis-server`, `curl`) instead.

## Labels

Labels define process groups. A single rule can cover many processes.

```yaml
labels:
  web_servers:
    - nginx
    - apache2
    - caddy
```

Usage:

```yaml
rules:
  - name: "web servers may not read /etc/shadow"
    subject: web_servers
    object: /etc/shadow
    action: file.read
    effect: deny
```

## Priority Rules

1. **Deny always comes before allow.** Even if the user writes it the other
   way around, deny wins.
2. **A specific rule comes before a general rule.** A rule for `/etc/shadow`
   is evaluated before a rule for `/etc`.
3. **At the same priority, the rule written last wins.**

## Simulation

`axctl policy simulate` shows what the policy affects:

```
$ axctl policy simulate

Policy Simulation
=================

Mode: enforcing
Total rules: 6
Labels: 3

[1] nginx may not read the shadow file
    subject: nginx, apache2, caddy
    object: /etc/shadow
    action: file.read
    effect: DENY

[2] nginx may not run bash
    subject: nginx, apache2, caddy
    object: /bin/bash
    action: process.exec
    effect: DENY

[3] firefox may not see ssh keys
    subject: firefox, chromium, google-chrome
    object: ~/.ssh
    action: file.read
    effect: DENY

[4] python may not connect to port 443
    subject: python
    action: net.connect
    port: 443
    effect: DENY

[5] nginx may read web content
    subject: nginx, apache2, caddy
    object: /var/www
    action: file.read
    effect: ALLOW

[6] redis-server may only bind to port 6379
    subject: redis-server
    action: net.bind
    port: 6379
    effect: ALLOW

Conflicts: None
```

## Example Policies

### Minimal Security

```yaml
version: 1
mode: enforcing

rules:
  - name: "browsers may not read ssh keys"
    subject: firefox
    object: ~/.ssh
    action: file.read
    effect: deny

  - name: "browsers may not read /etc/shadow"
    subject: firefox
    object: /etc/shadow
    action: file.read
    effect: deny
```

### Web Server

```yaml
version: 1
mode: enforcing

labels:
  web:
    - nginx
    - apache2

rules:
  - name: "web servers read web content"
    subject: web
    object: /var/www
    action: file.read
    effect: allow

  - name: "web servers may not read /etc/shadow"
    subject: web
    object: /etc/shadow
    action: file.read
    effect: deny

  - name: "web servers may not run bash"
    subject: web
    action: process.exec
    object: /bin/bash
    effect: deny

  - name: "web servers bind port 80"
    subject: web
    action: net.bind
    port: 80
    effect: allow

  - name: "web servers bind port 443"
    subject: web
    action: net.bind
    port: 443
    effect: allow
```

### Advanced

```yaml
version: 1
mode: permissive

labels:
  web:
    - nginx
    - apache2
  db:
    - postgres
    - mysql
  cache:
    - redis-server

rules:
  - name: "web servers read web content"
    subject: web
    object: /var/www
    action: file.read
    effect: allow

  - name: "web servers may connect to postgres"
    subject: web
    action: net.connect
    port: 5432
    effect: allow

  - name: "databases may not connect to port 5432"
    subject: db
    action: net.connect
    port: 5432
    effect: deny

  - name: "redis listens only on localhost"
    subject: cache
    action: net.bind
    port: 6379
    effect: allow

  - name: "nobody may read /etc/shadow"
    subject: "*"
    object: /etc/shadow
    action: file.read
    effect: deny
```

## Limitations

1. **Wildcard only for `subject: "*"`.** There is no object wildcard.
2. **No regex.** Full paths only.
3. **No time-based rules.** (May be added in v2.0)
4. **No user-based rules.** (May be added in v1.0)
5. **No dynamic policy.** Every change requires `axctl reload`.
6. **`port` and `object` are mutually exclusive.** A network rule uses
   `port`, a file rule uses `object`.

## Path rules: full path and mount points

> **DIRECTORY RULES DO NOT WORK — `object:` IS TREATED AS A FULL PATH.**
>
> The policy language called it "prefix" in older texts. That is a
> contract violation and it was not fixed:
>
>   object: /home/u/.gnupg, action: file.read, effect: deny
>   cat /home/u/.gnupg/secret.gpg   ->  ALLOWED   (leak)
>
> **Why:** the key code is aligned to the END of the path. A rule for
> `/a/b` is written as `[6]/a [5]/b`, whereas the runtime path `/x/y/a/b`
> becomes `[7]/x [6]/y [5]/a [4]/b`. For a shorter path to be able to use
> the same blocks, the blocks must be SHIFTED on the BPF side. Writing
> from scratch, a stack buffer (512-byte limit) and a map value were all
> three tried; no working path compatible with verifier limits was found.
>
> **Why expansion is not done for now:** if 6-8 keys were written per
> rule, a reload would fail at roughly 1450 rules in a 10240-entry map —
> which is worse than a silent breakage.
>
> **Path to use:** write the files you want to protect as full paths.
> Write several rules if necessary. The eventual solution is to switch to
> an "absolute depth" encoding that changes both sides
> (`setKeyPath` + `ax_fill_path` together).

There are two separate mount conditions and **both have been solved**.

Raw behaviour measured with bpftrace:

| Location | File system | Visible dentry chain |
|---|---|---|
| `/etc/ax-dosya` | btrfs (root) | `ax-dosya → etc → root(subvolume) → /` |
| `/tmp/ax-dosya` | tmpfs | `ax-dosya → /` — **`tmp` is invisible** |

### 1. btrfs subvolume root (invisible component)

It has been mounted as a root subvolume since Fedora 33 and an invisible
component named `root` enters the dentry chain. The policy writes
`/etc/ax-dosya`, the kernel sees `/root/etc/ax-dosya`.

Solution: `mount_artifact_map`. Because the daemon sees `root=/root` in
mountinfo it writes that name into the map; BPF drops the component that
corresponds to the mount root. Rules for `/etc`, `/var`, `/home` and
`/root` work.

### 2. Separate mount (invisible PREFIX)

Because `/tmp` is a tmpfs mount, the name of the mount point (`tmp`) is
NOT a directory entry; it is a mount link. That is why it never appears in
the dentry chain and the prefix is lost.

Solution: `mount_point_map`. The daemon reads the superblock device from
field 3 (`MAJ:MIN`) of mountinfo and writes it into the map; when BPF
reaches the mount root it looks up this map and appends the prefix
**below** the path.

The key reason it keys on the superblock device alone:

- The inode is not present in mountinfo.
- `stat()` is rejected by SELinux; 12 mount points were returning EACCES
  (`/run/user/1000`, `/sys/fs/cgroup`, `/dev/pts`, ...). A `stat()`-based
  solution would therefore have silently dropped 12 mounts.
- All tmpfs roots are inode 1; the only distinguishing value is `s_dev`.

Verification (Fedora 44, SELinux enforcing, RPM installation):

```
cat /tmp/ax-dosya       -> Operation not permitted
cat /dev/shm/ax-dosya   -> Operation not permitted
cat /run/ax-dosya       -> Operation not permitted
cat /run/user/1000/x    -> Operation not permitted
cat /etc/hostname       -> allowed   (outside the rule)
```

Remaining boundary: the map is keyed on the superblock device, so binding
the same superblock to two different paths (for example mounting the same
tmpfs at both `/tmp` and `/var/tmp`) shares one record. In practice this
does not occur. `axctl policy check` does not verify this distinction — the
rule counts as valid because the syntax is correct. The behaviour is
understood by measurement.