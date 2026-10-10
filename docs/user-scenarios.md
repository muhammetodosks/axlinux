# AXlinux User Scenarios

## Scenario 1: Initial Installation

```bash
# Install
sudo apt install axlinux

# Start
axctl init

# Status
axctl status
# → Mode: enforcing, empty policy, system unrestricted

# Write a policy
axctl policy edit
```

## Scenario 2: Protect the Shadow File

The user wants to stop browsers from reading `/etc/shadow`.

```bash
# Edit the policy.yaml file
axctl policy edit

# Content:
# version: 1
# mode: enforcing
# rules:
#   - name: "browsers cannot read shadow"
#     subject: firefox
#     object: /etc/shadow
#     action: file.read
#     effect: deny

# Validate
axctl policy check
# → ✓ Valid

# Simulate
axctl policy simulate
# → firefox, cannot read /etc/shadow

# Apply
axctl reload
# → ✓ Loaded

# Test
cat /etc/shadow  # as root
# → firefox cannot read this file
```

## Scenario 3: Lock Down a Web Server

The user wants nginx to be able to read only `/var/www`.

```bash
axctl policy edit

# Content:
# version: 1
# mode: enforcing
# rules:
#   - name: "nginx reads web content"
#     subject: nginx
#     object: /var/www
#     action: file.read
#     effect: allow
#   - name: "nginx cannot read shadow"
#     subject: nginx
#     object: /etc/shadow
#     action: file.read
#     effect: deny
#   - name: "nginx cannot run bash"
#     subject: nginx
#     action: process.exec
#     object: /bin/bash
#     effect: deny

axctl policy check
axctl reload

# nginx can now:
# → read /var/www/*
# → not read /etc/shadow
# → not run bash
```

## Scenario 4: Learning Mode

The user wants to learn how the system behaves.

```bash
# Start learning
axctl learn start
# → System will be observed for 3 days

# Get the report after 3 days
axctl learn report

# Example output:
# Learning Report (3 days)
# ======================
#
# Observed operations:
#
# nginx (web server):
#   → read /var/www/* (1.247 times)
#   → read /etc/nginx/nginx.conf (89 times)
#   → wrote /var/log/nginx/* (456 times)
#   → bound to ports 80 and 443
#
# firefox (browser):
#   → downloaded to ~/ (345 times)
#   → attempted to read /etc/shadow (3 times) ← BLOCKED
#   → connected to 500+ distinct hosts
#
# Suggested policy:
#
# rules:
#   - name: "nginx reads web content"
#     subject: nginx
#     object: /var/www
#     action: file.read
#     effect: allow
#   - name: "nginx writes its own logs"
#     subject: nginx
#     object: /var/log/nginx
#     action: file.write
#     effect: allow
#   - name: "firefox cannot read shadow"
#     subject: firefox
#     object: /etc/shadow
#     action: file.read
#     effect: deny
```

## Scenario 5: Permissive Mode (Development)

A developer wants to see what the policy would do without blocking anything.

```bash
axctl mode permissive
# → Mode: permissive (violations are only logged)

# Test
axctl policy simulate

# Watch the violations
axctl logs --follow --filter deny

# When you are ready
axctl mode enforcing
```

## Scenario 6: Network Restriction

```bash
axctl policy edit

# python cannot reach the network
# rules:
#   - name: "python cannot reach the network"
#     subject: python
#     action: net.connect
#     effect: deny

axctl reload

# python can now:
# → connect() is blocked when it calls socket()
# → cannot bind()
# → only Unix socket communication is possible
```

## Scenario 7: Error and Recovery

The user wrote a wrong policy.

```bash
axctl policy edit

# Wrong content:
# rules:
#   - name: "block everything"
#     subject: "*"
#     action: "*"
#     effect: deny

axctl policy check
# → ✗ Error: subject "*" can only be used with deny

# Simulate
axctl policy simulate
# → ⚠ CAUTION: This policy can lock the system!

# The user corrects it
axctl policy edit

# Correct content
axctl policy check
axctl reload
```

## Scenario 8: Emergency Exit

The user has locked the system.

```bash
# Always works
axctl mode disabled
# → All restrictions removed

# Or
axctl reload --force-empty
# → Empty policy loaded, system unrestricted
```

## Scenario 9: Container Usage (v1.0)

```bash
# Apply a policy to a container
docker run --security-opt axpolicy=./nginx-policy.yaml nginx

# or
kubectl apply -f axpolicy.yaml
# → AXlinux policy is applied to the pod
```

## Scenario 10: Community Policy (FUTURE — does not exist yet)

> **This scenario is a design goal; the commands below do not
> work.** Remote policy security has not been implemented yet.
> Today, write your own `~/.axlinux/policy.yaml` file.

```bash
# Add a trusted source
axctl trust add https://github.com/axlinux/policies

# Load a policy
axctl policy install nginx-hardened

# Validate
axctl policy verify nginx-hardened
# → ✓ Signature valid

# Apply
axctl policy use nginx-hardened
axctl reload
```