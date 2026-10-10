# AXlinux Roadmap

This document shows **what has actually been built**. It was previously
labelled with version numbers and marked implemented features as
unimplemented; once the version reached 1.0.0 this left the wrong
impression.

## 1.0.0 — Completed

### Core

- [x] YAML policy language (labels, wildcard subject, priority)
- [x] `axctl` CLI: `init`, `status`, `reload`, `mode`, `logs`,
      `label add|ls|rm`, `learn start|stop|report`,
      `template ls|apply`, `policy edit|check|simulate`, `version`
- [x] `axdaemon` (Go): LSM hooks, eBPF map management, JSON-RPC
- [x] `axlog` (Go): durable JSONL audit, journal compression
- [x] `axbpf` (C): 5 LSM hooks

### Verification

- [x] Comprehensive test suite (`tests/deep_verify.sh`) — 8 named
      sections (K–R) and **measured** 732 checks (Fedora 44: 732 passed /
      0 remaining / 0 skipped; Debian family: 731 / 0 / 1)
- [x] Physical-machine guard in the test suite (`deep_verify.sh` refuses
      to run enforcement tests on a physical machine; the product itself
      has no such restriction — `install.sh` and `axctl` contain no
      virtual-machine check)
- [x] Python ↔ Go ↔ eBPF contract tests
- [x] Document–CLI audit (`tests/test_docs.py`)
- [x] End-to-end validation on three distributions: Ubuntu 24.04.5,
      Debian 12, Pardus 25.2

### Policy language

- [x] Rule priority ordering (`priority`)
- [x] Conflict detection (same target, different effect)
- [x] Duplicate rule detection
- [x] Applicability audit (an unenforceable rule is rejected)
- [x] Candidate policy validation via `policy check -f`
- [x] Impact analysis via `policy simulate`

### Learning mode

- [x] Observation collection from the event stream (`learn_map`)
- [x] Pattern aggregation (subject + object + action)
- [x] Suggestion engine: generation of paste-ready YAML
- [x] Time-bounded run (`--days`), automatic shutdown

### Security

- [x] 29 protected processes (lockout protection)
- [x] An unenforceable rule is an **error**, not a warning (no silent ineffectiveness)
- [x] Empty policy is valid → `reload --force-empty` as the emergency recovery path
- [x] Durable audit; write-error counter and `audit_healthy`
- [x] Distribution-independent installation (apt/dnf/pacman/apk/zypper)
- [x] Runtime dependency contract (`requirements.txt`)

## Future

No feature on this list **exists**. No version number is given: assigning
a date would amount to promising something that has not been planned.

### High priority

- [ ] `net.accept` support — if the `lsm/socket_accept` hook is attached
- [ ] Deletion/creation audit — `lsm/inode_unlink_at` hook
- [ ] User-based rules — let the subject of a rule be a user
- [ ] `sudo` context — distinguish processes running under `sudo -u`

### Medium priority

- [ ] Time/condition rules — "between 09:00-18:00 every day"
- [ ] Policy signing and verification
- [ ] Remote policy sources (`trust`, `policy install`)
- [ ] Event-based rules — "if this file changes"
- [ ] Hot reload (without restarting the daemon)

### Low priority

- [ ] Container scope (auditing a single container)
- [ ] Graphical interface
- [ ] Signal hook (`lsm/signal`)

## Deliberately Not Done

These are not gaps, they are **decisions**:

- **Pulling unsigned remote policies.** Half-finished signature
  verification is worse than none at all. Either signature verification is
  complete, or remote policy loading is never implemented.
- **Silently ineffective rules.** If it can be proven that a rule will not
  work (a rule on `bash`, a path deeper than 8, an action with no hook),
  the policy is rejected. When a user believes a rule has loaded and
  considers the system protected, a warning is not enough.
- **Allowing lockout.** The 29 recovery-path processes are subject to no
  rule at all. This is not a compromise; it is a precondition of usability.