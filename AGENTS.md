# AXlinux — Working Standard

This file holds the **permanent** rules to follow while working in this
repository. The next session must read it and apply the same standard.

---

## 1. No errors, no gaps, no excuses

Nothing is acceptable by default in this project:

- **Do not leave a bug.** If you find one, fix it, then show your
  evidence. "The user could also try…" is not an acceptable ending.
- **Do not leave anything incomplete.** Half-finished work, a `TODO`, or
  a "do this manually" note are all unacceptable. Either it is fixed or
  the claim is removed from the documentation.
- **Do not leave a blocker behind.** For any step that is hard,
  expensive or inconvenient, do not say "this is a blocker". Find a way
  for every step; if you cannot, dig deeper.
- **Fix the root cause.** No surface patches. If the same bug needs
  fixing twice, the first fix was wrong.

## 2. Every claim requires evidence

Every number, every "works", every "is supported" written in a document
**must be measured**.

- No item may remain in a document described as "unverified".
- If you cannot produce evidence, do not claim it — remove the claim.
- If you write a test, **run it**. A test that was not run is not a test.
- If you write a CI job, run it **locally too**. Do not trust that CI
  passes — in this project exactly such a bug was found (see below).

## 3. Verification method

The order is always: **measure → find the root cause → fix → measure
again.**

- Experiment, not theory. An assumption is not a verification.
- Bugs found by observing the production code are the most valuable;
  they reveal far more real bugs than written tests.
- If a number says "expected", compare the measurement with what was
  expected. If the measurement logic is wrong, the production code may
  be wrong too.
- If you see a contradiction (two documents disagreeing), do not pick
  one — **measure a third thing**: which is right?

## 4. Environment constraint

- AXlinux is never run on the primary machine's root filesystem.
- Every enforcement test runs in a VM under `/mnt/anka`.
- BPF LSM does not work inside containers; content verification
  (`deep_verify.sh`) therefore requires a virtual machine. This limit is
  deliberate and must be stated as a `::warning::` in CI output.

## 5. Reporting

- Write down what was measured, what changed, and where it was verified —
  all three.
- If something was **not** verified, say so explicitly. A report that
  hides its gaps is worse than one that behaves as if verified.
- If the user asks "is everything done?" and one item is unverified, the
  answer is not "yes" — verify it first.

---

## 6. Concrete lessons learned in this repository

These are permanent. Do not repeat them.

| Lesson | Where |
|--------|-------|
| `__builtin_memset` on structures larger than 256 bytes drops to a BPF libcall and the program fails to load | `axbpf.h` → `ax_event_clear()` |
| As the event struct grows, the per-CPU perf buffer is insufficient and the kernel **silently** drops records | `perf.NewReader(em, 65536)` + `LostSamples` |
| The event struct is written by hand in C and Go; a mismatch is **silent** | `TestEventLayoutMatchesC` measures it on every run |
| `axbpf.o` is a separate file in the RPM and must be updated **together** with the Go binary | separate measurement gate |
| `semanage delete` is **not** a valid subcommand | `axlinux.spec` `%preun` |
| `semanage fcontext -l` output is padded with **spaces**, not tabs | `awk '$1 ~ /axlinux/'` → `awk '/axlinux/'` |
| RPM deletes package files **before** `%postun`; module removal must happen in `%preun` | `axlinux.spec` |
| `fcontext -l` validates and **skips** invalid records | use the raw list |
| Removal order: fcontext records **first**, module second — the reverse order does not work | `axlinux.spec` |
| `parse_args()` was defined but **never called**; every flag was silently ignored | `install.sh` |
| `make rpm` demanded runtime Python modules for no reason | `rpm: bpf go`, spec `%build: make bpf go` |
| Writing code without running it is the most expensive mistake; run CI work locally | `packaging` matrix |
| The `cmd/mapdump` and `cmd/mapcmp` diagnostic tools look like external utilities but are **source code** — excluding them hides exactly the bugs they exist to catch | `.gitignore` |
| `rpm -qcp` lists only *some* conffiles; `%config(noreplace)` does **not** mean "preserved on removal" | `axlinux.spec` `%preun` |
| A stale build artefact in the tree makes `make` skip a rebuild, and `2>/dev/null` hides the error | `Makefile` `rpm` target |
| Test scripts refuse to run on physical machines; **the product does not**. Do not document a test limitation as a product limitation | `tests/deep_verify.sh` |