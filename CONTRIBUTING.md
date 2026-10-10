# Contributing

Contributions are welcome. This document keeps the process short.

## Before You Begin

Read the project's working standard: [AGENTS.md](AGENTS.md)

Three items in summary:

1. **Do not leave a bug** — if you find one, close it, then show your
   evidence.
2. **Every claim requires evidence** — measure before you write "works".
3. **Fix durably** — not a surface patch; close the root cause.

## Development Environment

```bash
git clone https://github.com/muhammetodosks/axlinux.git
cd axlinux

# Dependencies (Fedora)
sudo dnf install golang clang llvm bpftool make gcc rpm-build rpm-sign \
    python3-devel python3-setuptools python3-click python3-rich \
    python3-yaml selinux-policy-devel systemd-rpm-macros kernel-core

# Build
make bpf
make go
make python
```

## Tests

**Always run the test you wrote.** A test that has not been run is not a
test.

```bash
# Local package — fast, does not require a virtual machine
python3 -m pytest tests/ -q
cd src/go/axdaemon && go test ./...
cd src/go/axlog    && go test ./...

# Full verification — requires a virtual machine
sudo bash tests/deep_verify.sh
```

`deep_verify.sh` **refuses** to run on a physical machine. This is a
deliberate safety boundary, not a bug. It applies to the test script only:
AXlinux itself installs and runs on physical machines, and neither
`install.sh` nor `axctl` contains any virtual-machine check. The guard can
be overridden with `AXLINUX_ALLOW_PHYSICAL=1` if you have console access
and a way to recover.

## Commit Message

Project style: **plain ASCII, starts with an imperative sentence, states
what you changed and why, and how you verified it.**

> **Note on the convention.** The project is Turkish-speaking, and commit
> messages are historically written in Turkish **without diacritics** so
> that the text stays pure ASCII. The example below is a real commit
> message and is kept verbatim for that reason. This convention governs
> *commit text only* — this document and the rest of the repository are
> written in English.

```
Tekil "subject" policies.d yolunu reddediyordu; sistem kisitlamasiz kaliyordu

axctl policy check tekil (string) "subject: curl" yazan politikayi
GECERLI diyordu. Kullanici politika yolunda (axctl reload) de ayni
sey. Ama /etc/axlinux/policies.d - kalici konum - ayni dosyayi
reddediyordu.

Dogrulama: policies.d uzerinden yuklendi, deny derinlikte calisti.
```

Writing rules:
- The subject line must not exceed 72 characters
- It must not end with punctuation
- The body wraps at 72 characters
- Do not use Markdown backticks (keeps the text ASCII)

## Pull Request

1. Subject: what you changed and **why**
2. Body: which measurement validates the change
3. Test output (as a command, not as prose)
4. If you changed an example policy, the `axctl policy check` output

**Acceptance criterion:** tests green, measurement shown, claim evidenced.

## Security

Do **not** open a security vulnerability as an issue — follow the
procedure in [SECURITY.md](SECURITY.md).

## Content

Contributions to the policy language, examples and documentation are
welcome. When adding a new example policy:

```bash
axctl policy check -f examples/yeni-ornek.yaml
```

attach the output to the pull request. The `name` field is mandatory.

## License

Your contribution is published under the MIT license.