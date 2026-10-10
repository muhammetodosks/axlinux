## What You Changed

<!-- Short description -->

## Why

<!-- What was the problem, why was this change necessary -->

## How You Verified It

<!-- Paste the measurement. "I wrote a test" is not enough, it needs OUTPUT -->

```bash
# The command you ran and its output
```

## Test Status

- [ ] `python3 -m pytest tests/ -q` green
- [ ] `go test ./...` (axdaemon and axlog) green
- [ ] Numbers updated in every document touched by the change
- [ ] If policy/examples changed, the `axctl policy check` output is attached

## Example Policy Change

<!-- If you changed one, paste the `axctl policy check` output here.
     If you did not, write "none". -->

## Breaking Change

<!-- Is there a backwards-incompatible change? If so it will be added to the release notes. -->