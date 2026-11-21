# Security Policy

## Scope

This repository contains the independent offline verifier (`verify.ts` and
`verify.py`) for signed ALEX Evidence Packages, plus the `independence/`
reproducibility kit and the trust anchor registry (`trust-anchor.json`).
Report any issue that affects:

- The verifier accepting a bundle it should reject, or rejecting one it
  should accept (either implementation, or a mismatch between the two).
- Signature, hash-chain, or timestamp checks that can be bypassed.
- The trust anchor / key registry.
- The `independence/` reproducibility kit no longer reproducing what it
  claims to.

## Reporting a Vulnerability

Email **bewusst.ki@gmail.com** with a description and, if possible, a
reproduction (a bundle or a diff against a sample in this repo). Do not open
a public issue for an unpatched verifier bypass.

You will get an acknowledgement within 72 hours. There is no bug bounty.

## Disclosure

Fixes to files matched by `CRITICAL_PATH_REGEX` in
[`critical-file-cooldown.yml`](.github/workflows/critical-file-cooldown.yml)
(`verify.ts`, `verify.py`, `.github/allowed_signers`, `release.yml`,
`critical-file-cooldown.yml`, `trust-anchor.json`) go through a 24-hour
public cooldown before merge — see [`TRUST-BOUNDARY.md`](TRUST-BOUNDARY.md).
For an actively exploitable bypass, tell us privately first; we will
coordinate disclosure timing with you rather than let the fix sit in a
public, open PR for 24 hours while unpatched.
