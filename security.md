# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of these private channels:

1. **Preferred: GitHub Security Advisories** — go to the
   [Security tab](https://github.com/keerthivasan-sankar/crypto_flex/security)
   of this repo → **Report a vulnerability**. This opens a private
   discussion visible only to the maintainer until a fix is ready.
2. **Email:** [kkeerthivasan811@gmail.com] — replace with a real contact
   address before relying on this file.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce it, or a minimal proof-of-concept
- The version/commit of `cryptoflex` you tested against

## What to expect

- **Acknowledgment:** within 5 business days of your report.
- **Status updates:** I'll let you know if I can reproduce it and roughly
  what the fix timeline looks like, given this is a solo-maintained
  project rather than a funded team.
- **Credit:** with your permission, I'll credit you in the fix's
  changelog entry and/or the GitHub Security Advisory once it's public.
- **No bug bounty program at this time.** This is an early-stage,
  unaudited, unfunded open-source project — there's no budget for paid
  rewards right now. If that changes as the project matures, this file
  will be updated to reflect it.

## Coordinated disclosure

Please give a reasonable window (90 days is a common default) to
investigate and release a fix before disclosing publicly. I'll do my
best to move faster than that for anything with real-world exploit
impact, and I'm happy to discuss timeline specifics with you directly
for anything more urgent.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

This project is pre-1.0 and under active development. Once a stable
1.0 is released, this table will be updated with a real support
window.

## Scope

This policy covers the `cryptoflex` library itself
(`github.com/keerthivasan-sankar/crypto_flex`) — the policy engine,
combiner, header format, and source wrappers. It does not cover
`liboqs` or `liboqs-python` (report issues in those upstream) or
`cryptography` (also upstream). If you're unsure whether something is
a `cryptoflex` bug or an upstream one, report it here anyway and I'll
help route it correctly.

## A note on current status

`cryptoflex` has not yet undergone an independent third-party security
audit — see [`TECHNICAL_REVIEW.md`](TECHNICAL_REVIEW.md) for a fuller
picture of what's been verified so far (test coverage, CI, two
previously-found-and-fixed validation bugs) versus what hasn't
(formal audit, extensive fuzzing). Please keep that context in mind
both when deciding whether to rely on this library for anything
sensitive, and when assessing the severity of anything you find.
