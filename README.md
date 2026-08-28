# cryptoflex

[![tests](https://github.com/keerthivasan-sankar/crypto_flex/actions/workflows/tests.yml/badge.svg)](https://github.com/keerthivasan-sankar/crypto_flex/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

A **local-first crypto-agility policy engine** for Python.

`cryptoflex` doesn't implement any new cryptography. It orchestrates
existing, audited primitives — classical X25519 and post-quantum ML-KEM
(via [liboqs](https://github.com/open-quantum-safe/liboqs)) — behind a
policy engine that decides which combination an application should use,
based entirely on **local signals**. No network calls, no telemetry, no
third-party service dependency, ever.

## Why this exists

Most encryption tools hardcode one algorithm stack and never revisit
that choice. If the underlying math is ever weakened — most notably,
elliptic-curve crypto against a future large-scale quantum computer —
every app built on it needs a rewrite. Large platforms (Signal, Chrome,
Cloudflare) have already shipped hybrid classical+PQC key exchange for
their own protocols. This project targets what they haven't: **local,
offline, file-based tools** — encryption utilities, desktop apps,
embedded/IoT — where there's still no clean, drop-in crypto-agility
layer.

## What's actually novel here (and what isn't)

Hybrid classical+PQC key combining is **not new**. If you came here
looking for new cryptographic math, this isn't that project — see
Signal's PQXDH, Chrome's X25519Kyber768, or Open Quantum Safe's own
hybrid KEM support instead.

What this project adds:

1. **A policy/decision engine** — most existing hybrid implementations
   are static (compiled once with a fixed algorithm set). `cryptoflex`'s
   `PolicyEngine` picks a profile at runtime based on local
   availability, a caller-specified performance/security constraint, and
   a versioned local risk table — without ever phoning home.
2. **A local-first target domain** — built for file/desktop tools, not
   network protocols.
3. **Self-describing versioned headers** — every derived key ships with
   a header recording exactly which profile and which KEM ciphertexts
   produced it. Decryption always reads *that data's own* header rather
   than consulting current policy, so data encrypted under an old
   profile keeps decrypting correctly after the default policy changes.
   To be precise about scope: this is what makes old data readable, not
   a migration tool. `cryptoflex` itself has no batch re-encryption,
   rollback, or backup logic — an application built on top (such as
   [flexlock](https://github.com/keerthivasan-sankar/flex-lock)) has to
   implement actual migration workflows itself.

## Explicitly out of scope

- QKD (quantum key distribution) — requires physical infrastructure no
  software library can provide.
- Live network-fetched threat/deprecation feeds — the risk table is
  bundled with the package and updated via normal version releases, to
  preserve the "no external dependency" guarantee.
- Novel cryptographic primitives — we use `cryptography` (X25519) and
  `liboqs-python` (ML-KEM), both independently audited. We do not
  reimplement crypto math.
- Migration/re-encryption tooling — see point 3 above. That belongs in
  an application built on this library, not in the library itself.

## Installation

```bash
pip install cryptoflex          # classical-only, always works
pip install cryptoflex[pqc]     # + PQC support via liboqs-python
```

**Note on the PQC extra:** `liboqs-python` will attempt to compile
`liboqs` from source on first import if no prebuilt shared library is
found on your system — this is a multi-minute, one-time build (it
builds every algorithm liboqs ships). For CI/dev environments where you
want fast, predictable behavior instead, set:

```bash
export CRYPTOFLEX_DISABLE_PQC=1
```

This makes `PQCSource` report itself as unavailable immediately; the
`PolicyEngine` will gracefully fall back to `classical_only` and mark
the decision as `degraded=True` so your code can detect and log it.

**Faster PQC install on Debian/Ubuntu:** installing `liboqs` itself via
apt is much faster than letting `liboqs-python` compile it from source
on first import:

```bash
sudo apt-get install -y liboqs-dev
pip install cryptoflex[pqc]
```

### Refusing to degrade: strict mode

If your application would rather fail loudly than silently ship
non-quantum-safe protection, pass `require_quantum_safe=True`. This is
NOT a separate mode to bolt on - it's already the supported way to
express that requirement:

```python
from cryptoflex import PolicyEngine, Constraint

engine = PolicyEngine()
# raises RuntimeError instead of falling back to classical_only if no
# PQC source is available
decision = engine.decide(Constraint.BALANCED, require_quantum_safe=True)
```

`establish_keys()` accepts the same flag directly:

```python
from cryptoflex import establish_keys

keyset = establish_keys(require_quantum_safe=True)
```

Even without `require_quantum_safe`, every decision the engine makes
carries an explicit `degraded: bool` and human-readable `reason` -
`degraded=True` is never a silent fallback, it's a signal your code can
check and log:

```python
if keyset.policy_decision.degraded:
    logger.warning("cryptoflex degraded: %s", keyset.policy_decision.reason)
```

## Quick start

```python
from cryptoflex import PolicyEngine, Constraint, establish_keys, derive_root_key, recover_root_key

engine = PolicyEngine()

# Party A: generate a keypair for whatever profile the policy picks
keyset = establish_keys(engine, constraint=Constraint.BALANCED)
print(keyset.policy_decision.reason)
# e.g. "selected 'hybrid_standard' for constraint=balanced"

# Party B: derive a root key + header from A's public bundle
derived = derive_root_key(keyset.public_bundle)
# derived.root_key -> use as your AES-256-GCM key etc.
# derived.header.to_bytes() -> prepend this to your ciphertext file

# Party A: recover the same root key later
root_key = recover_root_key(keyset.private_handles, derived.header)
assert root_key == derived.root_key
```

## Security profiles (v1)

| Profile ID         | Sources                    | Quantum-safe |
|---------------------|-----------------------------|--------------|
| `classical_only`    | X25519                      | No           |
| `hybrid_standard`    | X25519 + ML-KEM-768          | Yes          |
| `hybrid_high`        | X25519 + ML-KEM-1024         | Yes          |

Hybrid profiles keep the classical component even though it isn't
quantum-safe on its own: it's far better audited than any PQC scheme's
current track record, so it provides a hedge against an undiscovered
flaw in the newer math. This is the same design choice Signal and
Chrome made.

## The combiner's security property

The combined root key must be at least as strong as the strongest input
source — an attacker who fully breaks every source but one still cannot
recover the combined key, as long as they don't also control the
unbroken source's ciphertext. This is achieved by binding **all** shared
secrets **and all** ciphertexts into a single HKDF derivation (see
`cryptoflex/combiner.py`), following the same shape as
[RFC 9954](https://www.rfc-editor.org/info/rfc9954) (Hybrid Key
Exchange in TLS 1.3). We don't invent new combiner math — this is
orchestration around `cryptography`'s HKDF implementation.

**Note on terminology:** RFC 9954 addresses two-party key *exchange*.
`cryptoflex`'s own use case (encrypting to your own public key, no
second party, no network) is asymmetric self-encryption via a KEM —
the same combiner math applies, but "key exchange" isn't an accurate
description of what `cryptoflex` itself does end-to-end. Any place in
this README or the code comments that talks about "key exchange" is
describing the underlying primitive or the prior art (Signal, Chrome),
not claiming `cryptoflex` itself performs a two-party exchange.

## Known limitations

- **Per-invocation profile selection isn't pinned across machines.**
  `PolicyEngine.decide()` picks a profile based on what's available on
  *the machine running it, right now*. If the same identity/context is
  used across multiple devices and one lacks a compiled `liboqs`, that
  device will silently select a weaker profile with no coordination
  with the others — two machines could end up encrypting under
  different profiles with nothing to flag the mismatch. There's
  currently no mechanism to pin a profile to an identity once and keep
  it consistent across devices; that's on an application built on top
  of `cryptoflex` to handle, not something this library does today.
- **No migration tooling**, as covered above — self-describing headers
  only, no batch re-encryption/rollback/backup logic in this library.
- **No independent security review.** The combiner construction
  follows RFC 9954's shape, and `TECHNICAL_REVIEW.md` contains a
  detailed self-assessment, but neither is a substitute for an actual
  audit of this specific implementation by an unaffiliated party.

## Running tests

```bash
pip install -e ".[dev]"
CRYPTOFLEX_DISABLE_PQC=1 pytest -v
```

(Drop the env var if you have a prebuilt liboqs available and want to
exercise the real PQC path instead of the test-only `MockPQCSource`.)

## Contributing

Issues and PRs welcome. Please run the test suite (see above) and
`pyflakes cryptoflex/` before submitting.

## Self-review

A structured, AI-assisted self-review of the codebase is available in
[`TECHNICAL_REVIEW.md`](TECHNICAL_REVIEW.md). It was generated at the
project author's request to review the author's own code — **it is
not an independent third-party audit**, and its numeric scores should
be read as one structured perspective on the code, not as outside
validation. See the disclaimer at the top of that file for more detail
and for what's changed since it was written.

## A note on how this was built

This project was built with AI assistance (design, code, and docs),
not written solo by hand. Flagging that plainly rather than leaving it
ambiguous.

## Status

v0.1.0 — early, unaudited. Don't use this for anything where you can't
afford to be wrong yet. Issues and review welcome.
