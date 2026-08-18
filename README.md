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
3. **Migration tooling** — a versioned header format so data encrypted
   under an old profile keeps decrypting after the default policy
   changes, without a full rewrite of the consuming application.

## Explicitly out of scope

- QKD (quantum key distribution) — requires physical infrastructure no
  software library can provide.
- Live network-fetched threat/deprecation feeds — the risk table is
  bundled with the package and updated via normal version releases, to
  preserve the "no external dependency" guarantee.
- Novel cryptographic primitives — we use `cryptography` (X25519) and
  `liboqs-python` (ML-KEM), both independently audited. We do not
  reimplement crypto math.

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
`draft-ietf-tls-hybrid-design`. We don't invent new combiner math —
this is orchestration around `cryptography`'s HKDF implementation.

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

## Status

v0.1.0 — early, unaudited. Don't use this for anything where you can't
afford to be wrong yet. Issues and review welcome.
