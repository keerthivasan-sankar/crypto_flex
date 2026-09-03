# Changelog

This project uses [Semantic Versioning](https://semver.org/). Because
`cryptoflex` writes a versioned on-disk header (`FORMAT_VERSION` in
`cryptoflex/header.py`), this changelog tracks **two separate version
numbers** that don't necessarily move together:

- **Package version** (`pyproject.toml`) - normal semver for the
  Python API surface.
- **Header format version** (`FORMAT_VERSION`) - only bumped when the
  on-disk byte layout changes. A header format bump is a breaking
  change for anyone with existing encrypted files and will always be
  called out explicitly here.

## [0.4.1] - 2026-09-03

### Added
- **Argon2id Keystore Protection**: Upgraded `cryptoflex.keystore` to support Argon2id password key derivation (`CFLA` header magic; $m=64\text{MB}, t=3, p=4$) as the new default for `export_keyset_bytes()`, while maintaining full backward compatibility with Scrypt (`CFLK` magic header).
- **In-Place Memory Zeroization**: Added `cryptoflex.utils.zeroize(buffer)` helper to securely wipe sensitive bytearrays and memoryviews in-place (`0x00`) to mitigate RAM retention risk.
- **CLI Migration Command**: Added `cryptoflex migrate` CLI subcommand allowing users to re-encrypt existing `.cflx` files under a new recipient `PublicBundle` to upgrade security profiles completely offline.

## [0.4.0] - 2026-09-03

### Security Hardening
- **Bypass-proof assertions**: Replaced `assert nonce is not None` in `api.py` and `streaming.py` with explicit `ValueError` checks, ensuring assertions cannot be bypassed when running Python under optimized mode (`python -O`).
- **Scrypt Work Factor**: Upgraded Scrypt parameter `N` in `keystore.py` from $2^{15}$ (32,768) to $2^{17}$ (131,072) to comply with OWASP key derivation guidelines against password brute-forcing.
- **CLI Password Security**: Updated CLI commands to resolve passwords securely via `getpass.getpass()` or `CRYPTOFLEX_PASSWORD` environment variable, making `--password` optional with a process-list visibility warning.
- **`liboqs` Lifetime Management**: Fixed `sources.py` `PQCSource.encapsulate()` to replace unsupported `with` context manager usage with explicit `try/finally` and `.free()` calls.
- **Stream Sanity Bounds**: Enforced `MAX_CHUNK_SIZE` (9 MB) and `MAX_HEADER_SIZE` (64 KB) in `streaming.py` to prevent stream buffer crashes and unreadable files.

### Added
- **Ephemeral Forward-Secret Messaging**: `cryptoflex.ephemeral` module providing `ephemeral_encrypt()`, `ephemeral_decrypt()`, and `WireMessage` dataclass. Fresh root keys are generated and discarded per call via direct encapsulation.
- **Property-Based Header Fuzzing**: `tests/test_fuzz_header.py` with `hypothesis` strategy testing 200+ byte mutations to verify `CryptoflexHeader.from_bytes()` raises only `HeaderParseError`.
- **12 Ephemeral Messaging Tests**: `tests/test_ephemeral.py` covering round-trips, uniqueness, tampering, wrong keys, downgrade prevention, empty/large payloads, and multi-message independence.

## [0.3.0] - 2026-08-31

### Added
- **Streaming AEAD API**: `encrypt_stream()` and `decrypt_stream()` in `cryptoflex.streaming` for memory-efficient processing of multi-GB payloads using 64 KB chunks with 4-byte sequence counters bound to AES-GCM nonces and AAD.
- **Password-Wrapped Keystore**: `export_keyset_bytes()` and `import_keyset_bytes()` in `cryptoflex.keystore` to encrypt private key handles under Scrypt + AES-256-GCM.
- **CLI Tooling**: `cryptoflex.cli` entrypoint for terminal `keygen`, `encrypt`, `decrypt`, and `info` header inspection.

## [0.2.0] - 2026-08-30

### Security Fixes (Discussion #2534)
- **Header v2 Format**: Added 12-byte random nonce to header; full header byte string authenticated as AES-256-GCM Associated Data (AAD).
- **Canonical Combiner**: Rewrote `combiner.py` to use length-prefixed injective encoding with profile-specific domain separation (`b"cryptoflex-hybrid-kem-combiner-" + profile_id`) and HKDF-SHA384.
- **Explicit Downgrade Protection**: Added `strength_level` integers to profiles and `min_profile` parameters to `decrypt()`, raising `DowngradeError` prior to decapsulation.
- **Uniform Error Boundaries**: All cryptographic failures collapse into generic `DecryptionError` to eliminate timing and error side-channels.

## [0.1.0] - initial release

- Header format version: 1
- Initial `classical_only`, `hybrid_standard`, `hybrid_high` profiles.
- Status: early, unaudited. See README "Status" section.
