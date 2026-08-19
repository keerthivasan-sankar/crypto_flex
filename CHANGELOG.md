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

## [Unreleased]

### Fixed
- **Security-relevant:** `recover_root_key()` used a Python chained
  comparison (`a != b != c`) to validate that the profile's expected
  source count, the caller's private-handle count, and the header's
  component count all matched. Chained comparisons don't check "all
  three differ" - they check `(a != b) and (b != c)` - so a header
  truncated to drop one component (e.g. an attacker or corruption
  stripping the PQC ciphertext) could silently pass validation instead
  of raising, and `recover_root_key()` would derive a key from a
  subset of the intended sources. Fixed to use `not (a == b == c)`.
  Covered by `tests/test_integration.py::test_recover_rejects_truncated_header_components`
  and the broader `tests/test_adversarial.py` module.
- `CryptoflexHeader.from_bytes()` could raise a bare `struct.error`,
  `IndexError`, or `UnicodeDecodeError` on truncated/malformed input
  instead of the library's own `HeaderParseError`, meaning callers
  who only caught `HeaderParseError` (the documented contract) could
  still see an unhandled exception from corrupted or partially-written
  files. All parse failures now consistently raise `HeaderParseError`.
  Found and covered by `tests/test_adversarial.py::test_truncated_at_every_offset_never_crashes_uncontrolled`.

### Added
- `tests/test_adversarial.py`: a dedicated module for malformed-input,
  truncation, reordering, duplication, and tampering tests, separate
  from the happy-path integration tests.
- CI now runs the test suite twice: once with `CRYPTOFLEX_DISABLE_PQC=1`
  (fast, no compile) and once against a real installed `liboqs`, so the
  actual PQC code path is exercised in CI, not just `MockPQCSource`.
- README: documented `require_quantum_safe=True` more prominently
  (it already existed on `PolicyEngine.decide()` and `establish_keys()`,
  but wasn't given its own section) and added the faster
  `apt-get install liboqs-dev` install path for Linux.

### Changed
- Minor `mypy` cleanup in `cryptoflex/sources.py`: the optional `oqs`
  import is now typed as `Any` instead of being inferred as `None`,
  removing five false-positive type errors on the guarded PQC call
  sites. No behavior change.

## [0.1.0] - initial release

- Header format version: 1
- Initial `classical_only`, `hybrid_standard`, `hybrid_high` profiles.
- Status: early, unaudited. See README "Status" section.
