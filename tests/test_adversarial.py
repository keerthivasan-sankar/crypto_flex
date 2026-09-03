from __future__ import annotations

import pytest

from cryptoflex.api import DecryptionError, derive_root_key, establish_keys, recover_root_key
from cryptoflex.header import FORMAT_VERSION, CryptoflexHeader, HeaderParseError


def test_truncated_at_every_offset_never_crashes_uncontrolled():
    header = CryptoflexHeader(
        profile_id="hybrid_standard",
        components=[("x25519", b"\xaa" * 32), ("mlkem768", b"\xbb" * 1088)],
        nonce=b"\xcc" * 12,
    )
    full = header.to_bytes()

    for cut in range(len(full)):
        truncated = full[:cut]
        try:
            parsed, consumed = CryptoflexHeader.from_bytes(truncated)
            assert cut == len(full)
        except HeaderParseError:
            pass  # the only acceptable failure mode


def test_empty_bytes_rejected_cleanly():
    with pytest.raises(HeaderParseError):
        CryptoflexHeader.from_bytes(b"")


def test_random_garbage_rejected_cleanly():
    import os

    for _ in range(50):
        garbage = os.urandom(64)
        try:
            CryptoflexHeader.from_bytes(garbage)
        except HeaderParseError:
            pass  # the only acceptable failure mode


def test_future_format_version_rejected_not_misparsed():
    header = CryptoflexHeader(
        profile_id="classical_only",
        components=[("x25519", b"\x00" * 32)],
        nonce=b"\x00" * 12,
    )
    data = bytearray(header.to_bytes())
    data[4] = FORMAT_VERSION + 99
    with pytest.raises(HeaderParseError):
        CryptoflexHeader.from_bytes(bytes(data))


def test_downgrade_by_stripping_pqc_component_is_rejected(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    stripped = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=derived.header.components[:1],
        nonce=derived.header.nonce,
    )
    with pytest.raises(DecryptionError):
        recover_root_key(keyset.private_handles, stripped)


def test_duplicated_component_is_rejected(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    duplicated = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=[derived.header.components[0], derived.header.components[0]],
        nonce=derived.header.nonce,
    )
    with pytest.raises(DecryptionError):
        recover_root_key(keyset.private_handles, duplicated)


def test_reordered_components_rejected_not_silently_wrong(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    reordered = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=list(reversed(derived.header.components)),
        nonce=derived.header.nonce,
    )
    with pytest.raises(DecryptionError):
        recover_root_key(keyset.private_handles, reordered)


def test_swapped_component_ciphertexts_rejected(hybrid_mock_profile, FixedProfileEngine):
    """Swap the ciphertexts between component 0 and component 1."""
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    c0_alg, c0_ct = derived.header.components[0]
    c1_alg, c1_ct = derived.header.components[1]

    swapped = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=[(c0_alg, c1_ct), (c1_alg, c0_ct)],
        nonce=derived.header.nonce,
    )
    # Recovering root key with swapped ciphertexts must produce a different root key or raise DecryptionError
    try:
        recovered = recover_root_key(keyset.private_handles, swapped)
        assert recovered != derived.root_key
    except DecryptionError:
        pass


def test_tampered_ciphertext_byte_changes_recovered_key_not_crashes(
    hybrid_mock_profile, FixedProfileEngine
):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    tampered_components = list(derived.header.components)
    alg_id, ct = tampered_components[0]
    tampered_ct = bytes((ct[0] ^ 0xFF,)) + ct[1:]
    tampered_components[0] = (alg_id, tampered_ct)
    tampered_header = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=tampered_components,
        nonce=derived.header.nonce,
    )

    try:
        recovered = recover_root_key(keyset.private_handles, tampered_header)
        assert recovered != derived.root_key
    except DecryptionError:
        pass
