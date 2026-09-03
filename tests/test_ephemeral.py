"""
Tests for cryptoflex.ephemeral — forward-secret messaging mode.

12 tests covering:
  - Basic round-trip (classical & hybrid)
  - Each message produces a unique blob (fresh keys every call)
  - Tamper detection (header and ciphertext)
  - Wrong private handles rejected
  - Downgrade enforcement (min_profile)
  - Empty plaintext, large plaintext
  - WireMessage structure
  - Multiple independent messages from same bundle
"""

import pytest

from cryptoflex.api import establish_keys
from cryptoflex.ephemeral import WireMessage, ephemeral_decrypt, ephemeral_encrypt
from cryptoflex.errors import DecryptionError, DowngradeError
from cryptoflex.policy import Constraint, PolicyEngine


# ---------------------------------------------------------------------------
# Test 1: Basic classical round-trip
# ---------------------------------------------------------------------------

def test_ephemeral_round_trip_classical():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    plaintext = b"Hello from sender, classical ephemeral test!"
    msg = ephemeral_encrypt(recipient.public_bundle, plaintext)
    recovered = ephemeral_decrypt(recipient.private_handles, msg)
    assert recovered == plaintext


# ---------------------------------------------------------------------------
# Test 2: Basic hybrid round-trip
# ---------------------------------------------------------------------------

def test_ephemeral_round_trip_hybrid(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    recipient = establish_keys(engine)

    plaintext = b"Hello from sender, hybrid ephemeral test!"
    msg = ephemeral_encrypt(recipient.public_bundle, plaintext)
    recovered = ephemeral_decrypt(recipient.private_handles, msg)
    assert recovered == plaintext


# ---------------------------------------------------------------------------
# Test 3: Each call produces a unique blob (fresh keys per message)
# ---------------------------------------------------------------------------

def test_ephemeral_unique_blobs_per_call():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    plaintext = b"same plaintext"
    msg1 = ephemeral_encrypt(recipient.public_bundle, plaintext)
    msg2 = ephemeral_encrypt(recipient.public_bundle, plaintext)

    # Different ephemeral keys → different ciphertext blobs
    assert msg1.encrypted_blob != msg2.encrypted_blob

    # But both decrypt correctly
    assert ephemeral_decrypt(recipient.private_handles, msg1) == plaintext
    assert ephemeral_decrypt(recipient.private_handles, msg2) == plaintext


# ---------------------------------------------------------------------------
# Test 4: WireMessage is a dataclass with encrypted_blob field
# ---------------------------------------------------------------------------

def test_wire_message_structure():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    msg = ephemeral_encrypt(recipient.public_bundle, b"structure test")
    assert isinstance(msg, WireMessage)
    assert isinstance(msg.encrypted_blob, bytes)
    assert len(msg.encrypted_blob) > 32


# ---------------------------------------------------------------------------
# Test 5: Tampered header byte is rejected
# ---------------------------------------------------------------------------

def test_ephemeral_tampered_header_rejected():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    msg = ephemeral_encrypt(recipient.public_bundle, b"tamper header test")
    blob = bytearray(msg.encrypted_blob)
    blob[5] ^= 0xFF  # tamper inside header magic/version area
    tampered = WireMessage(encrypted_blob=bytes(blob))

    with pytest.raises(DecryptionError):
        ephemeral_decrypt(recipient.private_handles, tampered)


# ---------------------------------------------------------------------------
# Test 6: Tampered ciphertext byte is rejected
# ---------------------------------------------------------------------------

def test_ephemeral_tampered_ciphertext_rejected():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    msg = ephemeral_encrypt(recipient.public_bundle, b"tamper ciphertext test")
    blob = bytearray(msg.encrypted_blob)
    blob[-10] ^= 0xFF  # tamper in the AEAD payload
    tampered = WireMessage(encrypted_blob=bytes(blob))

    with pytest.raises(DecryptionError):
        ephemeral_decrypt(recipient.private_handles, tampered)


# ---------------------------------------------------------------------------
# Test 7: Wrong private handles rejected
# ---------------------------------------------------------------------------

def test_ephemeral_wrong_private_handles_rejected():
    engine = PolicyEngine()
    alice = establish_keys(engine, constraint=Constraint.FAST)
    bob = establish_keys(engine, constraint=Constraint.FAST)

    msg = ephemeral_encrypt(alice.public_bundle, b"wrong handle test")

    with pytest.raises(DecryptionError):
        ephemeral_decrypt(bob.private_handles, msg)


# ---------------------------------------------------------------------------
# Test 8: Downgrade enforcement via min_profile
# ---------------------------------------------------------------------------

def test_ephemeral_min_profile_enforced():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)  # classical_only

    msg = ephemeral_encrypt(recipient.public_bundle, b"downgrade test")

    with pytest.raises(DowngradeError):
        ephemeral_decrypt(recipient.private_handles, msg, min_profile="hybrid_standard")


# ---------------------------------------------------------------------------
# Test 9: min_profile passes when profile is equal or stronger
# ---------------------------------------------------------------------------

def test_ephemeral_min_profile_passes_equal():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    msg = ephemeral_encrypt(recipient.public_bundle, b"equal profile test")
    recovered = ephemeral_decrypt(recipient.private_handles, msg, min_profile="classical_only")
    assert recovered == b"equal profile test"


# ---------------------------------------------------------------------------
# Test 10: Empty plaintext round-trip
# ---------------------------------------------------------------------------

def test_ephemeral_empty_plaintext():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    msg = ephemeral_encrypt(recipient.public_bundle, b"")
    recovered = ephemeral_decrypt(recipient.private_handles, msg)
    assert recovered == b""


# ---------------------------------------------------------------------------
# Test 11: Large plaintext (1 MB) round-trip
# ---------------------------------------------------------------------------

def test_ephemeral_large_plaintext():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    plaintext = b"A" * (1024 * 1024)  # 1 MB
    msg = ephemeral_encrypt(recipient.public_bundle, plaintext)
    recovered = ephemeral_decrypt(recipient.private_handles, msg)
    assert recovered == plaintext


# ---------------------------------------------------------------------------
# Test 12: Multiple independent messages decrypt independently
# ---------------------------------------------------------------------------

def test_ephemeral_multiple_messages_independent():
    engine = PolicyEngine()
    recipient = establish_keys(engine, constraint=Constraint.FAST)

    messages = [f"message number {i}".encode() for i in range(5)]
    wire_msgs = [ephemeral_encrypt(recipient.public_bundle, m) for m in messages]

    # Decrypt each independently
    for i, wire_msg in enumerate(wire_msgs):
        recovered = ephemeral_decrypt(recipient.private_handles, wire_msg)
        assert recovered == messages[i]
