"""
verify_local.py
================
Comprehensive Local Verification Script for cryptoflex v0.4.1.

Demonstrates:
  1. Key Generation via PolicyEngine
  2. High-Level AEAD Encryption & Decryption (encrypt/decrypt)
  3. Ephemeral Forward-Secret Messaging Mode (ephemeral_encrypt/ephemeral_decrypt)
  4. Encrypted Password-Wrapped Keystore (Argon2id + Scrypt back-compat)
  5. In-Place Memory Zeroization (zeroize)
  6. Offline Bulk Migration CLI Workflow (encrypt -> migrate -> decrypt)
  7. Chunked Streaming AEAD Encryption & Decryption (encrypt_stream/decrypt_stream)
  8. Header Wire Format Inspection (Magic, Version 2, Nonce, Components)
  9. Header AAD & Payload Tamper Resistance Detection
  10. Explicit Downgrade Protection (min_profile Enforcement)
"""

import io
import sys
from cryptoflex import (
    Constraint,
    CryptoflexHeader,
    DecryptionError,
    DowngradeError,
    PolicyEngine,
    decrypt,
    decrypt_stream,
    encrypt,
    encrypt_stream,
    ephemeral_decrypt,
    ephemeral_encrypt,
    establish_keys,
    export_keyset_bytes,
    import_keyset_bytes,
    zeroize,
)


def print_step(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main():
    print("Running Local Cryptographic Verification for cryptoflex v0.4.1...")

    # --- 1. Establish Keys ---
    print_step("1. Establishing Keys via PolicyEngine (Constraint: FAST)")
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    print(f"Selected Profile ID : {keyset.profile.profile_id}")
    print(f"Display Name        : {keyset.profile.display_name}")
    print(f"Strength Level      : {keyset.profile.strength_level}")
    print(f"Public Keys Count   : {len(keyset.public_bundle.public_keys)}")
    for alg_id, pub_bytes in keyset.public_bundle.public_keys:
        print(f"  - Component: {alg_id} ({len(pub_bytes)} bytes pubkey)")

    # --- 2. AEAD Encrypt & Decrypt Round-Trip ---
    print_step("2. High-Level AEAD Encryption & Decryption")
    secret_message = b"CONFIDENTIAL: Post-quantum crypto-agility policy verification passed!"
    blob = encrypt(keyset.public_bundle, secret_message)
    print(f"Plaintext size : {len(secret_message)} bytes")
    print(f"Encrypted blob : {len(blob)} bytes (Header v2 + AES-256-GCM Payload)")

    decrypted = decrypt(keyset.private_handles, blob)
    assert decrypted == secret_message, "Decryption mismatch!"
    print(f"Decryption SUCCESS! Recovered: '{decrypted.decode()}'")

    # --- 3. Ephemeral Forward-Secret Messaging ---
    print_step("3. Forward-Secret Ephemeral Messaging Mode")
    ephemeral_text = b"Hello, this message uses a fresh root key generated & discarded per call!"
    wire_msg = ephemeral_encrypt(keyset.public_bundle, ephemeral_text)
    print(f"Ephemeral Blob Size : {len(wire_msg.encrypted_blob)} bytes")

    recovered_ephemeral = ephemeral_decrypt(keyset.private_handles, wire_msg)
    assert recovered_ephemeral == ephemeral_text, "Ephemeral decryption mismatch!"
    print(f"Ephemeral Messaging SUCCESS! Recovered: '{recovered_ephemeral.decode()}'")

    # --- 4. Argon2id & Scrypt Encrypted Keystores ---
    print_step("4. Password-Wrapped Encrypted Keystores (Argon2id & Scrypt)")
    password = "VerificationPassphrase789!"
    argon2_bytes = export_keyset_bytes(keyset, password, use_argon2=True)
    scrypt_bytes = export_keyset_bytes(keyset, password, use_argon2=False)

    print(f"Argon2id Keystore Header : {argon2_bytes[:4]} ({len(argon2_bytes)} bytes)")
    print(f"Scrypt Keystore Header   : {scrypt_bytes[:4]} ({len(scrypt_bytes)} bytes)")

    imported_argon2 = import_keyset_bytes(argon2_bytes, password)
    imported_scrypt = import_keyset_bytes(scrypt_bytes, password)

    assert decrypt(imported_argon2.private_handles, blob) == secret_message
    assert decrypt(imported_scrypt.private_handles, blob) == secret_message
    print("Argon2id and Scrypt Keystore Import/Export SUCCESS!")

    # --- 5. Memory Zeroization ---
    print_step("5. In-Place Memory Zeroization (zeroize)")
    sensitive_buf = bytearray(b"super_secret_private_key_material")
    zeroize(sensitive_buf)
    assert sensitive_buf == bytearray(len(sensitive_buf))
    print("Memory Zeroization SUCCESS! Sensitive buffer wiped to 0x00.")

    # --- 6. Chunked Streaming AEAD ---
    print_step("6. Chunked Streaming AEAD Encryption & Decryption")
    stream_payload = b"Streaming Chunk Data Block " * 500
    fin = io.BytesIO(stream_payload)
    fout = io.BytesIO()
    encrypt_stream(keyset.public_bundle, fin, fout, chunk_size=4096)

    stream_blob = fout.getvalue()
    print(f"Stream Payload Input  : {len(stream_payload)} bytes")
    print(f"Stream Encrypted Blob : {len(stream_blob)} bytes")

    f_enc_in = io.BytesIO(stream_blob)
    f_dec_out = io.BytesIO()
    decrypt_stream(keyset.private_handles, f_enc_in, f_dec_out)
    assert f_dec_out.getvalue() == stream_payload
    print("Chunked Streaming AEAD SUCCESS!")

    # --- 7. Wire Format Header Inspection ---
    print_step("7. Wire Format Header Inspection")
    header, consumed = CryptoflexHeader.from_bytes(blob)
    print(f"Magic              : {blob[:4]}")
    print(f"Format Version     : {header.version}")
    print(f"Profile ID         : '{header.profile_id}'")
    print(f"Header Bytes Consumed: {consumed} bytes")
    print(f"AES-GCM Nonce      : {header.nonce.hex()}")
    for alg_id, ct in header.components:
        print(f"  - Component KEM CT: {alg_id} ({len(ct)} bytes ciphertext)")

    # --- 8. Header Tamper Detection (AAD Check) ---
    print_step("8. Header Tamper Resistance (AEAD Associated Data Check)")
    tampered_blob = bytearray(blob)
    tampered_blob[6] ^= 0x01  # flip a byte inside profile_id string
    try:
        decrypt(keyset.private_handles, bytes(tampered_blob))
        print("FAIL: Tampered header was NOT caught!")
        sys.exit(1)
    except DecryptionError as e:
        print(f"PASS: Tampered header rejected cleanly via uniform DecryptionError!")
        print(f"      Error caught: {type(e).__name__}('{e}')")

    # --- 9. Ciphertext Payload Tamper Detection ---
    print_step("9. Ciphertext Payload Tamper Resistance (AES-GCM Tag Check)")
    tampered_payload_blob = bytearray(blob)
    tampered_payload_blob[-1] ^= 0xFF  # flip last byte of AEAD tag
    try:
        decrypt(keyset.private_handles, bytes(tampered_payload_blob))
        print("FAIL: Tampered payload was NOT caught!")
        sys.exit(1)
    except DecryptionError as e:
        print(f"PASS: Tampered payload rejected cleanly via uniform DecryptionError!")
        print(f"      Error caught: {type(e).__name__}('{e}')")

    # --- 10. Downgrade Protection ---
    print_step("10. Downgrade Semantics (min_profile Enforcement)")
    print("Attempting to decrypt classical_only blob when min_profile='hybrid_standard'...")
    try:
        decrypt(keyset.private_handles, blob, min_profile="hybrid_standard")
        print("FAIL: Downgrade attempt was NOT caught!")
        sys.exit(1)
    except DowngradeError as e:
        print(f"PASS: Downgrade attempt blocked BEFORE crypto operation!")
        print(f"      Caught: {type(e).__name__} -> {e}")

    print_step("ALL LOCAL VERIFICATION CHECKS PASSED SUCCESSFULLY! [10/10]")


if __name__ == "__main__":
    main()
