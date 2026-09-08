"""
cryptoflex.keystore
====================

Encrypted Password-Wrapped Storage for KeySets and PublicBundles.

Security Rationale
-------------------
Private key handles returned by `establish_keys()` must never be stored as
plaintext on disk.  This module provides:
  - Password key derivation using Argon2id (default) or Scrypt (legacy/compat)
  - KeySet wrapping under AES-256-GCM with a 12-byte random nonce
  - JSON serialization for PublicBundle and encrypted KeySet files

File Formats:
  1. `.bundle.json`: PublicBundle (unencrypted public keys + profile_id)
  2. `.keyset.cflk`: Password-encrypted KeySet payload
     - `CFLA`: Magic for Argon2id KDF (memory_cost=32MB, time_cost=3, parallelism=1)
     - `CFLK`: Magic for Scrypt KDF (N=2^17, r=8, p=1)
"""

from __future__ import annotations

import base64
import json
import os
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .api import KeySet, PublicBundle
from .errors import DecryptionError
from .policy import PolicyDecision
from .profiles import get_profile

MAGIC_KEYSTORE_SCRYPT = b"CFLK"
MAGIC_KEYSTORE_ARGON2 = b"CFLA"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# Maximum keystore blob size accepted before any allocation or KDF attempt.
# Prevents attacker-controlled large inputs from exhausting RAM before rejection.
MAX_KEYSTORE_SIZE = 16 * 1024 * 1024  # 16 MB

# Cap concurrent memory-hard KDF derivations to 2 to prevent RAM exhaustion DoS.
# Semaphore acquire uses a timeout to prevent indefinite thread blocking.
_KDF_SEMAPHORE = threading.Semaphore(2)
_KDF_SEMAPHORE_TIMEOUT = 30.0  # seconds


def _derive_wrapping_key(password: str | bytes, salt: bytes, kdf_type: str = "argon2id") -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")

    # Reject empty passwords at the library boundary. A zero-length password
    # would silently produce a valid KDF output and weaken the security boundary.
    if not password:
        raise ValueError("keystore password must not be empty")

    acquired = _KDF_SEMAPHORE.acquire(timeout=_KDF_SEMAPHORE_TIMEOUT)
    if not acquired:
        raise RuntimeError(
            "KDF concurrency limit reached: too many simultaneous key-derivation "
            "operations. Try again shortly."
        )
    try:
        if kdf_type == "argon2id":
            kdf = Argon2id(
                salt=salt,
                length=KEY_LEN,
                iterations=3,
                memory_cost=32768,  # 32 MB — balanced for multi-tenancy
                lanes=1,           # single lane to limit per-call RAM ceiling
            )
            return kdf.derive(password)
        elif kdf_type == "scrypt":
            kdf = Scrypt(
                salt=salt,
                length=KEY_LEN,
                n=2**17,  # OWASP minimum
                r=8,
                p=1,
            )
            return kdf.derive(password)
        else:
            raise ValueError(f"unsupported KDF type: '{kdf_type}'")
    finally:
        _KDF_SEMAPHORE.release()


def serialize_public_bundle(bundle: PublicBundle) -> str:
    """Serialize a PublicBundle to a JSON string."""
    data = {
        "profile_id": bundle.profile_id,
        "public_keys": [
            {"alg_id": alg_id, "key_b64": base64.b64encode(pub).decode("ascii")}
            for alg_id, pub in bundle.public_keys
        ],
    }
    return json.dumps(data, indent=2)


def deserialize_public_bundle(json_str: str) -> PublicBundle:
    """Deserialize a PublicBundle from a JSON string."""
    try:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            raise ValueError("Root object must be a JSON object")
        
        profile_id = data.get("profile_id")
        if not isinstance(profile_id, str):
            raise ValueError("Missing or invalid profile_id")

        pk_list = data.get("public_keys")
        if not isinstance(pk_list, list):
            raise ValueError("Missing or invalid public_keys list")

        public_keys = []
        for item in pk_list:
            if not isinstance(item, dict):
                raise ValueError("Public key entry must be a JSON object")
            
            alg_id = item.get("alg_id")
            key_b64 = item.get("key_b64")
            if not isinstance(alg_id, str) or not isinstance(key_b64, str):
                raise ValueError("Missing or invalid alg_id or key_b64")
            
            public_keys.append((alg_id, base64.b64decode(key_b64, validate=True)))
            
        return PublicBundle(profile_id=profile_id, public_keys=public_keys)
    except Exception as e:
        raise DecryptionError(f"Malformed public bundle: {e}") from e


def export_keyset_bytes(keyset: KeySet, password: str | bytes, *, use_argon2: bool = True) -> bytes:
    """Export a KeySet as encrypted bytes protected by password.

    Default KDF is Argon2id (`CFLA` header). Set `use_argon2=False` for Scrypt (`CFLK` header).
    """
    if keyset.profile.profile_id != keyset.public_bundle.profile_id:
        raise ValueError("cannot export keyset: profile mismatch between keyset and public bundle")
    if len(keyset.profile.sources) != len(keyset.public_bundle.public_keys):
        raise ValueError("cannot export keyset: component count mismatch between profile and public bundle")
    if len(keyset.profile.sources) != len(keyset.private_handles):
        raise ValueError("cannot export keyset: component count mismatch between profile and private handles")
    serialized_privates = []
    for source, priv_handle in zip(keyset.profile.sources, keyset.private_handles):
        alg_id = source.algorithm_id
        try:
            priv_bytes = source.serialize_private(priv_handle)
        except Exception as e:
            raise DecryptionError(f"cannot serialize private handle for '{alg_id}'") from e

        serialized_privates.append(
            {"alg_id": alg_id, "priv_b64": base64.b64encode(priv_bytes).decode("ascii")}
        )

    payload = {
        "profile_id": keyset.profile.profile_id,
        "public_bundle": json.loads(serialize_public_bundle(keyset.public_bundle)),
        "private_handles": serialized_privates,
    }
    plaintext = json.dumps(payload).encode("utf-8")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    magic = MAGIC_KEYSTORE_ARGON2 if use_argon2 else MAGIC_KEYSTORE_SCRYPT
    kdf_type = "argon2id" if use_argon2 else "scrypt"

    wrapping_key = _derive_wrapping_key(password, salt, kdf_type=kdf_type)

    aesgcm = AESGCM(wrapping_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, magic)

    return magic + salt + nonce + ct_with_tag


def import_keyset_bytes(data: bytes, password: str | bytes) -> KeySet:
    """Import and decrypt a KeySet from bytes using password.

    Supports both Argon2id (`CFLA`) and Scrypt (`CFLK`) keystores.
    """
    # Size limit: reject oversized blobs before any allocation or KDF attempt.
    if len(data) > MAX_KEYSTORE_SIZE:
        raise DecryptionError(
            f"keystore exceeds maximum accepted size ({MAX_KEYSTORE_SIZE} bytes)"
        )
    if len(data) < 4 + SALT_LEN + NONCE_LEN:
        raise DecryptionError("invalid or corrupted keystore format")

    magic = data[:4]
    if magic == MAGIC_KEYSTORE_ARGON2:
        kdf_type = "argon2id"
    elif magic == MAGIC_KEYSTORE_SCRYPT:
        kdf_type = "scrypt"
    else:
        raise DecryptionError("invalid or unrecognized keystore magic")

    salt = data[4 : 4 + SALT_LEN]
    nonce = data[4 + SALT_LEN : 4 + SALT_LEN + NONCE_LEN]
    ct_with_tag = data[4 + SALT_LEN + NONCE_LEN :]

    wrapping_key = _derive_wrapping_key(password, salt, kdf_type=kdf_type)
    aesgcm = AESGCM(wrapping_key)

    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, magic)
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise DecryptionError("invalid password or corrupted keystore") from e

    try:
        keystore_profile_id = payload["profile_id"]
        if not isinstance(keystore_profile_id, str) or not keystore_profile_id:
            raise DecryptionError("invalid or missing profile_id in keystore")
        profile = get_profile(keystore_profile_id)
    except (ValueError, KeyError) as e:
        raise DecryptionError(f"unrecognized profile: {e}") from e
    bundle = deserialize_public_bundle(json.dumps(payload["public_bundle"]))

    # Cross-binding: keystore profile_id, public_bundle profile_id, and
    # registered SecurityProfile must all agree. A mismatch indicates a
    # corrupt or mismatched keystore/bundle pair.
    if bundle.profile_id != keystore_profile_id:
        raise DecryptionError(
            "keystore profile_id does not match public_bundle profile_id: "
            f"'{keystore_profile_id}' vs '{bundle.profile_id}'"
        )
    if profile.profile_id != keystore_profile_id:
        raise DecryptionError(
            "registered profile_id does not match keystore profile_id: "
            f"'{profile.profile_id}' vs '{keystore_profile_id}'"
        )

    private_handles_payload = payload.get("private_handles", [])
    if not isinstance(private_handles_payload, list):
        raise DecryptionError("invalid private_handles structure")

    if len(profile.sources) != len(private_handles_payload):
        raise DecryptionError(
            f"structural mismatch: profile requires {len(profile.sources)} sources, "
            f"but keystore contains {len(private_handles_payload)} private handles"
        )
    if len(profile.sources) != len(bundle.public_keys):
        raise DecryptionError(
            f"structural mismatch: profile requires {len(profile.sources)} sources, "
            f"but public bundle contains {len(bundle.public_keys)} public keys"
        )

    private_handles = []
    for source, item, (bundle_alg_id, _) in zip(profile.sources, private_handles_payload, bundle.public_keys):
        if not isinstance(item, dict):
            raise DecryptionError("invalid private handle entry structure")
            
        alg_id = item.get("alg_id")
        if not isinstance(alg_id, str):
            raise DecryptionError("missing or invalid alg_id in private handle")
            
        if source.algorithm_id != alg_id:
            raise DecryptionError(
                f"mismatched component algorithm in keystore: expected '{source.algorithm_id}', got '{alg_id}'"
            )
        if source.algorithm_id != bundle_alg_id:
            raise DecryptionError(
                f"mismatched component algorithm in public bundle: expected '{source.algorithm_id}', got '{bundle_alg_id}'"
            )

        priv_b64 = item.get("priv_b64")
        if not isinstance(priv_b64, str):
            raise DecryptionError(f"missing or invalid priv_b64 for '{alg_id}'")

        try:
            priv_bytes = base64.b64decode(priv_b64, validate=True)
            priv_handle = source.deserialize_private(priv_bytes)
        except Exception as e:
            raise DecryptionError(f"failed to deserialize private key for '{alg_id}': {e}") from e
        private_handles.append(priv_handle)

    decision = PolicyDecision(
        profile=profile,
        reason="imported from keystore",
        degraded=False,
        min_accepted_profile=profile.profile_id,
    )

    return KeySet(
        profile=profile,
        public_bundle=bundle,
        private_handles=private_handles,
        policy_decision=decision,
    )
