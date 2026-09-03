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

# Cap concurrent memory-hard KDF derivations to 2 to prevent RAM exhaustion DoS
_KDF_SEMAPHORE = threading.Semaphore(2)


def _derive_wrapping_key(password: str | bytes, salt: bytes, kdf_type: str = "argon2id") -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")

    with _KDF_SEMAPHORE:
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
    data = json.loads(json_str)
    public_keys = [
        (item["alg_id"], base64.b64decode(item["key_b64"]))
        for item in data["public_keys"]
    ]
    return PublicBundle(profile_id=data["profile_id"], public_keys=public_keys)


def export_keyset_bytes(keyset: KeySet, password: str | bytes, *, use_argon2: bool = True) -> bytes:
    """Export a KeySet as encrypted bytes protected by password.

    Default KDF is Argon2id (`CFLA` header). Set `use_argon2=False` for Scrypt (`CFLK` header).
    """
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

    profile = get_profile(payload["profile_id"])
    bundle = deserialize_public_bundle(json.dumps(payload["public_bundle"]))

    private_handles = []
    for source, item in zip(profile.sources, payload["private_handles"]):
        alg_id = item["alg_id"]
        if source.algorithm_id != alg_id:
            raise DecryptionError(
                f"mismatched component algorithm in keystore: expected '{source.algorithm_id}', got '{alg_id}'"
            )
        priv_bytes = base64.b64decode(item["priv_b64"])
        try:
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
