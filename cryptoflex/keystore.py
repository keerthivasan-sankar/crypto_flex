"""
cryptoflex.keystore
====================

Encrypted Password-Wrapped Storage for KeySets and PublicBundles.

Security Rationale
-------------------
Private key handles returned by `establish_keys()` must never be stored as
plaintext on disk.  This module provides:
  - Password key derivation using Scrypt (N=2^15, r=8, p=1)
  - KeySet wrapping under AES-256-GCM with a 12-byte random nonce
  - JSON serialization for PublicBundle and encrypted KeySet files

File Formats:
  1. `.bundle.json`: PublicBundle (unencrypted public keys + profile_id)
  2. `.keyset.cflk`: Password-encrypted KeySet payload containing private keys
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .api import KeySet, PublicBundle
from .errors import DecryptionError
from .policy import PolicyDecision
from .profiles import get_profile

MAGIC_KEYSTORE = b"CFLK"
SCRYPT_SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32


def _derive_wrapping_key(password: str | bytes, salt: bytes) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(password)


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


def export_keyset_bytes(keyset: KeySet, password: str | bytes) -> bytes:
    """Export a KeySet as encrypted bytes protected by password."""
    serialized_privates = []
    for source, priv_handle in zip(keyset.profile.sources, keyset.private_handles):
        alg_id = source.algorithm_id
        try:
            priv_bytes = source.serialize_private(priv_handle)
        except Exception as e:
            raise TypeError(f"cannot serialize private handle for '{alg_id}': {e}") from e

        serialized_privates.append(
            {"alg_id": alg_id, "priv_b64": base64.b64encode(priv_bytes).decode("ascii")}
        )

    payload = {
        "profile_id": keyset.profile.profile_id,
        "public_bundle": json.loads(serialize_public_bundle(keyset.public_bundle)),
        "private_handles": serialized_privates,
    }
    plaintext = json.dumps(payload).encode("utf-8")

    salt = os.urandom(SCRYPT_SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    wrapping_key = _derive_wrapping_key(password, salt)

    aesgcm = AESGCM(wrapping_key)
    aad = MAGIC_KEYSTORE
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

    return MAGIC_KEYSTORE + salt + nonce + ct_with_tag


def import_keyset_bytes(data: bytes, password: str | bytes) -> KeySet:
    """Import and decrypt a KeySet from bytes using password."""
    if len(data) < 4 + SCRYPT_SALT_LEN + NONCE_LEN or data[:4] != MAGIC_KEYSTORE:
        raise DecryptionError("invalid or corrupted keystore format")

    salt = data[4 : 4 + SCRYPT_SALT_LEN]
    nonce = data[4 + SCRYPT_SALT_LEN : 4 + SCRYPT_SALT_LEN + NONCE_LEN]
    ct_with_tag = data[4 + SCRYPT_SALT_LEN + NONCE_LEN :]

    wrapping_key = _derive_wrapping_key(password, salt)
    aesgcm = AESGCM(wrapping_key)

    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, MAGIC_KEYSTORE)
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
