"""
cryptoflex.ephemeral
======================

Ephemeral (forward-secret) encryption for messaging workloads.

Design
-------
For file encryption, static long-lived keypairs are appropriate because
the sender can look up the recipient's public key, encrypt, and the
recipient decrypts later with the same private key.

For *messaging*, each message should use fresh ephemeral keys that are
discarded immediately after use.  If an attacker captures the private
key of one party later, they still cannot decrypt past messages because
the ephemeral keys were never saved anywhere.

How it works
-------------
``ephemeral_encrypt(recipient_bundle, plaintext)`` calls ``derive_root_key()``
directly.  Inside ``derive_root_key()``, each source calls
``encapsulate(peer_public_key)`` which — for ECDH sources — generates a
fresh ephemeral keypair, completes the exchange, and discards the
ephemeral private key immediately.  The KEM ciphertext (carrying the
sender's ephemeral public key) is stored in the header, so the recipient
can decapsulate and recover the shared secret.

There is NO separate ``establish_ephemeral_keys()`` step.  The prior v0.3.x
draft incorrectly added one, generating keypairs that were then ignored.
The ephemeral key is generated and consumed inside ``encapsulate()``; no
EphemeralKeySet or intermediate object is needed.

Wire Format
-----------
``ephemeral_encrypt()`` returns a ``WireMessage`` dataclass containing a
single ``encrypted_blob`` field — a self-contained bytes object identical
to the output of ``encrypt()``:

    header_bytes || AES-GCM(ciphertext || 16-byte tag)

The header carries the KEM ciphertexts (i.e., the sender's ephemeral
public material) so the recipient can recover the root key.  Since a new
root key is derived per message, each message is independently forward-
secret.
"""

from __future__ import annotations

from dataclasses import dataclass

from .api import PublicBundle, decrypt, derive_root_key

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class WireMessage:
    """Self-contained encrypted message blob produced by ephemeral_encrypt().

    ``encrypted_blob`` is identical in format to the output of ``encrypt()``:
        header_bytes || AES-GCM(ciphertext || 16-byte tag)

    The header embeds the sender's ephemeral KEM ciphertext(s) so the
    recipient can decapsulate without the sender needing to remain online.
    """

    encrypted_blob: bytes


def ephemeral_encrypt(
    recipient_bundle: PublicBundle,
    plaintext: bytes,
) -> WireMessage:
    """Encrypt a message for ``recipient_bundle`` using fresh ephemeral keys.

    Each call generates a completely fresh root key via ``derive_root_key()``,
    which internally calls ``source.encapsulate()`` for each component.
    The ephemeral key material is embedded in the returned ``WireMessage``
    and is not stored anywhere else.

    Returns a ``WireMessage`` whose ``encrypted_blob`` can be transmitted
    and later decrypted by the recipient using ``ephemeral_decrypt()``.
    """
    derived = derive_root_key(recipient_bundle)
    header_bytes = derived.header.to_bytes()
    nonce = derived.header.nonce
    if nonce is None:
        raise ValueError("derive_root_key() returned a v1 header with no nonce")

    aesgcm = AESGCM(derived.root_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, header_bytes)

    return WireMessage(encrypted_blob=header_bytes + ct_with_tag)


def ephemeral_decrypt(
    private_handles: list[object],
    message: WireMessage,
    *,
    min_profile: str | None = None,
) -> bytes:
    """Decrypt a ``WireMessage`` produced by ``ephemeral_encrypt()``.

    ``private_handles`` must be the long-lived private key handles of the
    recipient (from ``establish_keys()``).  These are used to decapsulate
    the sender's ephemeral KEM ciphertext from the message header.

    If ``min_profile`` is specified, raises ``DowngradeError`` if the
    message was encrypted under a weaker profile than required.

    All crypto failures collapse into ``DecryptionError``.
    """
    return decrypt(private_handles, message.encrypted_blob, min_profile=min_profile)
