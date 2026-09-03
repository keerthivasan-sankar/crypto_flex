"""
cryptoflex.errors
====================

Uniform error types for cryptoflex.

Design rationale (from Mahidul Haque's review, Discussion #2534):
    "Do not expose distinguishable errors or timing for 'classical
    failed', 'ML-KEM failed', and 'payload authentication failed'.
    Derive the candidate key according to the specified combiner,
    perform authentication, and return one generic failure at the
    API boundary."

DecryptionError is the ONLY exception that should ever escape the
decrypt() / recover_root_key() boundary. Callers never learn whether
the classical source, the PQC source, or the AEAD tag check was the
step that failed - all they see is "decryption failed".

DowngradeError is a subclass of DecryptionError raised BEFORE any
cryptographic operation when the header's profile is weaker than the
caller's stated minimum. This is a policy check, not a crypto failure,
but it still surfaces through the same exception hierarchy so callers
only need one except clause.
"""

from __future__ import annotations


class DecryptionError(Exception):
    """Generic decryption failure.

    This is intentionally vague: it does NOT reveal which source failed,
    which step failed, or any internal detail that would help an attacker
    distinguish between failure modes.
    """


class DowngradeError(DecryptionError):
    """The header's recorded profile is weaker than the caller's stated
    minimum accepted profile.

    Raised BEFORE any cryptographic operation is attempted, so no timing
    side-channel exists between this and a genuine decryption failure.
    """
