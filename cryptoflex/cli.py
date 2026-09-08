"""
cryptoflex.cli
===============

Command Line Interface for cryptoflex v0.5.2.

Usage:
  cryptoflex keygen --key key.cflk --bundle bundle.json [--password PASS] [--kdf {argon2id,scrypt}]
  cryptoflex encrypt --in input.dat --out output.cflx --bundle bundle.json [--stream]
  cryptoflex decrypt --in output.cflx --out restored.dat --key key.cflk [--password PASS] [--min-profile PROFILE] [--stream]
  cryptoflex migrate --in input.cflx --out migrated.cflx --key key.cflk --new-bundle new_bundle.json [--password PASS]
  cryptoflex info input.cflx

Password handling (in order of precedence):
  1. CRYPTOFLEX_PASSWORD environment variable
  2. --password flag (WARNING: visible in process list on shared systems)
  3. Interactive getpass prompt (safest, used when neither above is set)

Atomic output semantics:
  All file-writing operations (encrypt, decrypt, migrate, keygen) use
  temporary files in the destination directory followed by atomic rename.
  If the operation fails at any point, the original destination file is
  preserved unchanged and the temporary file is removed.

Path alias protection:
  input and output paths that resolve to the same file are rejected.
  This is a protection against detected same-file collisions; it does not
  claim to detect all possible filesystem alias conditions (e.g. bind mounts,
  complex symlink chains).
"""

from __future__ import annotations

import argparse
import getpass
import os
import stat
import sys
import tempfile
from pathlib import Path

from .api import decrypt, encrypt, establish_keys
from .errors import DecryptionError
from .header import CryptoflexHeader
from .keystore import (
    deserialize_public_bundle,
    export_keyset_bytes,
    import_keyset_bytes,
    serialize_public_bundle,
)
from .policy import Constraint
from .streaming import decrypt_stream, encrypt_stream, migrate_stream


def _resolve_password(parsed_password: str | None, prompt: str) -> str:
    """Resolve password from env var, --password flag (with warning), or interactive prompt."""
    env_pw = os.environ.get("CRYPTOFLEX_PASSWORD")
    if env_pw:
        return env_pw
    if parsed_password is not None:
        print(
            "WARNING: --password visible in process list. "
            "Use CRYPTOFLEX_PASSWORD env var or omit for interactive prompt.",
            file=sys.stderr,
        )
        return parsed_password
    return getpass.getpass(prompt)


def _check_path_alias(input_path: str, output_path: str) -> None:
    """Ensure input and output paths do not resolve to the same file.

    NOTE: This check compares resolved paths to catch the common case of
    same-file aliases. It does not claim to detect all possible filesystem
    aliasing conditions (bind mounts, complex symlink chains, etc.).
    """
    try:
        if Path(input_path).resolve() == Path(output_path).resolve():
            raise ValueError(f"input and output paths resolve to the same file: '{input_path}'")
    except (OSError, ValueError):
        raise


def _make_temp_in_dir(dest_path: str) -> tuple[int, str]:
    """Create a secure temporary file in the same directory as dest_path.

    Returns (fd, temp_path). The caller is responsible for closing fd and
    removing temp_path on failure, or replacing dest_path on success.

    Creating the temp file in the same directory as the destination ensures
    os.replace() is atomic (same filesystem).
    """
    dest_dir = os.path.dirname(os.path.abspath(dest_path))
    fd, temp_path = tempfile.mkstemp(dir=dest_dir, prefix=".cryptoflex_tmp_")
    # Restrict permissions immediately on POSIX; no-op on Windows
    try:
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, AttributeError):
        pass
    return fd, temp_path


def _atomic_write_bytes(dest_path: str, data: bytes) -> None:
    """Write data atomically to dest_path using a temp file + rename."""
    fd, temp_path = _make_temp_in_dir(dest_path)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        os.replace(temp_path, dest_path)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def _atomic_stream_write(dest_path: str, write_fn) -> None:
    """Write a file atomically using streaming: write_fn(file_obj) -> None.

    write_fn receives an open binary-writable file object. After write_fn
    returns successfully, the temp file is fsynced and renamed into place.
    If write_fn raises, the temp file is removed and the exception is
    propagated; the original destination is preserved.
    """
    fd, temp_path = _make_temp_in_dir(dest_path)
    try:
        with os.fdopen(fd, "wb") as fout:
            write_fn(fout)
            fout.flush()
            try:
                os.fsync(fout.fileno())
            except (OSError, AttributeError):
                pass
        os.replace(temp_path, dest_path)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cryptoflex",
        description="cryptoflex: local-first crypto-agility policy engine CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- KEYGEN ---
    p_keygen = subparsers.add_parser("keygen", help="Generate a fresh keypair and password-encrypt the private keyset")
    p_keygen.add_argument("--key", required=True, help="Output path for password-encrypted KeySet (.cflk)")
    p_keygen.add_argument("--bundle", required=True, help="Output path for PublicBundle (.json)")
    p_keygen.add_argument("--password", default=None, help="Passphrase (use CRYPTOFLEX_PASSWORD env var or omit for prompt)")
    p_keygen.add_argument(
        "--kdf",
        choices=["argon2id", "scrypt"],
        default="argon2id",
        help="Keystore password key derivation algorithm (default: argon2id)",
    )
    p_keygen.add_argument(
        "--constraint",
        choices=["fast", "balanced", "max_security"],
        default="balanced",
        help="Policy constraint preference",
    )

    # --- ENCRYPT ---
    p_enc = subparsers.add_parser("encrypt", help="Encrypt a file using recipient's PublicBundle")
    p_enc.add_argument("--in", dest="input_path", required=True, help="Input file path")
    p_enc.add_argument("--out", dest="output_path", required=True, help="Output encrypted file path (.cflx)")
    p_enc.add_argument("--bundle", required=True, help="Recipient PublicBundle JSON file path")
    p_enc.add_argument("--stream", action="store_true", help="Use chunked streaming mode for large files")

    # --- DECRYPT ---
    p_dec = subparsers.add_parser("decrypt", help="Decrypt an encrypted file (.cflx)")
    p_dec.add_argument("--in", dest="input_path", required=True, help="Encrypted file path (.cflx)")
    p_dec.add_argument("--out", dest="output_path", required=True, help="Output restored file path")
    p_dec.add_argument("--key", required=True, help="Password-encrypted KeySet file path (.cflk)")
    p_dec.add_argument("--password", default=None, help="Passphrase (use CRYPTOFLEX_PASSWORD env var or omit for prompt)")
    p_dec.add_argument("--min-profile", help="Minimum required profile ID to prevent downgrades")
    p_dec.add_argument("--stream", action="store_true", help="Use chunked streaming mode for large files")

    # --- MIGRATE ---
    p_mig = subparsers.add_parser("migrate", help="Re-encrypt a .cflx file under a new PublicBundle (offline migration)")
    p_mig.add_argument("--in", dest="input_path", required=True, help="Existing encrypted file path (.cflx)")
    p_mig.add_argument("--out", dest="output_path", required=True, help="Migrated output file path (.cflx)")
    p_mig.add_argument("--key", required=True, help="Current KeySet file path (.cflk)")
    p_mig.add_argument("--new-bundle", required=True, help="Target new PublicBundle JSON file path")
    p_mig.add_argument("--password", default=None, help="Passphrase for KeySet")
    p_mig.add_argument("--min-profile", help="Minimum required profile ID for existing ciphertext")
    p_mig.add_argument("--stream", action="store_true", help="Use chunked streaming mode for large files")

    # --- INFO ---
    p_info = subparsers.add_parser("info", help="Inspect metadata from a .cflx encrypted file header")
    p_info.add_argument("file", help="Path to .cflx file")

    parsed = parser.parse_args(args)

    try:
        if parsed.command == "keygen":
            password = _resolve_password(parsed.password, "Enter new keyset password: ")
            constraint = Constraint(parsed.constraint)
            keyset = establish_keys(constraint=constraint)

            # Build both artifacts in memory first
            bundle_json = serialize_public_bundle(keyset.public_bundle)
            use_argon2 = parsed.kdf == "argon2id"
            keyset_bytes = export_keyset_bytes(keyset, password, use_argon2=use_argon2)

            # Write bundle file atomically first (public, non-secret)
            _atomic_write_bytes(parsed.bundle, bundle_json.encode("utf-8"))

            # Write encrypted key file atomically, with restrictive permissions
            fd, temp_key_path = _make_temp_in_dir(parsed.key)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(keyset_bytes)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except (OSError, AttributeError):
                        pass
                os.replace(temp_key_path, parsed.key)
                # Set restrictive permissions on the final key file
                try:
                    os.chmod(parsed.key, stat.S_IRUSR | stat.S_IWUSR)
                except (OSError, AttributeError):
                    pass
            except Exception:
                try:
                    os.unlink(temp_key_path)
                except OSError:
                    pass
                raise

            print(f"Keypair generated under profile '{keyset.profile.profile_id}' (KDF: {parsed.kdf}).")
            print(f"  Public bundle saved to: {parsed.bundle}")
            print(f"  Encrypted key saved to: {parsed.key}")
            return 0

        elif parsed.command == "encrypt":
            _check_path_alias(parsed.input_path, parsed.output_path)
            with open(parsed.bundle, "r", encoding="utf-8") as f:
                bundle = deserialize_public_bundle(f.read())

            if parsed.stream:
                with open(parsed.input_path, "rb") as fin:
                    _atomic_stream_write(
                        parsed.output_path,
                        lambda fout: encrypt_stream(bundle, fin, fout),
                    )
            else:
                with open(parsed.input_path, "rb") as fin:
                    plaintext = fin.read()
                blob = encrypt(bundle, plaintext)
                del plaintext
                _atomic_write_bytes(parsed.output_path, blob)

            print(f"Successfully encrypted '{parsed.input_path}' -> '{parsed.output_path}'")
            return 0

        elif parsed.command == "decrypt":
            _check_path_alias(parsed.input_path, parsed.output_path)
            password = _resolve_password(parsed.password, "Enter keyset password: ")
            with open(parsed.key, "rb") as f:
                key_bytes = f.read()
            keyset = import_keyset_bytes(key_bytes, password)

            if parsed.stream:
                with open(parsed.input_path, "rb") as fin:
                    _atomic_stream_write(
                        parsed.output_path,
                        lambda fout: decrypt_stream(
                            keyset.private_handles, fin, fout, min_profile=parsed.min_profile
                        ),
                    )
            else:
                with open(parsed.input_path, "rb") as fin:
                    blob = fin.read()
                plaintext = decrypt(keyset.private_handles, blob, min_profile=parsed.min_profile)
                _atomic_write_bytes(parsed.output_path, plaintext)
                del plaintext

            print(f"Successfully decrypted '{parsed.input_path}' -> '{parsed.output_path}'")
            return 0

        elif parsed.command == "migrate":
            _check_path_alias(parsed.input_path, parsed.output_path)
            password = _resolve_password(parsed.password, "Enter keyset password: ")
            with open(parsed.key, "rb") as f:
                key_bytes = f.read()
            keyset = import_keyset_bytes(key_bytes, password)

            with open(parsed.new_bundle, "r", encoding="utf-8") as f:
                new_bundle = deserialize_public_bundle(f.read())

            if parsed.stream:
                with open(parsed.input_path, "rb") as fin:
                    _atomic_stream_write(
                        parsed.output_path,
                        lambda fout: migrate_stream(
                            keyset.private_handles,
                            fin,
                            fout,
                            new_bundle,
                            min_profile=parsed.min_profile,
                        ),
                    )
            else:
                with open(parsed.input_path, "rb") as fin:
                    blob = fin.read()
                from .api import migrate
                migrated = migrate(
                    keyset.private_handles,
                    blob,
                    new_bundle,
                    min_profile=parsed.min_profile,
                )
                _atomic_write_bytes(parsed.output_path, migrated)

            print(
                f"Successfully migrated '{parsed.input_path}' to target bundle"
                f" profile '{new_bundle.profile_id}' -> '{parsed.output_path}'"
            )
            return 0

        elif parsed.command == "info":
            with open(parsed.file, "rb") as f:
                data = f.read(65536)  # 64 KB — enough for any realistic header
            header, consumed = CryptoflexHeader.from_bytes(data)

            print("==================================================")
            print(f"  cryptoflex File Header Inspection: {parsed.file}")
            print("==================================================")
            print("Magic               : CFLX")
            print(f"Header Version      : {header.version}")
            print(f"Profile ID          : {header.profile_id}")
            print(f"Header Consumed     : {consumed} bytes")
            if header.nonce:
                print(f"AES-GCM Base Nonce  : {header.nonce.hex()}")
            print(f"Components ({len(header.components)}):")
            for alg_id, ct in header.components:
                print(f"  - {alg_id}: {len(ct)} bytes ciphertext")
            print("==================================================")
            return 0

    except DecryptionError as e:
        # Normalize decryption failures without leaking internal detail
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
