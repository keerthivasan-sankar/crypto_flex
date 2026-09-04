"""
cryptoflex.cli
===============

Command Line Interface for cryptoflex v0.4.0.

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
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from .api import decrypt, encrypt, establish_keys, migrate_file
from .header import CryptoflexHeader
from .keystore import (
    deserialize_public_bundle,
    export_keyset_bytes,
    import_keyset_bytes,
    serialize_public_bundle,
)
from .policy import Constraint
from .streaming import decrypt_stream, encrypt_stream




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

            bundle_json = serialize_public_bundle(keyset.public_bundle)
            with open(parsed.bundle, "w", encoding="utf-8") as f:
                f.write(bundle_json)

            use_argon2 = parsed.kdf == "argon2id"
            keyset_bytes = export_keyset_bytes(keyset, password, use_argon2=use_argon2)
            with open(parsed.key, "wb") as f:
                f.write(keyset_bytes)

            print(f"Keypair generated under profile '{keyset.profile.profile_id}' (KDF: {parsed.kdf}).")
            print(f"  Public bundle saved to: {parsed.bundle}")
            print(f"  Encrypted key saved to: {parsed.key}")
            return 0

        elif parsed.command == "encrypt":
            with open(parsed.bundle, "r", encoding="utf-8") as f:
                bundle = deserialize_public_bundle(f.read())

            if parsed.stream:
                with open(parsed.input_path, "rb") as fin, open(parsed.output_path, "wb") as fout:
                    encrypt_stream(bundle, fin, fout)
            else:
                with open(parsed.input_path, "rb") as fin:
                    plaintext = fin.read()
                blob = encrypt(bundle, plaintext)
                with open(parsed.output_path, "wb") as fout:
                    fout.write(blob)

            print(f"Successfully encrypted '{parsed.input_path}' -> '{parsed.output_path}'")
            return 0

        elif parsed.command == "decrypt":
            password = _resolve_password(parsed.password, "Enter keyset password: ")
            with open(parsed.key, "rb") as f:
                key_bytes = f.read()
            keyset = import_keyset_bytes(key_bytes, password)

            if parsed.stream:
                with open(parsed.input_path, "rb") as fin, open(parsed.output_path, "wb") as fout:
                    decrypt_stream(keyset.private_handles, fin, fout, min_profile=parsed.min_profile)
            else:
                with open(parsed.input_path, "rb") as fin:
                    blob = fin.read()
                plaintext = decrypt(keyset.private_handles, blob, min_profile=parsed.min_profile)
                with open(parsed.output_path, "wb") as fout:
                    fout.write(plaintext)

            print(f"Successfully decrypted '{parsed.input_path}' -> '{parsed.output_path}'")
            return 0

        elif parsed.command == "migrate":
            password = _resolve_password(parsed.password, "Enter keyset password: ")
            with open(parsed.key, "rb") as f:
                key_bytes = f.read()
            keyset = import_keyset_bytes(key_bytes, password)

            with open(parsed.new_bundle, "r", encoding="utf-8") as f:
                new_bundle = deserialize_public_bundle(f.read())

            migrate_file(
                keyset.private_handles,
                parsed.input_path,
                parsed.output_path,
                new_bundle,
                min_profile=parsed.min_profile,
                stream=parsed.stream,
            )

            print(f"Successfully migrated '{parsed.input_path}' to target bundle profile '{new_bundle.profile_id}' -> '{parsed.output_path}'")
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

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
