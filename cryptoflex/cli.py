"""
cryptoflex.cli
===============

Command Line Interface for cryptoflex v0.3.0.

Usage:
  cryptoflex keygen --key key.cflk --bundle bundle.json --password PASS
  cryptoflex encrypt --in input.dat --out output.cflx --bundle bundle.json [--stream]
  cryptoflex decrypt --in output.cflx --out restored.dat --key key.cflk --password PASS [--min-profile PROFILE] [--stream]
  cryptoflex info input.cflx
"""

from __future__ import annotations

import argparse
import sys

from .api import decrypt, encrypt, establish_keys
from .header import CryptoflexHeader
from .keystore import (
    deserialize_public_bundle,
    export_keyset_bytes,
    import_keyset_bytes,
    serialize_public_bundle,
)
from .policy import Constraint
from .streaming import decrypt_stream, encrypt_stream


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
    p_keygen.add_argument("--password", required=True, help="Passphrase to encrypt the private key file")
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
    p_dec.add_argument("--password", required=True, help="Passphrase to unlock private key file")
    p_dec.add_argument("--min-profile", help="Minimum required profile ID to prevent downgrades")
    p_dec.add_argument("--stream", action="store_true", help="Use chunked streaming mode for large files")

    # --- INFO ---
    p_info = subparsers.add_parser("info", help="Inspect metadata from a .cflx encrypted file header")
    p_info.add_argument("file", help="Path to .cflx file")

    parsed = parser.parse_args(args)

    try:
        if parsed.command == "keygen":
            constraint = Constraint(parsed.constraint)
            keyset = establish_keys(constraint=constraint)

            bundle_json = serialize_public_bundle(keyset.public_bundle)
            with open(parsed.bundle, "w", encoding="utf-8") as f:
                f.write(bundle_json)

            keyset_bytes = export_keyset_bytes(keyset, parsed.password)
            with open(parsed.key, "wb") as f:
                f.write(keyset_bytes)

            print(f"Keypair generated under profile '{keyset.profile.profile_id}'.")
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
            with open(parsed.key, "rb") as f:
                key_bytes = f.read()
            keyset = import_keyset_bytes(key_bytes, parsed.password)

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

        elif parsed.command == "info":
            with open(parsed.file, "rb") as f:
                data = f.read(4096)
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
