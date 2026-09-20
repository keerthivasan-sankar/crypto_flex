#!/usr/bin/env python3
"""
benchmark_performance.py
=========================
Reproducible performance evaluation for CryptoFlex operations across profiles.

Measures actual execution times for:
  - Key generation (establish_keys)
  - Key derivation / encapsulation (derive_root_key)
  - AEAD payload encryption (encrypt)
  - AEAD payload decryption (decrypt)
  - Streaming encryption/decryption (1 MB payload)

Outputs empirical timing metrics (mean, stddev, ops/sec).
No hardcoded or fabricated numbers.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

# Add project root to path if needed
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptoflex.api import decrypt, derive_root_key, encrypt, establish_keys
from cryptoflex.streaming import decrypt_stream, encrypt_stream
from cryptoflex.policy import Constraint, PolicyEngine
from cryptoflex.profiles import SecurityProfile, get_profile


class FixedEngine:
    def __init__(self, profile: SecurityProfile):
        self._profile = profile

    def decide(self, constraint=Constraint.BALANCED, *, require_quantum_safe=False):
        from cryptoflex.policy import PolicyDecision
        return PolicyDecision(
            profile=self._profile,
            reason="benchmark fixed profile",
            degraded=False,
            min_accepted_profile=self._profile.profile_id,
        )


def benchmark_op(func, iterations: int = 100) -> dict[str, float]:
    """Runs func for iterations and returns timing statistics."""
    # Warmup
    for _ in range(max(1, iterations // 10)):
        func()

    times: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        func()
        t1 = time.perf_counter()
        times.append(t1 - t0)

    mean_sec = sum(times) / len(times)
    variance = sum((x - mean_sec) ** 2 for x in times) / (len(times) - 1) if len(times) > 1 else 0.0
    stddev_sec = variance ** 0.5
    ops_per_sec = 1.0 / mean_sec if mean_sec > 0 else 0.0

    return {
        "iterations": iterations,
        "mean_ms": mean_sec * 1000.0,
        "stddev_ms": stddev_sec * 1000.0,
        "ops_per_sec": ops_per_sec,
    }


def run_benchmarks(iterations: int = 100) -> dict:
    results = {}
    profiles_to_test = ["classical_only", "hybrid_standard", "hybrid_high"]

    plaintext_1k = b"X" * 1024
    plaintext_1m = b"S" * (1024 * 1024)

    for pid in profiles_to_test:
        prof = get_profile(pid)
        if not prof.is_available():
            print(f"Skipping profile '{pid}' (not available in this environment)")
            continue

        engine = FixedEngine(prof)
        keyset = establish_keys(engine)

        print(f"\nBenchmarking profile: {pid} ({prof.display_name})...")

        # 1. Key generation
        keygen_stats = benchmark_op(lambda: establish_keys(engine), iterations=iterations)
        print(f"  - Keygen        : {keygen_stats['mean_ms']:.3f} ms/op ({keygen_stats['ops_per_sec']:.1f} ops/sec)")

        # 2. Derive root key
        derive_stats = benchmark_op(lambda: derive_root_key(keyset.public_bundle), iterations=iterations)
        print(f"  - Derive RootKey: {derive_stats['mean_ms']:.3f} ms/op ({derive_stats['ops_per_sec']:.1f} ops/sec)")

        # 3. Encrypt 1 KB
        enc_stats = benchmark_op(lambda: encrypt(keyset.public_bundle, plaintext_1k), iterations=iterations)
        blob = encrypt(keyset.public_bundle, plaintext_1k)
        print(f"  - Encrypt (1KB) : {enc_stats['mean_ms']:.3f} ms/op ({enc_stats['ops_per_sec']:.1f} ops/sec)")

        # 4. Decrypt 1 KB
        dec_stats = benchmark_op(lambda: decrypt(keyset.private_handles, blob), iterations=iterations)
        print(f"  - Decrypt (1KB) : {dec_stats['mean_ms']:.3f} ms/op ({dec_stats['ops_per_sec']:.1f} ops/sec)")

        # 5. Stream Encrypt 1 MB
        def _bench_st_enc():
            inp = io.BytesIO(plaintext_1m)
            outp = io.BytesIO()
            encrypt_stream(keyset.public_bundle, inp, outp)
            return outp.getvalue()

        st_enc_stats = benchmark_op(_bench_st_enc, iterations=max(10, iterations // 5))
        st_blob = _bench_st_enc()
        print(f"  - Stream Enc (1MB): {st_enc_stats['mean_ms']:.3f} ms/op ({st_enc_stats['ops_per_sec']:.1f} ops/sec)")

        # 6. Stream Decrypt 1 MB
        def _bench_st_dec():
            inp = io.BytesIO(st_blob)
            outp = io.BytesIO()
            decrypt_stream(keyset.private_handles, inp, outp)
            return outp.getvalue()

        st_dec_stats = benchmark_op(_bench_st_dec, iterations=max(10, iterations // 5))
        print(f"  - Stream Dec (1MB): {st_dec_stats['mean_ms']:.3f} ms/op ({st_dec_stats['ops_per_sec']:.1f} ops/sec)")

        results[pid] = {
            "display_name": prof.display_name,
            "keygen": keygen_stats,
            "derive_root_key": derive_stats,
            "encrypt_1k": enc_stats,
            "decrypt_1k": dec_stats,
            "stream_encrypt_1m": st_enc_stats,
            "stream_decrypt_1m": st_dec_stats,
        }

    return results


def main():
    print("=" * 70)
    print("  CryptoFlex Performance Evaluation Benchmark")
    print("=" * 70)

    results = run_benchmarks(iterations=50)

    out_dir = REPO_ROOT / "docs" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "benchmark-results.json"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved empirical benchmark metrics to: {json_path}")


if __name__ == "__main__":
    main()
