#!/usr/bin/env python3
"""
generate_validation_graph.py
=============================

Generates docs/results/validation-results.svg from actual CryptoFlex
test and verification results.

Usage:
    python scripts/generate_validation_graph.py

The script runs pytest and verify_local.py, parses their output,
and writes a self-contained SVG visualization of the results.

No external dependencies beyond Python 3.10+ standard library and
the project's own test dependencies (pytest, hypothesis).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_pytest(repo_root: str) -> dict:
    """Run pytest and parse results."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", "--tb=no"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        env={**os.environ, "CRYPTOFLEX_DISABLE_PQC": ""},
    )
    output = result.stdout + result.stderr

    # Parse summary line: "128 passed in 9.25s" or "127 passed, 1 failed in 5s"
    summary_match = re.search(
        r"(\d+)\s+passed(?:,\s*(\d+)\s+failed)?(?:,\s*(\d+)\s+skipped)?\s+in",
        output,
    )
    passed = int(summary_match.group(1)) if summary_match else 0
    failed = int(summary_match.group(2) or 0) if summary_match else 0
    skipped = int(summary_match.group(3) or 0) if summary_match else 0
    total = passed + failed + skipped

    # Parse per-file counts from verbose lines like:
    # tests/test_header.py::test_rejects_bad_magic PASSED [ 39%]
    # tests\test_header.py::test_rejects_bad_magic PASSED [  0%]
    file_counts: dict[str, dict[str, int]] = {}
    for line in output.splitlines():
        line = line.strip()
        m = re.search(r"tests[/\\](test_\w+)\.py::\S+\s+(PASSED|FAILED|SKIPPED)", line)
        if m:
            fname = m.group(1)
            status = m.group(2).lower()
            if fname not in file_counts:
                file_counts[fname] = {"passed": 0, "failed": 0, "skipped": 0}
            file_counts[fname][status] += 1

    # Map test files to human-readable category names
    category_map = {
        "test_adversarial": "Adversarial",
        "test_cli": "CLI",
        "test_combiner": "Combiner",
        "test_cross_version": "Cross-Version",
        "test_encrypt_decrypt": "Encrypt/Decrypt",
        "test_ephemeral": "Ephemeral",
        "test_fuzz_header": "Fuzz (Hypothesis)",
        "test_header": "Header Parsing",
        "test_integration": "Integration",
        "test_keystore": "Keystore",
        "test_policy": "Policy Engine",
        "test_sources": "KEM Sources",
        "test_streaming": "Streaming AEAD",
        "test_utils": "Utilities",
        "test_vectors": "Test Vectors",
    }

    categories = []
    for fname, counts in sorted(file_counts.items()):
        label = category_map.get(fname, fname.replace("test_", "").replace("_", " ").title())
        categories.append({
            "label": label,
            "passed": counts["passed"],
            "failed": counts["failed"],
            "skipped": counts["skipped"],
            "total": counts["passed"] + counts["failed"] + counts["skipped"],
        })

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "categories": categories,
        "exit_code": result.returncode,
    }


def run_verify_local(repo_root: str) -> dict:
    """Run verify_local.py and parse results."""
    result = subprocess.run(
        [sys.executable, "verify_local.py"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr

    # Count check steps (numbered sections)
    checks_found = len(re.findall(r"^\s+\d+\.\s", output, re.MULTILINE))
    # Count SUCCESS/PASS lines
    passes = len(re.findall(r"SUCCESS!|^PASS:", output, re.MULTILINE))
    # Look for summary line
    summary = re.search(r"\[(\d+)/(\d+)\]", output)
    if summary:
        passed = int(summary.group(1))
        total = int(summary.group(2))
    else:
        total = max(checks_found, passes)
        passed = passes

    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "exit_code": result.returncode,
    }


def get_version(repo_root: str) -> str:
    """Read the package version from pyproject.toml."""
    toml_path = Path(repo_root) / "pyproject.toml"
    for line in toml_path.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if m:
            return m.group(1)
    return "unknown"


def generate_svg(
    pytest_results: dict,
    verify_results: dict,
    version: str,
    run_date: str,
) -> str:
    """Generate the SVG string."""

    categories = pytest_results["categories"]
    num_cats = len(categories)

    # ── layout constants ──
    W = 720
    MARGIN_X = 32
    CONTENT_W = W - 2 * MARGIN_X
    HEADER_H = 90
    SUMMARY_H = 100
    CAT_ROW_H = 28
    CAT_HEADER_H = 36
    CAT_BLOCK_H = CAT_HEADER_H + num_cats * CAT_ROW_H + 16
    DISCLAIMER_H = 56
    FOOTER_H = 28
    PADDING = 16
    H = HEADER_H + SUMMARY_H + CAT_BLOCK_H + DISCLAIMER_H + FOOTER_H + PADDING * 3

    # ── colors ──
    BG = "#0d1117"
    CARD_BG = "#161b22"
    BORDER = "#30363d"
    TEXT_PRIMARY = "#e6edf3"
    TEXT_SECONDARY = "#8b949e"
    TEXT_DIM = "#6e7681"
    GREEN = "#3fb950"
    GREEN_DIM = "#238636"
    RED = "#f85149"
    ACCENT = "#58a6ff"
    BAR_BG = "#21262d"

    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    lines: list[str] = []
    a = lines.append

    a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
    a(f'  <rect width="{W}" height="{H}" rx="12" fill="{BG}"/>')

    # ── title block ──
    ty = 36
    a(f'  <text x="{W//2}" y="{ty}" text-anchor="middle" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="20" font-weight="700" fill="{TEXT_PRIMARY}">CryptoFlex — Test &amp; Verification Results</text>')
    ty += 24
    a(f'  <text x="{W//2}" y="{ty}" text-anchor="middle" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="13" fill="{TEXT_SECONDARY}">v{esc(version)}  ·  {esc(run_date)}</text>')
    ty += 18
    a(f'  <text x="{W//2}" y="{ty}" text-anchor="middle" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="11" fill="{TEXT_DIM}">Unaudited research prototype — results do not constitute a security proof</text>')

    # ── summary cards ──
    card_y = HEADER_H
    card_h = SUMMARY_H - 12
    card_w = (CONTENT_W - 16) // 2

    def draw_summary_card(x: int, y: int, w: int, h: int, title: str, passed: int, total: int, failed: int):
        color = GREEN if failed == 0 else RED
        a(f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{CARD_BG}" stroke="{BORDER}" stroke-width="1"/>')
        a(f'  <text x="{x + w//2}" y="{y + 24}" text-anchor="middle" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="12" font-weight="600" fill="{TEXT_SECONDARY}">{esc(title)}</text>')
        a(f'  <text x="{x + w//2}" y="{y + 52}" text-anchor="middle" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="26" font-weight="700" fill="{color}">{passed} / {total}</text>')
        label = "ALL PASSED" if failed == 0 else f"{failed} FAILED"
        a(f'  <text x="{x + w//2}" y="{y + 72}" text-anchor="middle" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="11" font-weight="600" fill="{color}">{label}</text>')

    draw_summary_card(
        MARGIN_X, card_y, card_w, card_h,
        "Automated Tests (pytest)",
        pytest_results["passed"], pytest_results["total"], pytest_results["failed"],
    )
    draw_summary_card(
        MARGIN_X + card_w + 16, card_y, card_w, card_h,
        "Local Verification (verify_local.py)",
        verify_results["passed"], verify_results["total"], verify_results["failed"],
    )

    # ── category breakdown ──
    cat_y = HEADER_H + SUMMARY_H + PADDING
    a(f'  <text x="{MARGIN_X}" y="{cat_y + 16}" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="13" font-weight="600" fill="{TEXT_SECONDARY}">Test Categories</text>')
    cat_y += CAT_HEADER_H

    BAR_X = MARGIN_X + 160
    BAR_W = CONTENT_W - 160 - 60
    NUM_X = MARGIN_X + CONTENT_W - 4

    for cat in categories:
        label = cat["label"]
        p = cat["passed"]
        t = cat["total"]
        f_ = cat["failed"]
        fill_w = int(BAR_W * (p / t)) if t > 0 else 0
        bar_color = GREEN_DIM if f_ == 0 else RED

        a(f'  <text x="{MARGIN_X + 4}" y="{cat_y + 16}" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="12" fill="{TEXT_PRIMARY}">{esc(label)}</text>')
        a(f'  <rect x="{BAR_X}" y="{cat_y + 4}" width="{BAR_W}" height="{16}" rx="4" fill="{BAR_BG}"/>')
        if fill_w > 0:
            a(f'  <rect x="{BAR_X}" y="{cat_y + 4}" width="{fill_w}" height="{16}" rx="4" fill="{bar_color}"/>')
        num_color = GREEN if f_ == 0 else RED
        a(f'  <text x="{NUM_X}" y="{cat_y + 16}" text-anchor="end" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="11" font-weight="600" fill="{num_color}">{p}/{t}</text>')
        cat_y += CAT_ROW_H

    # ── disclaimer ──
    disc_y = cat_y + PADDING + 8
    a(f'  <line x1="{MARGIN_X}" y1="{disc_y}" x2="{W - MARGIN_X}" y2="{disc_y}" stroke="{BORDER}" stroke-width="1"/>')
    disc_y += 18
    a(f'  <text x="{W//2}" y="{disc_y}" text-anchor="middle" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="10" fill="{TEXT_DIM}">Test results indicate implementation behavior under tested cases.</text>')
    disc_y += 14
    a(f'  <text x="{W//2}" y="{disc_y}" text-anchor="middle" font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="10" fill="{TEXT_DIM}">They do not constitute a cryptographic security proof or independent security audit.</text>')

    a('</svg>')
    return "\n".join(lines)


def main():
    repo_root = str(Path(__file__).resolve().parent.parent)
    print(f"Repository root: {repo_root}")

    print("\n[1/4] Running pytest...")
    pytest_results = run_pytest(repo_root)
    print(f"      pytest: {pytest_results['passed']} passed, {pytest_results['failed']} failed, "
          f"{pytest_results['skipped']} skipped  (total {pytest_results['total']})")

    print("\n[2/4] Running verify_local.py...")
    verify_results = run_verify_local(repo_root)
    print(f"      verify_local: {verify_results['passed']}/{verify_results['total']} passed")

    print("\n[3/4] Reading version...")
    version = get_version(repo_root)
    print(f"      Version: {version}")

    run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    print(f"      Date: {run_date}")

    print("\n[4/4] Generating SVG...")
    svg = generate_svg(pytest_results, verify_results, version, run_date)

    out_dir = Path(repo_root) / "docs" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "validation-results.svg"
    out_path.write_text(svg, encoding="utf-8")
    print(f"      Written to: {out_path}")

    # Print category summary
    print("\n      Category breakdown:")
    for cat in pytest_results["categories"]:
        status = "[PASS]" if cat["failed"] == 0 else "[FAIL]"
        print(f"        {status} {cat['label']}: {cat['passed']}/{cat['total']}")

    print("\nDone.")


if __name__ == "__main__":
    main()
