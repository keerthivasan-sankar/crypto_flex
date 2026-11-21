#!/usr/bin/env python3
"""
Normalize cyclonedx-py output so it satisfies scripts/verify_sbom.py policy.

Runs BETWEEN SBOM generation and verification. It makes exactly two changes
and nothing else:

1. Bootstrap packages (pip, setuptools, wheel - the verifier's own
   BOOTSTRAP_PACKAGES) are removed from `components`, together with their
   `dependencies` entries and any edges between bootstrap packages. They are
   installed by `python -m venv`, they are not runtime dependencies of
   cryptoflex, and the verifier excludes them from inventory reconciliation.

2. A `dependencies` entry that exists but has no `dependsOn` key gets
   `"dependsOn": []`. CycloneDX 1.5 uses an explicit empty list to mean
   "this component has no dependencies"; the verifier requires it.

What it deliberately does NOT do (so the verifier still catches real defects):

- It never creates a missing `dependencies` entry for a component.
- It never adds, removes or rewrites an edge between non-bootstrap packages.
- It refuses (exit code 2, file untouched) if any non-bootstrap component
  depends on a bootstrap package, because that would be a real runtime
  dependency that must not be silently dropped.

File formatting is preserved: key order, 2-space indent, line-ending style and
trailing-newline status. A file that needs no change is not rewritten.

Usage:
    python scripts/normalize_sbom.py dist/SBOM.json dist/SBOM-pqc.json
    python scripts/normalize_sbom.py --dry-run dist/SBOM.json dist/SBOM-pqc.json

Exit codes: 0 ok, 1 unreadable/invalid input, 2 refused (see above).
"""

import argparse
import copy
import json
import os
import sys
from pathlib import Path

try:  # run as a script: python scripts/normalize_sbom.py
    from verify_sbom import BOOTSTRAP_PACKAGES, normalize_name
except ImportError:  # imported as a package: scripts.normalize_sbom
    from scripts.verify_sbom import BOOTSTRAP_PACKAGES, normalize_name


class NormalizationRefused(ValueError):
    """Raised when normalizing would hide a real runtime dependency."""


def normalize_sbom(sbom: dict) -> tuple:
    """Return (normalized_copy, report). The input is never mutated."""
    sbom = copy.deepcopy(sbom)
    root_ref = (sbom.get("metadata", {}).get("component") or {}).get("bom-ref")

    # 1. Identify bootstrap components (never the root; never ref-less ones,
    #    which the verifier rejects on its own).
    removed = {}
    kept = []
    for comp in sbom.get("components", []):
        ref = comp.get("bom-ref")
        if ref and ref != root_ref and normalize_name(comp.get("name", "")) in BOOTSTRAP_PACKAGES:
            removed[ref] = comp.get("name")
        else:
            kept.append(comp)

    removed_edges = []
    filled = []
    refused = []

    deps = sbom.get("dependencies")
    new_deps = deps
    if isinstance(deps, list):
        new_deps = []
        for entry in deps:
            if not isinstance(entry, dict):
                new_deps.append(entry)  # malformed: leave for the verifier
                continue
            ref = entry.get("ref")
            targets = entry.get("dependsOn")

            if ref in removed:  # entry of a bootstrap package: drop it
                for tgt in targets if isinstance(targets, list) else []:
                    removed_edges.append((ref, tgt))
                continue

            if isinstance(targets, list):
                bad = [t for t in targets if t in removed]
                refused.extend((ref, t) for t in bad)
            elif "dependsOn" not in entry:
                entry["dependsOn"] = []
                filled.append(ref)
            new_deps.append(entry)

    if refused:
        pairs = ", ".join(f"{a} -> {b}" for a, b in refused)
        raise NormalizationRefused(
            "non-bootstrap component(s) depend on bootstrap package(s): "
            f"{pairs}. Not dropping a real runtime dependency; investigate."
        )

    if "components" in sbom:
        sbom["components"] = kept
    if isinstance(deps, list):
        sbom["dependencies"] = new_deps

    report = {
        "removed_components": sorted(removed),
        "removed_edges": removed_edges,
        "filled_empty_dependsOn": filled,
    }
    return sbom, report


def _dump(sbom: dict, newline: str, trailing_newline: bool) -> bytes:
    text = json.dumps(sbom, indent=2, sort_keys=False, ensure_ascii=False)
    if newline != "\n":
        text = text.replace("\n", newline)
    if trailing_newline:
        text += newline
    return text.encode("utf-8")


def process_file(path: Path, dry_run: bool = False) -> tuple:
    """Normalize one file. Returns (changed: bool, report: dict)."""
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    sbom = json.loads(text)
    normalized, report = normalize_sbom(sbom)
    changed = normalized != sbom
    if changed and not dry_run:
        newline = "\r\n" if "\r\n" in text else "\n"
        data = _dump(normalized, newline, text.endswith("\n"))
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
    return changed, report


def _describe(report: dict) -> str:
    if not (report["removed_components"] or report["filled_empty_dependsOn"]):
        return "no changes needed"
    parts = []
    if report["removed_components"]:
        parts.append("remove components: " + ", ".join(report["removed_components"]))
    if report["removed_edges"]:
        parts.append("remove edges: " + ", ".join(f"{a} -> {b}" for a, b in report["removed_edges"]))
    if report["filled_empty_dependsOn"]:
        parts.append("add empty dependsOn to: " + ", ".join(report["filled_empty_dependsOn"]))
    return "; ".join(parts)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Normalize cyclonedx-py SBOMs for verify_sbom.py")
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--dry-run", action="store_true", help="report what would change; write nothing")
    args = ap.parse_args(argv)

    rc = 0
    for path in args.files:
        try:
            changed, report = process_file(path, dry_run=args.dry_run)
        except NormalizationRefused as exc:
            print(f"REFUSED {path}: {exc}", file=sys.stderr)
            rc = max(rc, 2)
            continue
        except Exception as exc:  # noqa: BLE001 - report and keep going
            print(f"ERROR {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            rc = max(rc, 1)
            continue
        verb = "would change" if (changed and args.dry_run) else ("changed" if changed else "unchanged")
        print(f"{path}: {verb} - {_describe(report)}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
