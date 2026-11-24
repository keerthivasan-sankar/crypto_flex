#!/usr/bin/env python3
"""
CycloneDX 1.5 SBOM Verifier for CryptoFlex v0.5.5.

Enforces:
1. Strict CycloneDX 1.5 JSON schema validation using official schema and jsonschema.
2. Component bom-ref registry (root and all components; no missing or duplicate refs).
3. Dependency graph completeness: EVERY registered component (including terminal leaves)
   must have an explicit entry in the dependencies array.
4. Dependency graph reference integrity: all refs and dependsOn targets must resolve.
5. Dependency graph reachability: all components must be reachable from the root (no orphans).
6. Root dependency relationships: root component must directly list required runtime dependencies.
7. PEP 503 package name normalization.
8. Runtime inventory reconciliation against isolated virtual environments (excluding bootstrap packages).
9. Scanner/build-tool contamination detection across all known scanner tooling.
10. Presence and correct version of root component ('cryptoflex' 0.5.5).
11. Presence of required runtime dependencies ('cryptography' for base, plus 'liboqs-python' for PQC).

Dependency Graph Completeness Policy:
1. 'dependencies' section must be present and non-empty.
2. Root component ('root_ref') must have an entry in 'dependencies'.
3. Every registered component in the SBOM (root, intermediate libraries, and terminal leaves)
   MUST have an explicit entry in 'dependencies'. Terminal leaf components must explicitly declare
   'dependsOn': [].
4. Root component's entry must directly depend on all required direct runtime dependencies:
   - Base: 'cryptography'
   - PQC: 'cryptography' and 'liboqs-python'
5. Reference Integrity:
   - Every 'ref' in 'dependencies' must exist in the component registry (no unknown sources).
   - No duplicate 'ref' entries allowed in 'dependencies'.
   - Every target in 'dependsOn' must exist in the component registry (no dangling references).
6. Graph Connectivity / Reachability (No Orphan Components):
   - Every declared component in the SBOM must be reachable from the root component in the directed graph.
   - Disconnected / orphan components are rejected as invalid graph state.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent / "bom-1.5.schema.json"


def normalize_name(name: str) -> str:
    """PEP 503-compatible package name normalization."""
    if not name:
        return ""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


# Policy definitions
ROOT_PACKAGE_NAME = normalize_name("cryptoflex")
ROOT_PACKAGE_VERSION = "0.5.5"

BOOTSTRAP_PACKAGES = {normalize_name(p) for p in ["pip", "setuptools", "wheel"]}

# Pinned scanner tooling and its known transitive dependency stack
SCANNER_PACKAGES = {
    normalize_name(p)
    for p in [
        "cyclonedx-bom",
        "cyclonedx-python-lib",
        "packageurl-python",
        "pip-requirements-parser",
        "py-serializable",
        "sortedcontainers",
        "license-expression",
        "jsonschema",
        "jsonschema-specifications",
        "referencing",
        "rpds-py",
        "chardet",
        "tomli",
    ]
}

REQUIRED_RUNTIME_DEPS_BASE = {normalize_name("cryptography")}
REQUIRED_RUNTIME_DEPS_PQC = {normalize_name("cryptography"), normalize_name("liboqs-python")}


def load_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise ValueError(f"Failed to parse JSON from {path}: {e}")


def load_schema(schema_path: Path) -> dict:
    if not schema_path.exists():
        raise FileNotFoundError(f"CycloneDX 1.5 official schema not found: {schema_path}")
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        if jsonschema is not None:
            jsonschema.Draft7Validator.check_schema(schema)
        return schema
    except Exception as e:
        raise ValueError(f"Failed to load or validate CycloneDX schema from {schema_path}: {e}")


def validate_schema(sbom: dict, path: Path, schema: dict) -> None:
    """
    Validate CycloneDX document against official JSON schema.
    Fails closed if jsonschema is missing or validation errors occur.
    """
    if jsonschema is None:
        raise RuntimeError("jsonschema library is required for schema validation but is not installed")
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(sbom))
    if errors:
        error_msgs = []
        for err in errors[:5]:
            path_str = " -> ".join(str(p) for p in err.path) if err.path else "root"
            error_msgs.append(f"[{path_str}]: {err.message}")
        raise ValueError(f"SBOM {path} failed CycloneDX 1.5 schema validation:\n" + "\n".join(error_msgs))


def build_component_registry(sbom: dict, path: Path) -> tuple[dict, str]:
    """
    Build component-reference registry using bom-ref.
    Includes root component and all components.
    Rejects missing or duplicate bom-ref identifiers.
    Returns (registry dict mapping bom-ref -> component, root_ref).
    """
    metadata = sbom.get("metadata", {})
    root_comp = metadata.get("component")
    if not root_comp:
        raise ValueError(f"SBOM {path} missing metadata.component")

    root_ref = root_comp.get("bom-ref")
    if not root_ref or not str(root_ref).strip():
        raise ValueError(f"SBOM {path} root component missing required 'bom-ref'")

    registry = {}
    registry[root_ref] = root_comp

    for idx, comp in enumerate(sbom.get("components", [])):
        cname = comp.get("name", f"<component-{idx}>")
        comp_ref = comp.get("bom-ref")
        if not comp_ref or not str(comp_ref).strip():
            raise ValueError(f"SBOM {path} component '{cname}' missing required 'bom-ref'")
        if comp_ref in registry:
            raise ValueError(f"SBOM {path} contains duplicate bom-ref '{comp_ref}'")
        registry[comp_ref] = comp

    return registry, root_ref


def validate_dependency_graph(
    sbom: dict,
    path: Path,
    registry: dict,
    root_ref: str,
    required_direct_deps: set,
) -> None:
    """
    Enforce strict dependency graph completeness and reference integrity:
    1. 'dependencies' section must be present and non-empty.
    2. Root component ('root_ref') must have an entry in 'dependencies'.
    3. Every registered component (including terminal leaves) must have an explicit entry in 'dependencies'.
    4. Root component's entry must directly depend on all required direct runtime dependencies.
    5. Every 'ref' and 'dependsOn' target must exist in component registry (no dangling refs).
    6. No duplicate 'ref' entries.
    7. All components must be reachable from the root in the directed graph (no orphans/disconnected components).
    """
    if "dependencies" not in sbom:
        raise ValueError(f"SBOM {path} missing 'dependencies' graph section")
    deps_list = sbom["dependencies"]
    if not isinstance(deps_list, list) or len(deps_list) == 0:
        raise ValueError(f"SBOM {path} 'dependencies' section is absent or empty")

    graph = {}
    seen_refs = set()
    for entry in deps_list:
        if not isinstance(entry, dict):
            raise ValueError(f"SBOM {path} dependency entry is not an object")
        ref = entry.get("ref")
        if not ref or not str(ref).strip():
            raise ValueError(f"SBOM {path} dependency entry missing required 'ref'")
        if ref in seen_refs:
            raise ValueError(f"SBOM {path} contains duplicate dependency entry for ref '{ref}'")
        seen_refs.add(ref)

        if ref not in registry:
            raise ValueError(f"SBOM {path} dependency entry ref '{ref}' not found in component registry")

        if "dependsOn" not in entry:
            raise ValueError(f"SBOM {path} dependency entry '{ref}' missing required 'dependsOn' property")

        depends_on = entry["dependsOn"]
        if not isinstance(depends_on, list):
            raise ValueError(f"SBOM {path} dependency entry '{ref}' 'dependsOn' must be a list")

        for target in depends_on:
            if target not in registry:
                raise ValueError(
                    f"SBOM {path} dependency '{ref}' contains dangling reference to '{target}' "
                    f"(not found in component registry)"
                )
        graph[ref] = depends_on

    if root_ref not in graph:
        raise ValueError(f"SBOM {path} root component '{root_ref}' is missing from dependency graph")

    # Strict graph completeness: require an explicit dependency entry for every component, including leaves
    missing_entries = set(registry.keys()) - seen_refs
    if missing_entries:
        missing_names = [registry[r].get("name", r) for r in sorted(missing_entries)]
        raise ValueError(
            f"SBOM {path} dependency graph is incomplete: missing explicit dependency entries for components: {missing_names}"
        )

    # Validate root-to-direct runtime dependency relationships
    root_depends_on = graph[root_ref]
    root_dep_names = {normalize_name(registry[tgt].get("name", "")) for tgt in root_depends_on}
    missing_direct = required_direct_deps - root_dep_names
    if missing_direct:
        raise ValueError(
            f"SBOM {path} root component dependency entry missing required direct runtime dependencies: "
            f"{sorted(missing_direct)}"
        )

    # Graph reachability check: all components in registry must be reachable from root
    reachable = {root_ref}
    queue = [root_ref]
    while queue:
        curr = queue.pop(0)
        for target in graph.get(curr, []):
            if target not in reachable:
                reachable.add(target)
                queue.append(target)

    unreachable = set(registry.keys()) - reachable
    if unreachable:
        unreachable_names = [registry[r].get("name", r) for r in sorted(unreachable)]
        raise ValueError(
            f"SBOM {path} contains disconnected/orphan components not reachable from root: {unreachable_names}"
        )


def check_scanner_contamination(registry: dict, path: Path) -> None:
    """Ensure scanner or build tools do not appear as components."""
    for comp_ref, comp in registry.items():
        norm_name = normalize_name(comp.get("name", ""))
        if norm_name in SCANNER_PACKAGES:
            raise ValueError(
                f"SBOM {path} contains forbidden scanner/build-tool package '{comp.get('name')}' "
                f"(ref '{comp_ref}')"
            )


def get_installed_packages(env_root: Path) -> set:
    """
    Extract installed package names from target virtual environment via pip list --format=json.
    Normalizes all names per PEP 503.
    """
    if not env_root.exists():
        raise FileNotFoundError(f"Virtual environment directory not found: {env_root}")

    candidates = [
        env_root / "bin" / "pip",
        env_root / "bin" / "pip.exe",
        env_root / "Scripts" / "pip.exe",
        env_root / "Scripts" / "pip",
    ]
    pip_exe = next((c for c in candidates if c.exists()), None)
    if not pip_exe:
        raise RuntimeError(f"pip executable not found in virtual environment {env_root}")

    cmd = [str(pip_exe), "list", "--format=json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except OSError:
        # Cross-platform fallback when pip is a script without executable extension
        proc = subprocess.run([sys.executable, str(pip_exe), "list", "--format=json"], capture_output=True, text=True, check=True)

    try:
        pkgs = json.loads(proc.stdout)
    except Exception as e:
        raise RuntimeError(f"Failed to parse pip list output from {env_root}: {e}")

    return {normalize_name(p["name"]) for p in pkgs if "name" in p}


def process_sbom(
    sbom_path: Path,
    env_root: Path,
    schema: dict,
    required_runtime_deps: set,
    label: str,
) -> None:
    """
    Execute complete verification workflow for a single SBOM and its target environment.
    """
    sbom = load_json(sbom_path)

    # 1. Full CycloneDX 1.5 schema validation
    validate_schema(sbom, sbom_path, schema)

    # 2. Build component registry using bom-ref
    registry, root_ref = build_component_registry(sbom, sbom_path)

    # 3. Verify root component identity and version
    root_comp = registry[root_ref]
    root_name = normalize_name(root_comp.get("name", ""))
    root_version = root_comp.get("version", "")
    if root_name != ROOT_PACKAGE_NAME:
        raise ValueError(
            f"{label} root component name mismatch: expected '{ROOT_PACKAGE_NAME}', got '{root_name}'"
        )
    if root_version != ROOT_PACKAGE_VERSION:
        raise ValueError(
            f"{label} root component version mismatch: expected '{ROOT_PACKAGE_VERSION}', got '{root_version}'"
        )

    # 4. Scanner contamination check
    check_scanner_contamination(registry, sbom_path)

    # 5. Dependency graph validation
    validate_dependency_graph(sbom, sbom_path, registry, root_ref, required_runtime_deps)

    # 6. Reconcile runtime inventory with actual environment
    installed_all = get_installed_packages(env_root)
    installed_runtime = installed_all - BOOTSTRAP_PACKAGES

    if ROOT_PACKAGE_NAME not in installed_runtime:
        raise ValueError(
            f"Target virtual environment {env_root} is missing target package '{ROOT_PACKAGE_NAME}'"
        )

    sbom_component_names = {normalize_name(c.get("name", "")) for c in registry.values()}

    # Verify all expected direct dependencies are in SBOM
    missing_required = required_runtime_deps - sbom_component_names
    if missing_required:
        raise ValueError(f"{label} missing required runtime dependencies: {sorted(missing_required)}")

    # Strict two-way set reconciliation: installed runtime packages == SBOM components
    missing_from_sbom = installed_runtime - sbom_component_names
    if missing_from_sbom:
        raise ValueError(
            f"Packages installed in {env_root} missing from {label}: {sorted(missing_from_sbom)}"
        )

    extra_in_sbom = sbom_component_names - installed_runtime
    if extra_in_sbom:
        raise ValueError(
            f"{label} lists components not installed in {env_root}: {sorted(extra_in_sbom)}"
        )


def main():
    parser = argparse.ArgumentParser(description="Validate CycloneDX 1.5 SBOMs for CryptoFlex")
    parser.add_argument("--base", default="dist/SBOM.json", help="Path to Base Runtime SBOM")
    parser.add_argument("--pqc", default="dist/SBOM-pqc.json", help="Path to PQC Runtime SBOM")
    parser.add_argument("--runtime-env", default=".sbom_runtime", help="Path to Base runtime virtualenv")
    parser.add_argument("--pqc-env", default=".sbom_pqc", help="Path to PQC runtime virtualenv")
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA_PATH), help="Path to CycloneDX 1.5 JSON schema")

    args = parser.parse_args()

    schema_path = Path(args.schema)
    base_path = Path(args.base)
    pqc_path = Path(args.pqc)
    runtime_env = Path(args.runtime_env)
    pqc_env = Path(args.pqc_env)

    errors = []

    try:
        schema = load_schema(schema_path)
    except Exception as e:
        print(f"FATAL: Schema error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        process_sbom(base_path, runtime_env, schema, REQUIRED_RUNTIME_DEPS_BASE, "Base SBOM")
    except Exception as e:
        errors.append(str(e))

    try:
        process_sbom(pqc_path, pqc_env, schema, REQUIRED_RUNTIME_DEPS_PQC, "PQC SBOM")
    except Exception as e:
        errors.append(str(e))

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)

    print("SUCCESS: CycloneDX 1.5 SBOM verification passed for both Base and PQC.")
    sys.exit(0)


if __name__ == "__main__":
    main()
