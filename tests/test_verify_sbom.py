import json
import os
import subprocess
import sys
from pathlib import Path
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_sbom.py"
OFFICIAL_SCHEMA = Path(__file__).resolve().parents[1] / "scripts" / "bom-1.5.schema.json"


def create_fake_env(tmp_path: Path, env_name: str, packages: list[str]) -> Path:
    """
    Creates an isolated fake virtual environment directory with a simulated pip executable.
    Does not access developer or host Python environments.
    """
    env_root = tmp_path / env_name
    bin_dir = env_root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    pip_script = bin_dir / "pip"

    pkg_json = json.dumps([{"name": p, "version": "1.0.0"} for p in packages])
    content = f"#!/usr/bin/env python3\nimport sys, json\nprint({repr(pkg_json)})\n"
    pip_script.write_text(content, encoding="utf-8")
    pip_script.chmod(0o755)

    if sys.platform == "win32":
        cmd_script = bin_dir / "pip.cmd"
        cmd_script.write_text(
            f"@echo off\r\n\"{sys.executable}\" -c \"import json; print({repr(pkg_json)})\"\r\n",
            encoding="utf-8",
        )

    return env_root


def build_sbom(
    root_name: str = "cryptoflex",
    root_version: str = "0.5.5",
    root_ref: str = "pkg:pypi/cryptoflex@0.5.5",
    root_type: str = "application",
    components: list[dict] = None,
    dependencies: list[dict] = None,
    bom_format: str = "CycloneDX",
    spec_version: str = "1.5",
    omit_metadata: bool = False,
    omit_dependencies: bool = False,
    metadata_component_override=None,
) -> dict:
    """Constructs a valid or customizable CycloneDX 1.5 document structure."""
    doc = {
        "bomFormat": bom_format,
        "specVersion": spec_version,
        "version": 1,
    }

    if not omit_metadata:
        if metadata_component_override is not None:
            doc["metadata"] = {"component": metadata_component_override}
        else:
            comp = {
                "type": root_type,
                "name": root_name,
                "version": root_version,
            }
            if root_ref is not None:
                comp["bom-ref"] = root_ref
            doc["metadata"] = {"component": comp}

    if components is not None:
        doc["components"] = components
    else:
        doc["components"] = []

    if not omit_dependencies:
        if dependencies is not None:
            doc["dependencies"] = dependencies
        else:
            doc["dependencies"] = []

    return doc


def save_sbom(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def run_verify(base_path: Path, pqc_path: Path, runtime_env: Path, pqc_env: Path, schema_path: Path = None, expect_success: bool = True):
    cmd = [
        sys.executable,
        str(SCRIPT),
        "--base", str(base_path),
        "--pqc", str(pqc_path),
        "--runtime-env", str(runtime_env),
        "--pqc-env", str(pqc_env),
    ]
    if schema_path is not None:
        cmd.extend(["--schema", str(schema_path)])

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if expect_success:
        assert proc.returncode == 0, f"Expected success (0), got {proc.returncode}.\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    else:
        assert proc.returncode != 0, f"Expected failure (non-zero), got 0.\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    return proc


@pytest.fixture
def standard_envs(tmp_path):
    base_env = create_fake_env(tmp_path, "base_env", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography"])
    pqc_env = create_fake_env(tmp_path, "pqc_env", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography", "liboqs-python"])
    return base_env, pqc_env


def create_valid_sboms(tmp_path):
    base_components = [
        {
            "type": "library",
            "name": "cryptography",
            "version": "42.0.5",
            "bom-ref": "pkg:pypi/cryptography@42.0.5",
        }
    ]
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["pkg:pypi/cryptography@42.0.5"]},
        {"ref": "pkg:pypi/cryptography@42.0.5", "dependsOn": []},
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM.json", base_sbom)

    pqc_components = [
        {
            "type": "library",
            "name": "cryptography",
            "version": "42.0.5",
            "bom-ref": "pkg:pypi/cryptography@42.0.5",
        },
        {
            "type": "library",
            "name": "liboqs-python",
            "version": "0.10.0",
            "bom-ref": "pkg:pypi/liboqs-python@0.10.0",
        },
    ]
    pqc_deps = [
        {
            "ref": "pkg:pypi/cryptoflex@0.5.5",
            "dependsOn": [
                "pkg:pypi/cryptography@42.0.5",
                "pkg:pypi/liboqs-python@0.10.0",
            ],
        },
        {"ref": "pkg:pypi/cryptography@42.0.5", "dependsOn": []},
        {"ref": "pkg:pypi/liboqs-python@0.10.0", "dependsOn": []},
    ]
    pqc_sbom = build_sbom(components=pqc_components, dependencies=pqc_deps)
    pqc_path = save_sbom(tmp_path / "SBOM-pqc.json", pqc_sbom)

    return base_path, pqc_path


# --- Test Cases ---

def test_valid_graph_with_explicit_empty_leaf_entries(tmp_path, standard_envs):
    """Confirm that a valid graph with explicit empty leaf entries ('dependsOn': []) passes verification."""
    base_env, pqc_env = standard_envs
    base_path, pqc_path = create_valid_sboms(tmp_path)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=True)


def test_rejection_missing_depends_on_property(tmp_path, standard_envs):
    """Rejection when a dependency entry omits the 'dependsOn' property entirely (not defaulted)."""
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    # ref-crypto omits the dependsOn property entirely
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto"]},
        {"ref": "ref-crypto"},  # missing dependsOn key
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-missing-dependson-prop.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_rejection_omitted_leaf_component_entry(tmp_path, standard_envs):
    """Rejection when a leaf component is referenced in parent dependsOn but omits its own dependency entry."""
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    # Root depends on ref-crypto, but ref-crypto has no explicit entry in dependencies
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto"]},
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-omitted-leaf.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_rejection_omitted_intermediate_component_entry(tmp_path):
    """Rejection when an intermediate component in a dependency chain is omitted from the dependency graph."""
    base_env = create_fake_env(tmp_path, "base_inter", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography", "cffi"])
    pqc_env = create_fake_env(tmp_path, "pqc_env", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography", "liboqs-python"])
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"},
        {"type": "library", "name": "cffi", "version": "1.16.0", "bom-ref": "ref-cffi"},
    ]
    # Root -> cryptography -> cffi, but intermediate ref-crypto entry is omitted from dependencies
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto"]},
        {"ref": "ref-cffi", "dependsOn": []},
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-omitted-intermediate.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_rejection_omitted_root_entry(tmp_path, standard_envs):
    """Rejection when the root component entry itself is omitted from dependencies."""
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    # Root entry omitted; only leaf is declared
    base_deps = [
        {"ref": "ref-crypto", "dependsOn": []},
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-omitted-root.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_rejection_dangling_reference(tmp_path, standard_envs):
    """Rejection when dependsOn references an unknown target bom-ref."""
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto", "nonexistent-dangling-target"]},
        {"ref": "ref-crypto", "dependsOn": []},
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-dangling.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_rejection_duplicate_dependency_entries(tmp_path, standard_envs):
    """Rejection when two dependency entries declare the same ref."""
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto"]},
        {"ref": "ref-crypto", "dependsOn": []},
        {"ref": "ref-crypto", "dependsOn": []},  # duplicate ref
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-duplicate-entry.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_rejection_disconnected_component(tmp_path, standard_envs):
    """Rejection when a declared component has a graph entry but is unreachable from root (orphan)."""
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"},
        {"type": "library", "name": "orphan-pkg", "version": "1.0.0", "bom-ref": "ref-orphan"},
    ]
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto"]},
        {"ref": "ref-crypto", "dependsOn": []},
        {"ref": "ref-orphan", "dependsOn": []},  # disconnected from root
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-disconnected.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_distinct_component_name_and_bom_ref(tmp_path, standard_envs):
    """Verify that component names and bom-ref are not assumed to be equal."""
    base_env, pqc_env = standard_envs

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "opaque-crypto-ref-123"}
    ]
    base_deps = [
        {"ref": "opaque-root-ref-999", "dependsOn": ["opaque-crypto-ref-123"]},
        {"ref": "opaque-crypto-ref-123", "dependsOn": []},
    ]
    base_sbom = build_sbom(root_ref="opaque-root-ref-999", components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-distinct.json", base_sbom)

    _, pqc_path = create_valid_sboms(tmp_path)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=True)


def test_missing_root_component(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_sbom = build_sbom(omit_metadata=True)
    base_path = save_sbom(tmp_path / "SBOM-no-root.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_incorrect_root_name(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_sbom = build_sbom(root_name="not-cryptoflex")
    base_path = save_sbom(tmp_path / "SBOM-wrong-name.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_incorrect_root_version(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_sbom = build_sbom(root_version="0.5.4")
    base_path = save_sbom(tmp_path / "SBOM-wrong-ver.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_missing_root_bom_ref(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_sbom = build_sbom(root_ref=None)
    base_path = save_sbom(tmp_path / "SBOM-no-root-ref.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_missing_component_bom_ref(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    comp = {"type": "library", "name": "cryptography", "version": "42.0.5"}  # missing bom-ref
    base_sbom = build_sbom(components=[comp], dependencies=[{"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": []}])
    base_path = save_sbom(tmp_path / "SBOM-no-comp-ref.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_duplicate_bom_ref(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    dup_ref = "shared-ref-123"
    comps = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": dup_ref},
        {"type": "library", "name": "other", "version": "1.0", "bom-ref": dup_ref},
    ]
    base_sbom = build_sbom(components=comps, dependencies=[])
    base_path = save_sbom(tmp_path / "SBOM-dup-ref.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_missing_cryptography_base(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_sbom = build_sbom(components=[], dependencies=[{"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": []}])
    base_path = save_sbom(tmp_path / "SBOM-missing-crypto.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_missing_liboqs_python_pqc(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    base_path, _ = create_valid_sboms(tmp_path)

    pqc_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "pkg:pypi/cryptography@42.0.5"}
    ]
    pqc_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["pkg:pypi/cryptography@42.0.5"]},
        {"ref": "pkg:pypi/cryptography@42.0.5", "dependsOn": []},
    ]
    pqc_sbom = build_sbom(components=pqc_components, dependencies=pqc_deps)
    pqc_path = save_sbom(tmp_path / "SBOM-pqc-missing-oqs.json", pqc_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_missing_installed_runtime_package_from_sbom(tmp_path):
    """Environment contains cffi, but SBOM components omit it."""
    base_env = create_fake_env(tmp_path, "base_with_cffi", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography", "cffi"])
    pqc_env = create_fake_env(tmp_path, "pqc_env", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography", "liboqs-python"])
    base_path, pqc_path = create_valid_sboms(tmp_path)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_extra_sbom_package_absent_from_env(tmp_path, standard_envs):
    """SBOM lists cffi, but it was never installed in the environment."""
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"},
        {"type": "library", "name": "cffi", "version": "1.16.0", "bom-ref": "ref-cffi"},
    ]
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto", "ref-cffi"]},
        {"ref": "ref-crypto", "dependsOn": []},
        {"ref": "ref-cffi", "dependsOn": []},
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-extra-pkg.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_scanner_contamination(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"},
        {"type": "library", "name": "cyclonedx-bom", "version": "4.1.2", "bom-ref": "ref-scanner"},
    ]
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto", "ref-scanner"]},
        {"ref": "ref-crypto", "dependsOn": []},
        {"ref": "ref-scanner", "dependsOn": []},
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-contaminated.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_invalid_json(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    bad_json = tmp_path / "SBOM-malformed.json"
    bad_json.write_text("{ unquoted_key: 123", encoding="utf-8")
    run_verify(bad_json, pqc_path, base_env, pqc_env, expect_success=False)


def test_missing_base_sbom_file(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)
    run_verify(tmp_path / "nonexistent.json", pqc_path, base_env, pqc_env, expect_success=False)


def test_missing_pqc_sbom_file(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    base_path, _ = create_valid_sboms(tmp_path)
    run_verify(base_path, tmp_path / "nonexistent-pqc.json", base_env, pqc_env, expect_success=False)


def test_schema_validation_missing_component_type(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    # CycloneDX 1.5 schema requires 'type' for components
    comp = {"name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}  # missing 'type'
    base_sbom = build_sbom(components=[comp], dependencies=[{"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": ["ref-crypto"]}, {"ref": "ref-crypto", "dependsOn": []}])
    base_path = save_sbom(tmp_path / "SBOM-schema-no-type.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_schema_validation_malformed_metadata(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_sbom = build_sbom(metadata_component_override="not-an-object")
    base_path = save_sbom(tmp_path / "SBOM-malformed-meta.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_schema_validation_invalid_dependency_entry(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    # Dependency entry missing required 'ref' property
    base_deps = [{"dependsOn": ["ref-crypto"]}]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-bad-dep-entry.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_fail_closed_missing_schema(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    base_path, pqc_path = create_valid_sboms(tmp_path)
    run_verify(base_path, pqc_path, base_env, pqc_env, schema_path=tmp_path / "missing-schema.json", expect_success=False)


def test_dependency_graph_absent(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    base_sbom = build_sbom(components=base_components, omit_dependencies=True)
    base_path = save_sbom(tmp_path / "SBOM-no-deps.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_dependency_graph_empty(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    base_sbom = build_sbom(components=base_components, dependencies=[])
    base_path = save_sbom(tmp_path / "SBOM-empty-deps.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_dependency_graph_missing_direct_relationship(tmp_path, standard_envs):
    base_env, pqc_env = standard_envs
    _, pqc_path = create_valid_sboms(tmp_path)

    base_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    # Root fails to list cryptography in dependsOn
    base_deps = [
        {"ref": "pkg:pypi/cryptoflex@0.5.5", "dependsOn": []},
        {"ref": "ref-crypto", "dependsOn": []},
    ]
    base_sbom = build_sbom(components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-missing-direct-rel.json", base_sbom)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_package_name_normalization_pep503_equivalent(tmp_path):
    """PEP 503 equivalent names (e.g. LibOQS_Python vs liboqs-python, CryptoFlex vs cryptoflex)."""
    base_env = create_fake_env(tmp_path, "base_norm", ["pip", "setuptools", "wheel", "CryptoFlex", "CryptoGraphy"])
    pqc_env = create_fake_env(tmp_path, "pqc_norm", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography", "LibOQS_Python"])

    base_components = [
        {"type": "library", "name": "CryptoGraphy", "version": "42.0.5", "bom-ref": "ref-crypto"}
    ]
    base_deps = [
        {"ref": "ref-root", "dependsOn": ["ref-crypto"]},
        {"ref": "ref-crypto", "dependsOn": []},
    ]
    base_sbom = build_sbom(root_name="CryptoFlex", root_ref="ref-root", components=base_components, dependencies=base_deps)
    base_path = save_sbom(tmp_path / "SBOM-norm-base.json", base_sbom)

    pqc_components = [
        {"type": "library", "name": "cryptography", "version": "42.0.5", "bom-ref": "ref-crypto"},
        {"type": "library", "name": "liboqs.python", "version": "0.10.0", "bom-ref": "ref-oqs"},
    ]
    pqc_deps = [
        {"ref": "ref-root-pqc", "dependsOn": ["ref-crypto", "ref-oqs"]},
        {"ref": "ref-crypto", "dependsOn": []},
        {"ref": "ref-oqs", "dependsOn": []},
    ]
    pqc_sbom = build_sbom(root_ref="ref-root-pqc", components=pqc_components, dependencies=pqc_deps)
    pqc_path = save_sbom(tmp_path / "SBOM-norm-pqc.json", pqc_sbom)

    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=True)


def test_package_name_normalization_distinct_names(tmp_path, standard_envs):
    """cryptography-vectors is not the same package as cryptography."""
    base_env = create_fake_env(tmp_path, "base_distinct", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography-vectors"])
    pqc_env = create_fake_env(tmp_path, "pqc_env", ["pip", "setuptools", "wheel", "cryptoflex", "cryptography", "liboqs-python"])
    base_path, pqc_path = create_valid_sboms(tmp_path)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=False)


def test_bootstrap_packages_excluded_from_sbom(tmp_path, standard_envs):
    """Confirm bootstrap packages (pip, setuptools, wheel) are present in env but excluded from SBOM."""
    base_env, pqc_env = standard_envs
    base_path, pqc_path = create_valid_sboms(tmp_path)
    run_verify(base_path, pqc_path, base_env, pqc_env, expect_success=True)
