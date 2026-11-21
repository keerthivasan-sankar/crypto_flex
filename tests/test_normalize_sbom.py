"""Tests for scripts/normalize_sbom.py.

The SBOM fixtures reproduce the shape cyclonedx-py 4.1.2 actually produced for
CryptoFlex v0.5.5 (observed in the Stage 4C.7 evidence): bootstrap packages
present, leaf entries without a `dependsOn` key, and a setuptools -> pip edge.
"""

import copy
import json
from pathlib import Path

import pytest

from scripts.normalize_sbom import NormalizationRefused, main, normalize_sbom
from scripts.verify_sbom import (
    REQUIRED_RUNTIME_DEPS_BASE,
    REQUIRED_RUNTIME_DEPS_PQC,
    build_component_registry,
    validate_dependency_graph,
)

ROOT = "root-component"


def comp(name: str, version: str) -> dict:
    return {
        "bom-ref": f"{name}=={version}",
        "name": name,
        "version": version,
        "type": "library",
        "purl": f"pkg:pypi/{name}@{version}",
    }


def generated_sbom(pqc: bool = False) -> dict:
    """SBOM in the shape cyclonedx-py emits: bootstrap included, no leaf dependsOn."""
    components = [
        comp("cffi", "2.1.1"),
        comp("cryptography", "50.0.2"),
        comp("pip", "26.2.1"),
        comp("pycparser", "3.12"),
        comp("setuptools", "65.5.0"),
    ]
    deps = [
        {"ref": "cffi==2.1.1", "dependsOn": ["pycparser==3.12"]},
        {"ref": "cryptography==50.0.2", "dependsOn": ["cffi==2.1.1"]},
        {"ref": "pip==26.2.1"},
        {"ref": "pycparser==3.12"},
        {"ref": ROOT, "dependsOn": ["cryptography==50.0.2"]},
        {"ref": "setuptools==65.5.0", "dependsOn": ["pip==26.2.1"]},
    ]
    if pqc:
        components.insert(2, comp("liboqs-python", "0.16.0.2"))
        deps.insert(2, {"ref": "liboqs-python==0.16.0.2"})
        deps[5]["dependsOn"].append("liboqs-python==0.16.0.2")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": ROOT,
                "type": "library",
                "name": "cryptoflex",
                "version": "0.5.5",
            }
        },
        "components": components,
        "dependencies": deps,
    }


def run_graph_checks(sbom: dict, required: set) -> None:
    path = Path("sbom.json")
    registry, root_ref = build_component_registry(sbom, path)
    validate_dependency_graph(sbom, path, registry, root_ref, required)


def entry(sbom: dict, ref: str):
    return next((e for e in sbom["dependencies"] if e["ref"] == ref), None)


# --- the problem this tool exists to fix -----------------------------------


@pytest.mark.parametrize("pqc", [False, True])
def test_generator_shape_fails_verifier_graph_checks(pqc):
    required = REQUIRED_RUNTIME_DEPS_PQC if pqc else REQUIRED_RUNTIME_DEPS_BASE
    with pytest.raises(ValueError, match="missing required 'dependsOn' property"):
        run_graph_checks(generated_sbom(pqc), required)


@pytest.mark.parametrize(
    "pqc,required",
    [(False, REQUIRED_RUNTIME_DEPS_BASE), (True, REQUIRED_RUNTIME_DEPS_PQC)],
)
def test_normalized_sbom_passes_verifier_graph_checks(pqc, required):
    normalized, _ = normalize_sbom(generated_sbom(pqc))
    run_graph_checks(normalized, required)


# --- what it changes --------------------------------------------------------


def test_removes_bootstrap_components_entries_and_edges():
    sbom = generated_sbom()
    sbom["components"].append(comp("wheel", "0.45.1"))
    sbom["dependencies"].append({"ref": "wheel==0.45.1", "dependsOn": []})
    normalized, report = normalize_sbom(sbom)

    names = {c["name"] for c in normalized["components"]}
    assert names == {"cffi", "cryptography", "pycparser"}
    refs = {e["ref"] for e in normalized["dependencies"]}
    assert refs == {ROOT, "cffi==2.1.1", "cryptography==50.0.2", "pycparser==3.12"}
    assert report["removed_components"] == ["pip==26.2.1", "setuptools==65.5.0", "wheel==0.45.1"]
    assert ("setuptools==65.5.0", "pip==26.2.1") in report["removed_edges"]


def test_fills_empty_dependsOn_only_where_key_is_missing():
    normalized, report = normalize_sbom(generated_sbom(pqc=True))
    assert entry(normalized, "pycparser==3.12")["dependsOn"] == []
    assert entry(normalized, "liboqs-python==0.16.0.2")["dependsOn"] == []
    assert report["filled_empty_dependsOn"] == ["liboqs-python==0.16.0.2", "pycparser==3.12"]
    # existing lists are untouched
    assert entry(normalized, "cffi==2.1.1")["dependsOn"] == ["pycparser==3.12"]


def test_runtime_edges_are_preserved_exactly():
    original = generated_sbom(pqc=True)
    normalized, _ = normalize_sbom(original)
    for ref in (ROOT, "cffi==2.1.1", "cryptography==50.0.2"):
        assert entry(normalized, ref) == entry(original, ref)


def test_input_is_not_mutated():
    original = generated_sbom()
    snapshot = copy.deepcopy(original)
    normalize_sbom(original)
    assert original == snapshot


def test_is_idempotent():
    once, _ = normalize_sbom(generated_sbom(pqc=True))
    twice, report = normalize_sbom(once)
    assert twice == once
    assert not report["removed_components"] and not report["filled_empty_dependsOn"]


# --- what it must NOT hide ---------------------------------------------------


def test_does_not_invent_a_missing_entry():
    """A component whose entry was dropped must still be caught by the verifier."""
    sbom = generated_sbom()
    sbom["dependencies"] = [e for e in sbom["dependencies"] if e["ref"] != "pycparser==3.12"]
    normalized, _ = normalize_sbom(sbom)
    assert entry(normalized, "pycparser==3.12") is None
    with pytest.raises(ValueError, match="incomplete"):
        run_graph_checks(normalized, REQUIRED_RUNTIME_DEPS_BASE)


def test_does_not_hide_a_dropped_root_edge():
    sbom = generated_sbom(pqc=True)
    entry(sbom, ROOT)["dependsOn"].remove("liboqs-python==0.16.0.2")
    normalized, _ = normalize_sbom(sbom)
    with pytest.raises(ValueError):  # missing direct dep and/or orphan component
        run_graph_checks(normalized, REQUIRED_RUNTIME_DEPS_PQC)


def test_refuses_when_runtime_component_depends_on_bootstrap_package():
    sbom = generated_sbom()
    entry(sbom, "cffi==2.1.1")["dependsOn"].append("setuptools==65.5.0")
    with pytest.raises(NormalizationRefused, match="cffi==2.1.1 -> setuptools==65.5.0"):
        normalize_sbom(sbom)


def test_root_is_never_removed_even_if_named_like_bootstrap():
    sbom = generated_sbom()
    sbom["metadata"]["component"]["name"] = "pip"
    normalized, _ = normalize_sbom(sbom)
    assert normalized["metadata"]["component"]["name"] == "pip"
    assert entry(normalized, ROOT) is not None


# --- CLI / file handling ------------------------------------------------------


def write(path: Path, sbom: dict, newline: str = "\n", trailing: bool = True) -> bytes:
    text = json.dumps(sbom, indent=2, ensure_ascii=False).replace("\n", newline)
    data = (text + (newline if trailing else "")).encode("utf-8")
    path.write_bytes(data)
    return data


def test_dry_run_writes_nothing(tmp_path, capsys):
    p = tmp_path / "SBOM.json"
    before = write(p, generated_sbom())
    assert main(["--dry-run", str(p)]) == 0
    assert p.read_bytes() == before
    assert "would change" in capsys.readouterr().out


def test_in_place_rewrite_normalizes_and_is_stable(tmp_path):
    p = tmp_path / "SBOM.json"
    write(p, generated_sbom())
    assert main([str(p)]) == 0
    normalized = json.loads(p.read_text(encoding="utf-8"))
    run_graph_checks(normalized, REQUIRED_RUNTIME_DEPS_BASE)
    after_first = p.read_bytes()
    assert main([str(p)]) == 0
    assert p.read_bytes() == after_first  # second run does not rewrite


@pytest.mark.parametrize("newline,trailing", [("\n", True), ("\r\n", False)])
def test_preserves_line_endings_and_trailing_newline(tmp_path, newline, trailing):
    p = tmp_path / "SBOM.json"
    write(p, generated_sbom(), newline=newline, trailing=trailing)
    assert main([str(p)]) == 0
    data = p.read_bytes()
    assert data.endswith(b"\n") == trailing
    if newline == "\r\n":
        assert data.count(b"\r\n") == data.count(b"\n")
    else:
        assert b"\r\n" not in data


def test_preserves_key_order(tmp_path):
    p = tmp_path / "SBOM.json"
    sbom = generated_sbom()
    write(p, sbom)
    main([str(p)])
    assert list(json.loads(p.read_text(encoding="utf-8"))) == list(sbom)


def test_already_clean_file_is_not_rewritten(tmp_path):
    p = tmp_path / "SBOM.json"
    clean, _ = normalize_sbom(generated_sbom())
    before = write(p, clean, newline="\r\n", trailing=False)
    assert main([str(p)]) == 0
    assert p.read_bytes() == before


def test_refusal_exits_2_and_leaves_file_untouched(tmp_path, capsys):
    p = tmp_path / "SBOM.json"
    sbom = generated_sbom()
    entry(sbom, "cffi==2.1.1")["dependsOn"].append("pip==26.2.1")
    before = write(p, sbom)
    assert main([str(p)]) == 2
    assert p.read_bytes() == before
    assert "REFUSED" in capsys.readouterr().err


def test_invalid_json_exits_1(tmp_path):
    p = tmp_path / "SBOM.json"
    p.write_text("{not json", encoding="utf-8")
    assert main([str(p)]) == 1


def test_one_bad_file_does_not_stop_the_others(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    good = tmp_path / "good.json"
    write(good, generated_sbom())
    assert main([str(bad), str(good)]) == 1
    run_graph_checks(json.loads(good.read_text(encoding="utf-8")), REQUIRED_RUNTIME_DEPS_BASE)
