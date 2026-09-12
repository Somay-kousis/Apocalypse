import yaml
from controls.junyi import check_registry
from tests.conftest import write

SEALED = {
    "sealed": True, "hash_attested": True, "route_to_shared_registry": False,
    "packages": [{"name": "numpy", "version": "1.26.3", "sha256": "a" * 64}],
}


def test_pass_when_sealed_attested_isolated(tmp_path):
    write(tmp_path, "b1_registry", "mirror_manifest.yaml", yaml.dump(SEALED))
    res = check_registry.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_routed_to_shared_registry(tmp_path):
    manifest = {**SEALED, "route_to_shared_registry": True}
    write(tmp_path, "b1_registry", "mirror_manifest.yaml", yaml.dump(manifest))
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "shared registry" in res.detail


def test_fail_when_package_missing_hash(tmp_path):
    manifest = {**SEALED, "packages": [{"name": "numpy", "version": "1.26.3"}]}
    write(tmp_path, "b1_registry", "mirror_manifest.yaml", yaml.dump(manifest))
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "sha256" in res.detail


def test_fail_when_missing_file(tmp_path):
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
