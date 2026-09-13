import hashlib
import yaml
from controls.junyi import check_registry
from tests.conftest import write


def sealed_manifest(artifact=b"trusted wheel bytes"):
    return {
        "sealed": True,
        "hash_attested": True,
        "route_to_shared_registry": False,
        "packages": [{
            "name": "numpy",
            "version": "1.26.3",
            "artifact": "artifacts/numpy.whl",
            "sha256": hashlib.sha256(artifact).hexdigest(),
        }],
    }


def write_sealed(tmp_path, manifest=None, artifact="trusted wheel bytes"):
    write(tmp_path, "b1_registry/artifacts", "numpy.whl", artifact)
    write(
        tmp_path,
        "b1_registry",
        "mirror_manifest.yaml",
        yaml.safe_dump(manifest or sealed_manifest(artifact.encode())),
    )


def test_pass_when_sealed_attested_isolated(tmp_path):
    write_sealed(tmp_path)
    res = check_registry.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_routed_to_shared_registry(tmp_path):
    manifest = {**sealed_manifest(), "route_to_shared_registry": True}
    write_sealed(tmp_path, manifest)
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "shared registry" in res.detail


def test_fail_when_package_missing_hash(tmp_path):
    manifest = {**sealed_manifest(), "packages": [{"name": "numpy", "version": "1.26.3"}]}
    write_sealed(tmp_path, manifest)
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "sha256" in res.detail


def test_fail_when_sha256_is_truthy_but_not_a_digest(tmp_path):
    manifest = sealed_manifest()
    manifest["packages"][0]["sha256"] = "pinky-promise"
    write_sealed(tmp_path, manifest)
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "64-hex" in res.detail


def test_fail_when_artifact_content_does_not_match_pin(tmp_path):
    write_sealed(tmp_path, sealed_manifest(), artifact="tampered wheel bytes")
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "mismatch" in res.detail


def test_fail_when_artifact_path_escapes_mirror(tmp_path):
    manifest = sealed_manifest()
    manifest["packages"][0]["artifact"] = "../../outside.whl"
    write_sealed(tmp_path, manifest)
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "escapes" in res.detail


def test_fail_when_missing_file(tmp_path):
    res = check_registry.run(str(tmp_path))
    assert res.status == "FAIL"
