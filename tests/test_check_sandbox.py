import yaml
from controls.junyi import check_sandbox
from tests.conftest import write

HARDENED = {
    "runAsNonRoot": True, "runAsUser": 10001,
    "capabilities": {"add": [], "drop": ["ALL"]},
    "seccompProfile": {"type": "RuntimeDefault"},
    "allowEgress": False,
}


def test_pass_when_fully_hardened(tmp_path):
    write(tmp_path, "b3_sandbox", "security_context.yaml", yaml.dump(HARDENED))
    res = check_sandbox.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_root(tmp_path):
    ctx = {**HARDENED, "runAsNonRoot": False, "runAsUser": 0}
    write(tmp_path, "b3_sandbox", "security_context.yaml", yaml.dump(ctx))
    res = check_sandbox.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_nonroot_but_dangerous_cap_added(tmp_path):
    """Adversarial case: runAsNonRoot is true but SYS_ADMIN is still added -
    non-root alone doesn't make this safe."""
    ctx = {**HARDENED, "capabilities": {"add": ["SYS_ADMIN"], "drop": []}}
    write(tmp_path, "b3_sandbox", "security_context.yaml", yaml.dump(ctx))
    res = check_sandbox.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "SYS_ADMIN" in res.detail


def test_fail_when_seccomp_unconfined(tmp_path):
    ctx = {**HARDENED, "seccompProfile": {"type": "Unconfined"}}
    write(tmp_path, "b3_sandbox", "security_context.yaml", yaml.dump(ctx))
    res = check_sandbox.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_missing_file(tmp_path):
    res = check_sandbox.run(str(tmp_path))
    assert res.status == "FAIL"
