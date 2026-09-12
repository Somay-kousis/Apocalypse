import yaml
from controls.vikas import check_egress
from tests.conftest import write


def test_pass_when_deny_default_with_clean_allowlist(tmp_path):
    policy = {"default": "deny", "allowlist": [{"domain": "pypi.org", "sni": "pypi.org"}]}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_default_allow(tmp_path):
    policy = {"default": "allow", "allowlist": []}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_wildcard_allowlist_entry(tmp_path):
    """Adversarial case: default is correctly 'deny' but the allowlist itself
    is a wildcard, which defeats the whole point of an allowlist."""
    policy = {"default": "deny", "allowlist": [{"domain": "*", "sni": "*"}]}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "wildcard" in res.detail


def test_fail_when_missing_file(tmp_path):
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"
