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


def test_fail_when_subdomain_wildcard(tmp_path):
    """'*.amazonaws.com' is functionally as broad as '*' for an attacker who can
    stand up any subdomain of a huge shared registrar."""
    policy = {"default": "deny", "allowlist": [{"domain": "*.amazonaws.com", "sni": "*.amazonaws.com"}]}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_domain_and_sni_disagree(tmp_path):
    """Domain-fronting shape: allowlist a trusted-looking domain but pair it with a
    different SNI, so the connection actually routes to an attacker-controlled host."""
    policy = {"default": "deny", "allowlist": [{"domain": "pypi.org", "sni": "attacker.example.com"}]}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "disagree" in res.detail


def test_fail_when_ip_literal_used_instead_of_domain(tmp_path):
    """Mirrors the incident's own step (`curl http://<internal-svc>` by IP): an IP
    literal has no real SNI and completely bypasses DNS-based domain filtering."""
    policy = {"default": "deny", "allowlist": [{"domain": "203.0.113.5", "sni": "203.0.113.5"}]}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "IP literal" in res.detail


def test_fail_when_bare_single_label_domain(tmp_path):
    """A single-label / bare-TLD entry ('com') isn't a '*' string but is just as
    unbounded in practice."""
    policy = {"default": "deny", "allowlist": [{"domain": "com", "sni": "com"}]}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_allowlist_empty(tmp_path):
    """default: deny with an empty allowlist can't be verified as intentional vs.
    an incomplete config - fail-closed rather than silently PASS."""
    policy = {"default": "deny", "allowlist": []}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"


def test_pass_ignores_trailing_dot_and_case(tmp_path):
    """'PyPI.org.' (trailing dot + mixed case) is the same domain as 'pypi.org' and
    shouldn't be flagged just because it doesn't string-match naively."""
    policy = {"default": "deny", "allowlist": [{"domain": "PyPI.org.", "sni": "PyPI.org."}]}
    write(tmp_path, "b2_egress", "egress_policy.yaml", yaml.dump(policy))
    res = check_egress.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_missing_file(tmp_path):
    res = check_egress.run(str(tmp_path))
    assert res.status == "FAIL"
