import yaml
from controls.vikas import check_imds
from tests.conftest import write


def test_pass_when_link_local_fully_denied(tmp_path):
    """Strongest option: link-local blocked at the network layer, hop_limit irrelevant."""
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": 2, "link_local_denied": True}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "PASS"


def test_pass_when_imdsv2_required_and_hop_limit_1(tmp_path):
    """The other valid path: IMDSv2-only (http_tokens required) + hop_limit capped at 1."""
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": 1, "link_local_denied": False, "http_tokens": "required"}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_hop_limit_1_but_imdsv1_still_enabled(tmp_path):
    """Regression case from the TODO: hop-limit alone is not enough. IMDSv1 (no
    http_tokens requirement) still lets a same-hop `curl 169.254.169.254` through -
    exactly the incident's step."""
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": 1, "link_local_denied": False}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "http_tokens" in res.detail


def test_fail_when_http_tokens_optional(tmp_path):
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": 1, "link_local_denied": False, "http_tokens": "optional"}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_automount_token_true(tmp_path):
    spec = {"automountServiceAccountToken": True,
            "imds": {"hop_limit": 1, "link_local_denied": True, "http_tokens": "required"}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_automount_token_is_truthy_string_not_bool(tmp_path):
    """Adversarial case: a non-boolean truthy/ambiguous value must not slip past a
    Python-truthiness check the way it did in round 1 (`mirror_attested:"pinky-promise"`)."""
    spec = {"automountServiceAccountToken": "false",  # a STRING, not the bool False
            "imds": {"hop_limit": 1, "link_local_denied": True, "http_tokens": "required"}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "automountServiceAccountToken" in res.detail


def test_fail_when_hop_limit_is_string_not_int(tmp_path):
    """Adversarial case from round 1: hop_limit given as a string ("1") must not
    dodge an int-only comparison or crash the checker - coerce, and fail-closed if it
    can't be coerced."""
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": "not-a-number", "link_local_denied": False, "http_tokens": "required"}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"


def test_pass_when_hop_limit_given_as_numeric_string(tmp_path):
    """A quoted "1" in YAML should still count as 1 once coerced - this is a
    legitimate value, not a bypass, and shouldn't be over-flagged."""
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": "1", "link_local_denied": False, "http_tokens": "required"}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_neither_condition_met(tmp_path):
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": 2, "link_local_denied": False}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_missing_file(tmp_path):
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"
