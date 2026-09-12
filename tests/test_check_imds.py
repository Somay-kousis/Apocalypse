import yaml
from controls.vikas import check_imds
from tests.conftest import write


def test_pass_when_hop_limit_1(tmp_path):
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": 1, "link_local_denied": False}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "PASS"


def test_pass_when_link_local_denied_even_with_hop_limit_2(tmp_path):
    """pass_condition is an OR: hop-limit 1 OR link-local denied."""
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": 2, "link_local_denied": True}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_automount_token_true(tmp_path):
    spec = {"automountServiceAccountToken": True,
            "imds": {"hop_limit": 1, "link_local_denied": True}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_neither_condition_met(tmp_path):
    spec = {"automountServiceAccountToken": False,
            "imds": {"hop_limit": 2, "link_local_denied": False}}
    write(tmp_path, "b6_imds", "pod_spec.yaml", yaml.dump(spec))
    res = check_imds.run(str(tmp_path))
    assert res.status == "FAIL"
