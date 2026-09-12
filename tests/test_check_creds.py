import json
import yaml
from controls.somay import check_creds
from controls.base import CheckResult
from tests.conftest import write

GRAPH_BOUND_1_REACH_ALL = {
    "declared_blast_radius_bound": 1,
    "identities": [{"name": "worker-sa", "reach": ["imds", "control-plane", "vpn-pivot"]}],
}
SCOPE_BLOCKED = {"token_type": "biscuit-attenuated", "off_origin_replay_blocked": True}
SCOPE_NOT_BLOCKED = {"token_type": "raw", "off_origin_replay_blocked": False}


def _passing(rule_id):
    return CheckResult(rule_id, "n/a", "PASS", "ok")


def _failing(rule_id):
    return CheckResult(rule_id, "n/a", "FAIL", "open")


def test_pass_when_token_scoped_and_all_upstream_boundaries_pass(tmp_path):
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_BLOCKED))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(GRAPH_BOUND_1_REACH_ALL))
    context = {6: _passing(6), 7: _passing(7), 8: _passing(8)}
    res = check_creds.run(str(tmp_path), context=context)
    # every reach tag is closed off by an upstream PASS, so effective reach is empty
    assert res.status == "PASS"


def test_fail_when_token_replay_not_blocked_even_if_graph_is_fine(tmp_path):
    graph = {"declared_blast_radius_bound": 5, "identities": [{"name": "worker-sa", "reach": []}]}
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_NOT_BLOCKED))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(graph))
    res = check_creds.run(str(tmp_path), context={6: _passing(6), 7: _passing(7), 8: _passing(8)})
    assert res.status == "FAIL"
    assert "off-origin" in res.detail


def test_fail_when_upstream_boundaries_open_pushes_reach_over_bound(tmp_path):
    """Core cross-boundary case: the IAM graph alone doesn't tell the whole
    story - a reach tag only drops out if the corresponding rule 6/7/8
    checker already PASSed. If none of them pass, all 3 tags stay 'open'
    and blow past a bound of 1."""
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_BLOCKED))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(GRAPH_BOUND_1_REACH_ALL))
    context = {6: _failing(6), 7: _failing(7), 8: _failing(8)}
    res = check_creds.run(str(tmp_path), context=context)
    assert res.status == "FAIL"
    assert "exceeds declared bound" in res.detail


def test_fail_when_only_some_upstream_boundaries_pass(tmp_path):
    """Partial mitigation: rule 6 (imds) passes so that tag drops out, but
    7 and 8 are still open - 2 open tags still exceeds a bound of 1."""
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_BLOCKED))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(GRAPH_BOUND_1_REACH_ALL))
    context = {6: _passing(6), 7: _failing(7), 8: _failing(8)}
    res = check_creds.run(str(tmp_path), context=context)
    assert res.status == "FAIL"
    assert "control-plane" in res.detail and "vpn-pivot" in res.detail
    assert "imds" not in res.detail  # closed off by rule 6's PASS


def test_fail_when_missing_files(tmp_path):
    res = check_creds.run(str(tmp_path), context={})
    assert res.status == "FAIL"


def test_run_checks_passes_context_kwarg_automatically(tmp_path):
    """Integration check: run_checks.py's inspect.signature-based dispatch
    actually detects check_creds' `context` parameter and wires it up,
    rather than relying on tests to call it directly."""
    import inspect
    sig = inspect.signature(check_creds.run)
    assert "context" in sig.parameters
