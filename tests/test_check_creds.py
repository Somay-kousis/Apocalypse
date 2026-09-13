import json
import yaml
from controls.somay import check_creds
from controls.base import CheckResult
from tests.conftest import write

# scope now must bind pod (origin) + job (purpose) so the live replay audit can run
SCOPE_OK = {"token_type": "biscuit-attenuated",
            "scope": {"dataset": "ds", "job": "job-1", "pod": "pod-1"},
            "off_origin_replay_blocked": True}
SCOPE_NOT_BISCUIT = {"token_type": "raw",
                     "scope": {"dataset": "ds", "job": "job-1", "pod": "pod-1"}}
GRAPH_BOUND_1_REACH_ALL = {
    "declared_blast_radius_bound": 1,
    "identities": [{"name": "worker-sa", "reach": ["imds", "control-plane", "vpn-pivot"]}],
}


def _passing(rid): return CheckResult(rid, "n/a", "PASS", "ok")
def _failing(rid): return CheckResult(rid, "n/a", "FAIL", "open")


def test_pass_when_token_scoped_and_all_upstream_boundaries_pass(tmp_path):
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_OK))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(GRAPH_BOUND_1_REACH_ALL))
    context = {6: _passing(6), 7: _passing(7), 8: _passing(8)}
    assert check_creds.run(str(tmp_path), context=context).status == "PASS"


def test_fail_when_token_not_attenuated(tmp_path):
    graph = {"declared_blast_radius_bound": 5, "identities": [{"name": "w", "reach": []}]}
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_NOT_BISCUIT))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(graph))
    res = check_creds.run(str(tmp_path), context={6: _passing(6), 7: _passing(7), 8: _passing(8)})
    assert res.status == "FAIL"
    assert "not an attenuated capability token" in res.detail


def test_fail_when_scope_missing_origin(tmp_path):
    # a config can't skip the replay audit by omitting pod/job
    write(tmp_path, "b9_credentials", "credential_scope.yaml",
          yaml.dump({"token_type": "biscuit-attenuated", "off_origin_replay_blocked": True}))
    write(tmp_path, "b9_credentials", "iam_graph.json",
          json.dumps({"declared_blast_radius_bound": 0, "identities": []}))
    res = check_creds.run(str(tmp_path), context={})
    assert res.status == "FAIL" and "scope must bind pod" in res.detail


def test_fail_when_upstream_boundaries_open_pushes_reach_over_bound(tmp_path):
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_OK))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(GRAPH_BOUND_1_REACH_ALL))
    context = {6: _failing(6), 7: _failing(7), 8: _failing(8)}
    res = check_creds.run(str(tmp_path), context=context)
    assert res.status == "FAIL" and "exceeds bound" in res.detail


def test_fail_when_only_some_upstream_boundaries_pass(tmp_path):
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_OK))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(GRAPH_BOUND_1_REACH_ALL))
    context = {6: _passing(6), 7: _failing(7), 8: _failing(8)}
    res = check_creds.run(str(tmp_path), context=context)
    assert res.status == "FAIL"
    assert "control-plane" in res.detail and "vpn-pivot" in res.detail
    assert "imds" not in res.detail


def test_attacker_declared_bound_is_capped(tmp_path):
    # declaring a huge bound must not let wide reach through
    graph = {"declared_blast_radius_bound": 999,
             "identities": [{"name": "pwned", "reach": ["imds", "control-plane"]}]}
    write(tmp_path, "b9_credentials", "credential_scope.yaml", yaml.dump(SCOPE_OK))
    write(tmp_path, "b9_credentials", "iam_graph.json", json.dumps(graph))
    res = check_creds.run(str(tmp_path), context={})  # no upstream closures
    assert res.status == "FAIL" and "capped" in res.detail


def test_fail_when_missing_files(tmp_path):
    assert check_creds.run(str(tmp_path), context={}).status == "FAIL"


def test_run_checks_passes_context_kwarg_automatically():
    import inspect
    assert "context" in inspect.signature(check_creds.run).parameters
