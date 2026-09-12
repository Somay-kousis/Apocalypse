import yaml
from controls.vikas import check_controlplane
from tests.conftest import write


def test_pass_when_no_allowed_edge(tmp_path):
    graph = {"nodes": ["worker", "kubernetes.default.svc"],
             "edges": [{"from": "worker", "to": "kubernetes.default.svc", "allowed": False}]}
    write(tmp_path, "b7_controlplane", "rbac_graph.yaml", yaml.dump(graph))
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_direct_allowed_edge(tmp_path):
    graph = {"nodes": ["worker", "kubernetes.default.svc"],
             "edges": [{"from": "worker", "to": "kubernetes.default.svc", "allowed": True}]}
    write(tmp_path, "b7_controlplane", "rbac_graph.yaml", yaml.dump(graph))
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "FAIL"


def test_fail_when_reachable_via_multi_hop_pivot(tmp_path):
    """Adversarial case: no direct edge from worker to the API server, but a
    two-hop allowed path through an intermediate node still reaches it. A
    checker that only looked for a direct edge would incorrectly PASS this."""
    graph = {
        "nodes": ["worker", "pivot-node", "kubernetes.default.svc"],
        "edges": [
            {"from": "worker", "to": "pivot-node", "allowed": True},
            {"from": "pivot-node", "to": "kubernetes.default.svc", "allowed": True},
        ],
    }
    write(tmp_path, "b7_controlplane", "rbac_graph.yaml", yaml.dump(graph))
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "worker" in res.detail


def test_fail_when_missing_file(tmp_path):
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "FAIL"
