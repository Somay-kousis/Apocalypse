import yaml
from controls.vikas import check_controlplane
from tests.conftest import write


def test_pass_when_no_allowed_edge_legacy_schema(tmp_path):
    """Legacy single-flag schema still supported."""
    graph = {"nodes": ["worker", "kubernetes.default.svc"],
             "edges": [{"from": "worker", "to": "kubernetes.default.svc", "allowed": False}]}
    write(tmp_path, "b7_controlplane", "rbac_graph.yaml", yaml.dump(graph))
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_direct_allowed_edge_legacy_schema(tmp_path):
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


def test_pass_when_only_one_layer_open_per_edge(tmp_path):
    """Two-layer model: NetworkPolicy routes worker->API, but RBAC denies the
    identity (and vice versa on a second edge). Neither edge is exploitable alone
    (both layers must agree), so this should PASS - with a hardening note flagging
    the single points of failure."""
    graph = {
        "nodes": ["worker", "worker-b", "kubernetes.default.svc"],
        "edges": [
            {"from": "worker", "to": "kubernetes.default.svc",
             "network_reachable": True, "rbac_permitted": False},
            {"from": "worker-b", "to": "kubernetes.default.svc",
             "network_reachable": False, "rbac_permitted": True},
        ],
    }
    write(tmp_path, "b7_controlplane", "rbac_graph.yaml", yaml.dump(graph))
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "PASS"
    assert "hardening note" in res.detail


def test_fail_when_both_layers_open(tmp_path):
    """Both NetworkPolicy and RBAC permit the route - this is the real, exploitable
    path the rule exists to catch under the two-layer schema."""
    graph = {
        "nodes": ["worker", "kubernetes.default.svc"],
        "edges": [
            {"from": "worker", "to": "kubernetes.default.svc",
             "network_reachable": True, "rbac_permitted": True},
        ],
    }
    write(tmp_path, "b7_controlplane", "rbac_graph.yaml", yaml.dump(graph))
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "FAIL"
    assert "both NetworkPolicy and RBAC" in res.detail


def test_fail_when_layers_open_across_a_multi_hop_pivot(tmp_path):
    """The two-layer distinction has to compose across hops too: worker reaches a
    pivot only over the network (RBAC denies it there), but the pivot to the API
    server is only permitted by RBAC (network denies it there). Neither single hop
    is exploitable, so the combined multi-hop path shouldn't be exploitable either -
    this asserts the checker isn't fooled into conflating per-hop layers across
    hops."""
    graph = {
        "nodes": ["worker", "pivot-node", "kubernetes.default.svc"],
        "edges": [
            {"from": "worker", "to": "pivot-node",
             "network_reachable": True, "rbac_permitted": False},
            {"from": "pivot-node", "to": "kubernetes.default.svc",
             "network_reachable": False, "rbac_permitted": True},
        ],
    }
    write(tmp_path, "b7_controlplane", "rbac_graph.yaml", yaml.dump(graph))
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "PASS"


def test_fail_when_missing_file(tmp_path):
    res = check_controlplane.run(str(tmp_path))
    assert res.status == "FAIL"
