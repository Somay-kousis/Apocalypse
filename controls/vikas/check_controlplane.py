"""Rule 7: no RBAC/NetworkPolicy path from a data-plane worker to the API server.

Graph reachability, not a keyword check (artifact_type: yaml, but the field
that matters - "is there a path?" - is relational). Uses networkx if present;
falls back to a plain BFS over allowed edges so this still runs with a minimal
install.

Schema (preferred): edges carry `network_reachable` and `rbac_permitted` booleans.
Legacy `allowed: bool` is still accepted and is treated as both layers agreeing (kept
so existing fixed_lab/broken_lab fixtures don't need a rewrite).
"""
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b7_controlplane"
CONFIG_FILE = "rbac_graph.yaml"

_API_NODE_NAME_PATTERNS = (
    "kubernetes.default.svc",
    "kube-apiserver",
    "k8s-apiserver",
    "apiserver",
)
_CONTROL_PLANE_VALUES = {"control-plane", "control_plane", "api-server", "api_server", "apiserver"}


def _node_name(node) -> str:
    return node.get("name") if isinstance(node, dict) else node


def _find_api_node(nodes):
    """Identify the control-plane/API-server node structurally.

    Returns the node's name, or None if it can't be identified - callers must
    treat None as fail-closed (unconstrained graph), never as "no target, so
    nothing is reachable."
    """
    has_role_field = any(isinstance(n, dict) and (n.get("role") or n.get("type")) for n in nodes)

    if has_role_field:
        matches = [
            _node_name(n) for n in nodes
            if isinstance(n, dict) and (
                str(n.get("role", "")).lower() in _CONTROL_PLANE_VALUES or
                str(n.get("type", "")).lower() in _CONTROL_PLANE_VALUES
            )
        ]
        return matches[0] if len(matches) == 1 else (matches[0] if matches else None)

    matches = [
        _node_name(n) for n in nodes
        if str(_node_name(n)).lower() in (p.lower() for p in _API_NODE_NAME_PATTERNS)
        or any(pat in str(_node_name(n)).lower() for pat in _API_NODE_NAME_PATTERNS)
    ]
    return matches[0] if len(matches) == 1 else (matches[0] if matches else None)


def _exploitable(edge: dict) -> bool:
    """An edge is a real path only if BOTH the network and RBAC layers permit it."""
    if "allowed" in edge:
        return bool(edge.get("allowed"))
    return bool(edge.get("network_reachable")) and bool(edge.get("rbac_permitted"))


def _single_layer_open(edge: dict) -> str | None:
    """Flag edges where only one of the two layers is doing the blocking - a
    single point of failure even though the edge isn't exploitable *today*."""
    if "allowed" in edge:
        return None
    net, rbac = bool(edge.get("network_reachable")), bool(edge.get("rbac_permitted"))
    if net and not rbac:
        return f"{edge['from']}->{edge['to']}: NetworkPolicy allows the route, only RBAC denies it"
    if rbac and not net:
        return f"{edge['from']}->{edge['to']}: RBAC authorizes the identity, only NetworkPolicy denies it"
    return None


def _reachable(nodes, exploitable_edges, start, target):
    try:
        import networkx as nx
        g = nx.DiGraph()
        g.add_nodes_from(nodes)
        g.add_edges_from(exploitable_edges)
        return nx.has_path(g, start, target) if start in g and target in g else False
    except ImportError:
        adjacency = {}
        for a, b in exploitable_edges:
            adjacency.setdefault(a, []).append(b)
        seen, queue = {start}, [start]
        while queue:
            node = queue.pop()
            if node == target:
                return True
            for nxt in adjacency.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return False


def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / BOUNDARY_DIR / CONFIG_FILE
    if not cfg.exists():
        return CheckResult(7, "Control-plane unreachable from workers", "FAIL",
                            f"no {BOUNDARY_DIR}/{CONFIG_FILE}: RBAC graph unconstrained (broken default)")

    graph = yaml.safe_load(cfg.read_text()) or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    exploitable_edges = [(e["from"], e["to"]) for e in edges if _exploitable(e)]

    node_names = [_node_name(n) for n in nodes]
    api_node = _find_api_node(nodes)

    if api_node is None:
        return CheckResult(7, "Control-plane unreachable from workers", "FAIL",
                            "could not structurally identify a control-plane/API-server node in "
                            f"{BOUNDARY_DIR}/{CONFIG_FILE} (no role/type field and no name matched "
                            "known patterns) - fail-closed: a graph with no identifiable target "
                            "proves nothing about reachability",
                            evidence=[str(cfg)])

    worker_nodes = [n for n in node_names if n != api_node]
    reachable_from = [w for w in worker_nodes if _reachable(node_names, exploitable_edges, w, api_node)]

    if reachable_from:
        return CheckResult(7, "Control-plane unreachable from workers", "FAIL",
                            f"API server reachable from: {', '.join(reachable_from)} "
                            f"(both NetworkPolicy and RBAC permit the route; API node identified as "
                            f"'{api_node}')",
                            evidence=[str(cfg)])

    warnings = [w for e in edges for w in [_single_layer_open(e)] if w]
    detail = "no path from any worker to the API server survives both the NetworkPolicy and RBAC layers"
    if warnings:
        detail += f"; hardening note - single-layer-only edges (fix before the other layer regresses): {'; '.join(warnings)}"

    return CheckResult(7, "Control-plane unreachable from workers", "PASS",
                        detail, evidence=[str(cfg)])