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
API_NODE = "kubernetes.default.svc"


def _exploitable(edge: dict) -> bool:
    """An edge is a real path only if BOTH the network and RBAC layers permit it."""
    if "allowed" in edge:
        return bool(edge.get("allowed"))
    return bool(edge.get("network_reachable")) and bool(edge.get("rbac_permitted"))


def _single_layer_open(edge: dict) -> str | None:
    """Flag edges where only one of the two layers is doing the blocking - a
    single point of failure even though the edge isn't exploitable *today*."""
    if "allowed" in edge:
        return None  # legacy schema carries no per-layer info to compare
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
        # Plain BFS fallback - no networkx required.
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

    worker_nodes = [n for n in nodes if n != API_NODE]
    reachable_from = [w for w in worker_nodes if _reachable(nodes, exploitable_edges, w, API_NODE)]

    if reachable_from:
        return CheckResult(7, "Control-plane unreachable from workers", "FAIL",
                            f"API server reachable from: {', '.join(reachable_from)} "
                            f"(both NetworkPolicy and RBAC permit the route)",
                            evidence=[str(cfg)])

    warnings = [w for e in edges for w in [_single_layer_open(e)] if w]
    detail = "no path from any worker to the API server survives both the NetworkPolicy and RBAC layers"
    if warnings:
        detail += f"; hardening note - single-layer-only edges (fix before the other layer regresses): {'; '.join(warnings)}"

    return CheckResult(7, "Control-plane unreachable from workers", "PASS",
                        detail, evidence=[str(cfg)])
