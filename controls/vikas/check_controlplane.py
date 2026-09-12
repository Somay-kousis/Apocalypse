"""Rule 7: no RBAC/NetworkPolicy path from a data-plane worker to the API server.

Graph reachability, not a keyword check (artifact_type: yaml, but the field
that matters - "is there a path?" - is relational). Uses networkx if present;
falls back to a plain BFS over allowed edges so this still runs with a minimal
install.
"""
from pathlib import Path
import yaml
from controls.base import CheckResult

BOUNDARY_DIR = "b7_controlplane"
CONFIG_FILE = "rbac_graph.yaml"
API_NODE = "kubernetes.default.svc"


def _reachable(nodes, allowed_edges, start, target):
    try:
        import networkx as nx
        g = nx.DiGraph()
        g.add_nodes_from(nodes)
        g.add_edges_from(allowed_edges)
        return nx.has_path(g, start, target) if start in g and target in g else False
    except ImportError:
        # Plain BFS fallback - no networkx required.
        adjacency = {}
        for a, b in allowed_edges:
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
    allowed_edges = [(e["from"], e["to"]) for e in edges if e.get("allowed")]

    worker_nodes = [n for n in nodes if n != API_NODE]
    reachable_from = [w for w in worker_nodes if _reachable(nodes, allowed_edges, w, API_NODE)]

    if reachable_from:
        return CheckResult(7, "Control-plane unreachable from workers", "FAIL",
                            f"API server reachable from: {', '.join(reachable_from)}",
                            evidence=[str(cfg)])

    return CheckResult(7, "Control-plane unreachable from workers", "PASS",
                        "no allowed RBAC/NetworkPolicy path from any worker to the API server",
                        evidence=[str(cfg)])
