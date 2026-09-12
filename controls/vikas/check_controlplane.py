"""Control-plane unreachable from workers (control 7). Capacity-safe: an edge with no
declared capacity is treated as reachable (fail-closed), not a crash. Audits ALL worker/api pairs."""
from pathlib import Path
import json, networkx as nx
from controls.base import CheckResult

INF = 10**9

def _build(data):
    G = nx.DiGraph()
    for n in data.get("nodes", []):
        G.add_node(n)
    for e in data.get("edges", []):
        G.add_edge(e["source"], e["target"], capacity=e.get("capacity", INF))  # missing => reachable
    return G

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "rbac.json"
    if not cfg.exists():
        return CheckResult(7, "Control-plane unreachable from workers", "FAIL", "missing rbac.json")
    G = _build(json.loads(cfg.read_text()))
    workers = [n for n in G.nodes() if "worker" in n.lower()]
    apis = [n for n in G.nodes() if "api" in n.lower() or "control" in n.lower()]
    if not workers or not apis:
        return CheckResult(7, "Control-plane unreachable from workers", "FAIL",
                           "graph missing worker or API nodes (fail-closed)")
    for w in workers:
        for a in apis:
            if w == a:
                continue
            val, _ = nx.minimum_cut(G, w, a)
            if val > 0:
                return CheckResult(7, "Control-plane unreachable from workers", "FAIL",
                                   f"worker {w} reaches API {a} (min-cut {val})")
    return CheckResult(7, "Control-plane unreachable from workers", "PASS",
                       "no path from any worker to control plane.")
