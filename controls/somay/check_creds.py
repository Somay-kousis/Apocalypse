"""Origin-scoped credentials + blast-radius bound (control 9). CROSS-BOUNDARY (depends_on 6,7,8).

(a) Credential-scope audit -- NOW EXECUTES the replay, not just a manifest check:
    for each declared credential we MINT a real Ed25519 capability token per its policy
    (controls/somay/captoken.py, the Biscuit model), then REPLAY the incident's stolen-cred
    step (POST env+secrets) by presenting the token from a foreign origin. A secure credential
    is attenuated to origin()+purpose() and MUST be rejected off-origin; a bearer token is
    accepted anywhere and fails the check. Static pre-checks (type/origin/purpose/known-node)
    run first for clear evidence.
(b) Min-cut reachability: for EVERY worker node, combined reach across #6-8 targets
    (imds / k8s api / vpn / control) must be strictly 0.
"""
import json, re
import networkx as nx
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from controls.base import CheckResult
from controls.somay import captoken as ct

INF = 10**9
_ORIGIN = re.compile(r"origin\(([^)]*)\)")

def _fail(msg, ev=None):
    return CheckResult(9, "Origin-scoped credentials + blast-radius bound", "FAIL", msg, evidence=ev or [])

def _mint(cred):
    """Mint a real token per the credential's declared policy. Returns (token, holder_sk, root_pk)."""
    root = Ed25519PrivateKey.generate()
    tok, sk = ct.issue(root, [f"service_account({cred.get('identity','?')})"])
    if cred.get("token_type") == "biscuit":
        tok, sk = ct.attenuate(tok, sk, list(cred.get("attenuation", [])))
    return tok, sk, root.public_key()

def run(target_dir: str) -> CheckResult:
    rbac_file = Path(target_dir) / "rbac.json"
    creds_file = Path(target_dir) / "credentials.json"
    if not rbac_file.exists() or not creds_file.exists():
        return _fail("missing rbac.json or credentials.json", [str(target_dir)])

    rbac = json.loads(rbac_file.read_text())
    known_nodes = {str(n).lower() for n in rbac.get("nodes", [])}
    creds = json.loads(creds_file.read_text()).get("credentials", [])
    if not creds:
        return _fail("no credentials declared (fail-closed)", [str(creds_file)])

    # (a) static pre-checks + REAL mint-and-replay per credential
    for c in creds:
        ident = c.get("identity", "<unknown>")
        atts = c.get("attenuation", [])
        origins = [m.group(1) for a in atts for m in [_ORIGIN.search(str(a))] if m]
        if c.get("token_type") != "biscuit":
            return _fail(f"credential {ident!r} is {c.get('token_type')!r}, not an attenuated capability token",
                         [str(creds_file)])
        if not origins:
            return _fail(f"credential {ident!r} has no origin() attenuation", [str(creds_file)])
        if not any("purpose(" in str(a) for a in atts):
            return _fail(f"credential {ident!r} has no purpose() attenuation", [str(creds_file)])
        for o in origins:
            if o.lower() not in known_nodes:
                return _fail(f"credential {ident!r} scoped to unknown/attacker origin {o!r} "
                             f"(not a node in rbac.json)", [str(creds_file)])

        # --- the actual replay: mint, use legitimately, then steal + present off-origin ---
        tok, _sk, rpk = _mint(c)
        legit = {"origin": origins[0], "purpose": "dataset_eval"}
        try:
            ct.verify(tok, rpk, legit)
        except Exception as e:
            return _fail(f"credential {ident!r} unusable even at its own origin ({e})", [str(creds_file)])
        # incident replay: POST /<uuid> <-- env+secrets, token reused from attacker host
        try:
            ct.verify(tok, rpk, {"origin": "attacker_host", "purpose": "dataset_eval"})
            return _fail(f"credential {ident!r} STILL VALID off-origin -- stolen-cred replay succeeds",
                         [str(creds_file)])
        except ValueError:
            pass  # correct: token is dead off-origin

    # (b) blast-radius: min-cut 0 from EVERY worker to every restricted target
    G = nx.DiGraph()
    for n in rbac.get("nodes", []):
        G.add_node(n)
    for e in rbac.get("edges", []):
        G.add_edge(e["source"], e["target"], capacity=e.get("capacity", INF))
    workers = [n for n in G.nodes() if "worker" in n.lower()]
    if not workers:
        return _fail("no worker node in rbac (fail-closed)", [str(rbac_file)])
    targets = [n for n in G.nodes() if any(x in n.lower() for x in ("imds", "api", "vpn", "control"))]
    for w in workers:
        for t in targets:
            if w == t:
                continue
            val, _ = nx.minimum_cut(G, w, t)
            if val > 0:
                return _fail(f"blast-radius exceeded: worker {w} -> {t} min-cut {val}",
                             [f"{rbac_file}: {w}->{t}={val}"])
    return CheckResult(9, "Origin-scoped credentials + blast-radius bound", "PASS",
                       "every credential rejected off-origin under live replay; blast-radius 0.",
                       evidence=[str(creds_file), str(rbac_file)])
