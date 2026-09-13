"""Rule 4: dataset loader must refuse HDF5 external references of ALL kinds.
EXECUTES: crafts a malicious HDF5 file that uses BOTH an ExternalLink AND external raw
storage (H5Pset_external, the incident's actual envu8.h5 -> /proc/self/environ vector),
then runs a policy-driven reference loader. Hardened policy (external off) must refuse
every vector and leak nothing; a permissive policy follows them and leaks -> FAIL.
Fully offline, temp files cleaned up."""
import tempfile, os
from pathlib import Path
import h5py
from controls.base import CheckResult

DANGEROUS_DRIVERS = {"family", "split", "multi"}
FORBIDDEN_CONSTRUCTS = {"h5pset_external", "set_external_storage"}

class ExternalRefRefused(Exception): pass

def _parse(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out

def _external_vectors(f):
    """Every external-data vector present: link-to-other-file, external raw storage, or VDS."""
    hits = []
    for key in f.keys():
        link = f.get(key, getlink=True)
        if isinstance(link, h5py.ExternalLink):
            hits.append(("external_link", key)); continue
        try:
            obj = f[key]
        except Exception:
            continue
        if isinstance(obj, h5py.Dataset):
            try:
                if obj.id.get_create_plist().get_external_count() > 0:
                    hits.append(("external_raw_storage", key)); continue
            except Exception:
                pass
            if getattr(obj, "is_virtual", False):
                hits.append(("virtual_dataset", key))
    return hits

def _reference_loader(path, allow_external):
    """Honor the policy across all external vectors. Returns bytes leaked if permissive."""
    leaked = []
    with h5py.File(path, "r") as f:
        vectors = _external_vectors(f)
        if vectors and not allow_external:
            raise ExternalRefRefused(f"external references refused by policy: {vectors}")
        for _kind, key in vectors:
            try:
                leaked.append(bytes(f[key][()]))
            except Exception:
                leaked.append(b"<unreadable external ref>")
    return leaked

def run(target_dir: str) -> CheckResult:
    cfg = Path(target_dir) / "b4_hdf5" / "loader_policy.txt"
    if not cfg.exists():
        return CheckResult(4, "Loader refuses external refs", "FAIL",
                           "no b4_hdf5/loader_policy.txt: loader is unconstrained (broken default)")
    raw = cfg.read_text()
    kv = _parse(raw)
    allow_external = kv.get("allow_external_links") != "false"
    driver = kv.get("hdf5_driver", "")

    found = [c for c in FORBIDDEN_CONSTRUCTS if c in raw.lower()]
    if found:
        return CheckResult(4, "Loader refuses external refs", "FAIL",
                           f"forbidden construct present in loader policy: {', '.join(found)}",
                           evidence=[str(cfg)])

    tmp = tempfile.mkdtemp(prefix="rule4_")
    secret_h5 = os.path.join(tmp, "secret.h5")
    secret_raw = os.path.join(tmp, "secret.bin")
    mal = os.path.join(tmp, "malicious.h5")
    try:
        payload = b"AWS_SECRET=leaked-from-/proc/self/environ"
        with h5py.File(secret_h5, "w") as s:
            s["secret"] = payload
        with open(secret_raw, "wb") as r:
            r.write(payload)
        with h5py.File(mal, "w") as m:
            m["via_link"] = h5py.ExternalLink(secret_h5, "secret")                 # vector 1
            m.create_dataset("via_raw_storage", shape=(len(payload),), dtype="u1", # vector 2 (incident)
                             external=[(secret_raw, 0, len(payload))])
        try:
            leaked = _reference_loader(mal, allow_external)
        except ExternalRefRefused as e:
            if driver in DANGEROUS_DRIVERS:
                return CheckResult(4, "Loader refuses external refs", "FAIL",
                                   f"external refs refused but hdf5_driver {driver!r} still permits external raw storage",
                                   evidence=[str(cfg)])
            return CheckResult(4, "Loader refuses external refs", "PASS",
                               f"all crafted external vectors refused ({e})", evidence=[str(cfg)])
        return CheckResult(4, "Loader refuses external refs", "FAIL",
                           f"loader followed external refs and leaked {len(leaked)} value(s): {leaked[:1]}",
                           evidence=[str(cfg)])
    finally:
        for p in (secret_h5, secret_raw, mal):
            try: os.remove(p)
            except OSError: pass
        try: os.rmdir(tmp)
        except OSError: pass
