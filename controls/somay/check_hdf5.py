"""Rule 4: dataset loader must refuse HDF5 external raw storage refs.
NOW EXECUTES: builds a real malicious HDF5 file with an ExternalLink pointing at a secret
(the incident's envu8.h5 -> /proc/self/environ read), then runs a policy-driven reference
loader against it. Hardened policy (external links off) must REFUSE and leak nothing;
a permissive policy follows the link and leaks -> FAIL. Fully offline, temp files cleaned up."""
import tempfile, os
from pathlib import Path
import h5py
from controls.base import CheckResult

DANGEROUS_DRIVERS = {"family", "split", "multi"}
# Regression guard: a forbidden construct left in the config text (even commented
# out, or referenced as a "legacy path") means the loader policy can't be trusted
# even when the allow_external_links flag itself reads as safe.
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

def _reference_loader(path, allow_external):
    """A loader that honors the policy. Returns any bytes it leaked via external refs."""
    leaked = []
    with h5py.File(path, "r") as f:
        for key in f.keys():
            link = f.get(key, getlink=True)
            if isinstance(link, h5py.ExternalLink):
                if not allow_external:
                    raise ExternalRefRefused(f"external link {key!r} refused by policy")
                leaked.append(bytes(f[key][()]))   # permissive loader follows -> leak
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

    # A forbidden construct anywhere in the file (even in a comment describing a
    # "legacy path") means the policy can't be trusted, regardless of the flag.
    lowered = raw.lower()
    found = [c for c in FORBIDDEN_CONSTRUCTS if c in lowered]
    if found:
        return CheckResult(4, "Loader refuses external refs", "FAIL",
                           f"forbidden construct present in loader policy: {', '.join(found)}",
                           evidence=[str(cfg)])

    tmp = tempfile.mkdtemp(prefix="rule4_")
    secret_path, mal_path = os.path.join(tmp, "secret.h5"), os.path.join(tmp, "malicious.h5")
    try:
        with h5py.File(secret_path, "w") as s:
            s["secret"] = b"AWS_SECRET=leaked-from-/proc/self/environ"
        with h5py.File(mal_path, "w") as m:
            m["payload"] = h5py.ExternalLink(secret_path, "secret")  # the attack primitive
        try:
            leaked = _reference_loader(mal_path, allow_external)
        except ExternalRefRefused as e:
            if driver in DANGEROUS_DRIVERS:
                return CheckResult(4, "Loader refuses external refs", "FAIL",
                                   f"external links refused but hdf5_driver {driver!r} still permits external raw storage",
                                   evidence=[str(cfg)])
            return CheckResult(4, "Loader refuses external refs", "PASS",
                               f"crafted external-link read refused ({e})", evidence=[str(cfg)])
        return CheckResult(4, "Loader refuses external refs", "FAIL",
                           f"loader followed external link and leaked {len(leaked)} secret(s): {leaked[:1]}",
                           evidence=[str(cfg)])
    finally:
        for p in (secret_path, mal_path):
            try: os.remove(p)
            except OSError: pass
        try: os.rmdir(tmp)
        except OSError: pass
