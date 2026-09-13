"""Executable tests for Somay's controls (rules 4,5,9) + the capability-token primitive.
Behavioural, offline. Includes regression tests for red-team findings (captoken truncation,
rule-5 marker evasion, rule-4 external raw storage). Run: pytest -q
"""
import tempfile, os, shutil
import h5py
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from controls.somay import check_hdf5, check_jinja, check_creds, captoken as ct
from controls.somay.captoken import Token
from tests.conftest import write

FIXED = "environments/fixed_lab/configs"
BROKEN = "environments/broken_lab/configs"

# ---- capability token primitive (rule 9 core) ----
def _mint(caveats):
    root = Ed25519PrivateKey.generate()
    tok, sk = ct.issue(root, ["sa(worker)"], caveats=caveats)
    tok, sk = ct.attenuate(tok, sk, ["single_use(true)"])
    return ct.seal(tok, sk), root.public_key()

def test_attenuated_token_dies_off_origin():
    tok, rpk = _mint(["origin(hf_worker)", "purpose(eval)"])
    assert ct.verify(tok, rpk, {"origin": "hf_worker", "purpose": "eval"})
    with pytest.raises(ValueError):
        ct.verify(tok, rpk, {"origin": "attacker", "purpose": "eval"})

def test_truncation_attack_rejected():
    # regression: strip the attenuation block off a stolen token, replay off-origin
    tok, rpk = _mint(["origin(hf_worker)", "purpose(eval)"])
    trunc = Token(tok.blocks[:1], tok.next_pubs[:1], tok.sigs[:1], seal=tok.seal)
    with pytest.raises((InvalidSignature, ValueError)):
        ct.verify(trunc, rpk, {"origin": "attacker"})

def test_unsealed_token_rejected():
    root = Ed25519PrivateKey.generate()
    tok, _ = ct.issue(root, ["sa(worker)"], caveats=["origin(x)"])
    with pytest.raises(ValueError):
        ct.verify(tok, root.public_key(), {"origin": "x"})  # no seal

def test_tampered_token_rejected():
    tok, rpk = _mint(["origin(x)"])
    tok.blocks[0][0] = "sa(root)"
    with pytest.raises(InvalidSignature):
        ct.verify(tok, rpk, {"origin": "x"})

# ---- rule 4: HDF5 external references ----
def test_rule4_fixed_refuses_all_external_vectors():
    assert check_hdf5.run(FIXED).status == "PASS"

def test_rule4_broken_leaks_secret():
    r = check_hdf5.run(BROKEN)
    assert r.status == "FAIL" and "leaked" in r.detail

def test_rule4_detects_external_raw_storage():
    # regression: the incident's actual vector (H5Pset_external), not just ExternalLink
    tmp = tempfile.mkdtemp(); raw = os.path.join(tmp, "s.bin"); mal = os.path.join(tmp, "m.h5")
    try:
        open(raw, "wb").write(b"SECRET!!")
        with h5py.File(mal, "w") as f:
            f.create_dataset("p", shape=(8,), dtype="u1", external=[(raw, 0, 8)])
        with pytest.raises(check_hdf5.ExternalRefRefused):
            check_hdf5._reference_loader(mal, allow_external=False)
    finally:
        shutil.rmtree(tmp)

# ---- rule 5: templating of untrusted config ----
def test_rule5_fixed_blocks_ssti():
    assert check_jinja.run(FIXED).status == "PASS"

def test_rule5_broken_evaluates_ssti():
    r = check_jinja.run(BROKEN)
    assert r.status == "FAIL" and "internals" in r.detail

def test_rule5_compile_expression_not_missed(tmp_path):
    # regression: jinja evaluation via compile_expression must not be classified 'norender'
    write(tmp_path, "b5_jinja", "config_pipeline.txt",
          "env = Environment()\nexpr = env.compile_expression(untrusted_config)\n")
    assert check_jinja.run(str(tmp_path)).status == "FAIL"

def test_rule5_format_string_not_missed(tmp_path):
    write(tmp_path, "b5_jinja", "config_pipeline.txt",
          'msg = "x {c.__class__}".format(c=untrusted_config)\n')
    assert check_jinja.run(str(tmp_path)).status == "FAIL"

# ---- rule 9 ----
def test_rule9_fixed_passes_live_replay():
    assert check_creds.run(FIXED, context={}).status == "PASS"

def test_rule9_broken_fails():
    assert check_creds.run(BROKEN, context={}).status == "FAIL"
