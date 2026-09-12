"""Executable test suite for Somay's controls (rules 4, 5, 9) + the capability-token primitive.
These are genuine behavioural tests: they run the crafted HDF5/SSTI exploits and the
mint-and-replay, not string checks. Run: pytest -q
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from controls.somay import check_hdf5, check_jinja, check_creds, captoken as ct

FIXED = "environments/fixed_lab/configs"
BROKEN = "environments/broken_lab/configs"
ADV = "environments/adversarial_lab/configs"

# ---- capability token primitive (rule 9 core) ----
def test_attenuated_token_dies_off_origin():
    root = Ed25519PrivateKey.generate()
    tok, sk = ct.issue(root, ["sa(worker)"])
    tok, sk = ct.attenuate(tok, sk, ["origin(hf_worker)", "purpose(eval)"])
    assert ct.verify(tok, root.public_key(), {"origin": "hf_worker", "purpose": "eval"})
    with pytest.raises(ValueError):
        ct.verify(tok, root.public_key(), {"origin": "attacker", "purpose": "eval"})

def test_bearer_token_works_anywhere():
    root = Ed25519PrivateKey.generate()
    tok, _ = ct.issue(root, ["sa(worker)"])  # no origin caveat
    assert ct.verify(tok, root.public_key(), {"origin": "attacker"})

def test_tampered_token_rejected():
    from cryptography.exceptions import InvalidSignature
    root = Ed25519PrivateKey.generate()
    tok, _ = ct.issue(root, ["sa(worker)"])
    tok.blocks[0][0] = "sa(root)"
    with pytest.raises(InvalidSignature):
        ct.verify(tok, root.public_key(), {})

# ---- rule 4: HDF5 external raw storage ----
def test_rule4_fixed_refuses_external_link():
    assert check_hdf5.run(FIXED).status == "PASS"
def test_rule4_broken_leaks_secret():
    r = check_hdf5.run(BROKEN)
    assert r.status == "FAIL" and "leaked" in r.detail

# ---- rule 5: Jinja SSTI ----
def test_rule5_fixed_blocks_ssti():
    assert check_jinja.run(FIXED).status == "PASS"
def test_rule5_broken_evaluates_ssti():
    r = check_jinja.run(BROKEN)
    assert r.status == "FAIL" and "internals" in r.detail

# ---- rule 9: origin-scoped creds + blast radius ----
def test_rule9_fixed_passes_live_replay():
    assert check_creds.run(FIXED).status == "PASS"
def test_rule9_broken_bearer_fails():
    assert check_creds.run(BROKEN).status == "FAIL"
def test_rule9_adversarial_fails():
    assert check_creds.run(ADV).status == "FAIL"
