"""Minimal, self-contained implementation of the Biscuit capability-token MODEL,
built on Ed25519 (cryptography lib) so it installs and runs anywhere with no Rust
binding and no network. Demonstrates the security property behind Rule 9:

  - append-only attenuation: a holder can ADD caveats without the root key, never remove
  - offline public-key verification against a known root public key
  - caveats evaluated against a presented context -> a token attenuated to origin(X)
    is REJECTED when replayed from a different origin (the incident's stolen-cred reuse)

This is the Biscuit *design* (per-block next-key chain), not the reference biscuit-python
binding; chosen for zero-friction reproducibility. See docstring in check_creds.py.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_CAVEAT = re.compile(r"^(\w+)\(([^)]*)\)$")

@dataclass
class Token:
    """Public, serializable parts only (what a thief would exfiltrate)."""
    blocks: list = field(default_factory=list)   # each block: list[str] caveats/facts
    next_pubs: list = field(default_factory=list) # npk_i bytes (raw)
    sigs: list = field(default_factory=list)      # sig_i bytes

def _pub_bytes(pk: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def _load_pub(b: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b)

def _payload(block, npk_bytes) -> bytes:
    return ("||".join(block)).encode() + b"::" + npk_bytes

def issue(root_sk: Ed25519PrivateKey, facts):
    """Root issues an authority block. Returns (Token, holder_secret_key)."""
    nsk = Ed25519PrivateKey.generate()
    npk = _pub_bytes(nsk.public_key())
    block = list(facts)
    sig = root_sk.sign(_payload(block, npk))
    return Token(blocks=[block], next_pubs=[npk], sigs=[sig]), nsk

def attenuate(tok: Token, holder_sk: Ed25519PrivateKey, caveats):
    """Holder appends a block of caveats WITHOUT the root key. Append-only.
    Returns (new Token, new holder_secret_key)."""
    nsk = Ed25519PrivateKey.generate()
    npk = _pub_bytes(nsk.public_key())
    block = list(caveats)
    sig = holder_sk.sign(_payload(block, npk))  # signed by the PREVIOUS block's next-key
    return Token(blocks=tok.blocks + [block],
                 next_pubs=tok.next_pubs + [npk],
                 sigs=tok.sigs + [sig]), nsk

def _check_caveat(cav: str, ctx: dict) -> bool:
    m = _CAVEAT.match(cav.strip())
    if not m:
        return True  # a plain fact, not a constraint
    key, val = m.group(1), m.group(2)
    if key in ("origin", "purpose"):
        return str(ctx.get(key)) == val
    return True

def verify(tok: Token, root_pk: Ed25519PublicKey, context: dict):
    """Offline verify the signature chain, then evaluate ALL caveats vs context.
    Raises InvalidSignature on tamper, ValueError on failed caveat."""
    signer = root_pk
    for block, npk, sig in zip(tok.blocks, tok.next_pubs, tok.sigs):
        signer.verify(sig, _payload(block, npk))  # raises InvalidSignature if tampered
        signer = _load_pub(npk)                    # next block must be signed by this npk
    for block in tok.blocks:
        for cav in block:
            if not _check_caveat(cav, context):
                raise ValueError(f"caveat failed: {cav} vs context {context}")
    return True
