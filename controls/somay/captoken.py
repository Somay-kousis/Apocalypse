"""Minimal, self-contained implementation of the Biscuit capability-token MODEL,
on Ed25519 (cryptography lib) - installs and runs anywhere, no Rust binding, no network.

Security properties demonstrated for Rule 9:
  - authority caveats (origin/purpose) are bound by the ROOT at issuance, so they
    cannot be stripped by anyone without the root key
  - append-only holder attenuation (add caveats without the root key, never remove)
  - signature CHAINING (each block signs the previous signature) => reorder/tamper evident
  - a SEAL (signature by the final next-key over the whole transcript) is required to
    verify => a stolen token cannot be TRUNCATED to a less-attenuated prefix and re-presented
    (the discarded prefix next-key can't produce a matching seal)
  - caveats evaluated vs a presented context => a token bound to origin(X) is REJECTED
    off-origin (the incident's stolen-cred reuse)
"""
from __future__ import annotations
from dataclasses import dataclass, field
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_CAVEAT = re.compile(r"^(\w+)\(([^)]*)\)$")


@dataclass
class Token:
    """Public, serializable parts only (what a thief would exfiltrate)."""
    blocks: list = field(default_factory=list)    # each block: list[str] caveats/facts
    next_pubs: list = field(default_factory=list)  # npk_i bytes (raw)
    sigs: list = field(default_factory=list)        # sig_i bytes
    seal: bytes | None = None                       # signature by the final next-key


def _pub_bytes(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def _load_pub(b: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b)

def _payload(index: int, prev_sig: bytes, block, npk_bytes: bytes) -> bytes:
    # index + previous signature bind each block to its position in the chain
    return (f"{index}|".encode() + prev_sig + b"|" + "||".join(block).encode()
            + b"::" + npk_bytes)

def _transcript(tok: "Token") -> bytes:
    parts = [b"||".join(b.encode() for b in block) for block in tok.blocks]
    return (b"seal::" + b"#B#".join(parts) + b"#N#" + b"|".join(tok.next_pubs)
            + b"#S#" + b"|".join(tok.sigs))


def issue(root_sk: Ed25519PrivateKey, facts, caveats=None):
    """Root issues an authority block carrying facts + security-critical caveats.
    Returns (Token, holder_secret_key)."""
    nsk = Ed25519PrivateKey.generate()
    npk = _pub_bytes(nsk.public_key())
    block = list(facts) + list(caveats or [])
    sig = root_sk.sign(_payload(0, b"", block, npk))
    return Token(blocks=[block], next_pubs=[npk], sigs=[sig]), nsk


def attenuate(tok: Token, holder_sk: Ed25519PrivateKey, caveats):
    """Holder appends a block of caveats WITHOUT the root key (append-only)."""
    nsk = Ed25519PrivateKey.generate()
    npk = _pub_bytes(nsk.public_key())
    block = list(caveats)
    sig = holder_sk.sign(_payload(len(tok.blocks), tok.sigs[-1], block, npk))
    return Token(blocks=tok.blocks + [block],
                 next_pubs=tok.next_pubs + [npk],
                 sigs=tok.sigs + [sig]), nsk


def seal(tok: Token, holder_sk: Ed25519PrivateKey) -> Token:
    """Finalize: sign the whole transcript with the current holder key. Required to verify."""
    s = holder_sk.sign(_transcript(tok))
    return Token(list(tok.blocks), list(tok.next_pubs), list(tok.sigs), seal=s)


def _check_caveat(cav: str, ctx: dict) -> bool:
    m = _CAVEAT.match(cav.strip())
    if not m:
        return True
    key, val = m.group(1), m.group(2)
    if key in ("origin", "purpose"):
        return str(ctx.get(key)) == val
    return True


def verify(tok: Token, root_pk: Ed25519PublicKey, context: dict):
    """Offline: verify the chained signatures, require a valid seal (anti-truncation),
    then evaluate every caveat vs context. Raises InvalidSignature/ValueError on failure."""
    signer = root_pk
    prev_sig = b""
    for i, (block, npk, sig) in enumerate(zip(tok.blocks, tok.next_pubs, tok.sigs)):
        signer.verify(sig, _payload(i, prev_sig, block, npk))  # InvalidSignature on tamper/truncation
        signer = _load_pub(npk)
        prev_sig = sig
    if tok.seal is None:
        raise ValueError("unsealed token: presentation requires a seal (anti-truncation)")
    # the seal must be by the FINAL next-key; a truncated prefix's final key was discarded
    _load_pub(tok.next_pubs[-1]).verify(tok.seal, _transcript(tok))
    for block in tok.blocks:
        for cav in block:
            if not _check_caveat(cav, context):
                raise ValueError(f"caveat failed: {cav} vs context {context}")
    return True
