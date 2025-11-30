from __future__ import annotations
from typing import Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, hashlib, base64
from .utils import b64e, b64d
from .envelope import Envelope

# --------- Ed25519 (sign/verify) ----------
def ed25519_generate() -> Tuple[bytes, bytes]:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes_raw(), pk.public_bytes_raw()

def ed25519_sign(priv_raw: bytes, data: bytes) -> bytes:
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(priv_raw)
    return sk.sign(data)

def ed25519_verify(pub_raw: bytes, sig: bytes, data: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, data)
        return True
    except Exception:
        return False

# --------- X25519 + HKDF + AES-GCM (encrypt/decrypt) ----------
def x25519_generate() -> Tuple[bytes, bytes]:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes_raw(), pk.public_bytes_raw()
"""
aegnix_core.crypto
------------------
Implements cryptographic primitives for AEGNIX:

- Ed25519: digital signatures for message authenticity
- X25519 + HKDF + AES-GCM: hybrid encryption for payload confidentiality
- Canonical helpers: sign_envelope(), verify_envelope(),
  encrypt_payload_json(), decrypt_payload_json()

These functions are lightweight, dependency-minimal, and portable across
GCP, DoD, or air-gapped deployments.
"""

def derive_key(sender_priv: bytes, recipient_pub: bytes, salt: Optional[bytes] = None, info: bytes = b"aegnix-v1") -> bytes:
    sk = x25519.X25519PrivateKey.from_private_bytes(sender_priv)
    shared = sk.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_pub))
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(shared)  # 256-bit AEAD key

def aead_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)

# --------- Envelope helpers ----------
def sign_envelope(env: Envelope, priv_raw: bytes, key_id: str) -> Envelope:
    env.key_id = key_id
    sig = ed25519_sign(priv_raw, env.to_signing_bytes())
    env.sig = b64e(sig)
    return env

def verify_envelope(env: Envelope, pub_raw: bytes) -> bool:
    if not env.sig:
        return False
    return ed25519_verify(pub_raw, b64d(env.sig), env.to_signing_bytes())

def encrypt_payload_json(payload: dict, key: bytes, aad_fields: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    import json
    aad = None
    if aad_fields:
        aad = json.dumps(aad_fields, separators=(",", ":"), sort_keys=True).encode("utf-8")
    nonce, ct = aead_encrypt(key, json.dumps(payload).encode("utf-8"), aad=aad)
    return {"nonce": b64e(nonce), "ciphertext": b64e(ct)}

def decrypt_payload_json(enc: Dict[str, str], key: bytes, aad_fields: Optional[Dict[str, Any]] = None) -> dict:
    import json
    aad = None
    if aad_fields:
        aad = json.dumps(aad_fields, separators=(",", ":"), sort_keys=True).encode("utf-8")
    pt = aead_decrypt(key, b64d(enc["nonce"]), b64d(enc["ciphertext"]), aad=aad)
    return json.loads(pt.decode("utf-8"))

def compute_pubkey_fingerprint(pubkey_b64: str) -> str:
    """
    Compute a stable fingerprint for an Ed25519 public key.

    - Input: base64-encoded Ed25519 public key
    - Output: hex-encoded SHA256 hash (truncated to 32 chars for readability)

    The fingerprint is used for session binding, identity tracking,
    and cross-AE trust assertions.
    """

    raw = b64d(pubkey_b64)
    digest = hashlib.sha256(raw).hexdigest()

    # Optional: shorten to 16 bytes = 32 hex chars to keep DB smaller
    return digest[:32]