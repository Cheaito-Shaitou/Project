import os
import json
import time
import base64
import hashlib
import sys
from pathlib import Path
from typing import Tuple, Dict, Optional, Union

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =========================================================
# Base64 URL-safe helpers
# =========================================================
def b64url_encode(data: bytes) -> str:
    """Encode bytes to URL-safe Base64 string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def b64url_decode(s: str) -> bytes:
    """Decode URL-safe Base64 string (adds padding if needed)."""
    padding_needed = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + padding_needed).encode("utf-8"))

# =========================================================
# Utility helpers
# =========================================================
def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def now_unix() -> int:
    return int(time.time())

def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

# =========================================================
# RSA key generation & PEM handling
# =========================================================
def gen_rsa_keypair(key_size: int = 3072):
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return priv, priv.public_key()

def export_pub_pem(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def export_priv_pem_encrypted(priv, password: str) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    )

def import_pub_pem(pem: bytes):
    return serialization.load_pem_public_key(pem, backend=default_backend())

def import_priv_pem_encrypted(pem: bytes, password: str):
    return serialization.load_pem_private_key(
        pem,
        password=password.encode("utf-8"),
        backend=default_backend()
    )

def key_fingerprint(pub) -> str:
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fp = hashlib.sha256(der).hexdigest()
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))

def key_fingerprint_bytes(pub) -> bytes:
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).digest()

# =========================================================
# AES-256-GCM
# =========================================================
def aes_gcm_encrypt(plaintext: bytes, key32: bytes, aad: bytes) -> Dict[str, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key32)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return {
        "nonce": nonce,
        "ciphertext": ct_and_tag[:-16],
        "tag": ct_and_tag[-16:]
    }

def aes_gcm_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key32: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key32)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)

# =========================================================
# RSA-OAEP + RSA-PSS
# =========================================================
def rsa_oaep_encrypt(data: bytes, pub) -> bytes:
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_oaep_decrypt(data: bytes, priv) -> bytes:
    return priv.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_pss_sign(message: bytes, priv) -> bytes:
    return priv.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_pss_verify(message: bytes, signature: bytes, pub) -> bool:
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# =========================================================
# Hybrid payload components
# =========================================================
_AAD_V3 = b"EncryptedQR:v3"

def _u16(n: int) -> bytes:
    return int(n).to_bytes(2, "big", signed=False)

def _u32(n: int) -> bytes:
    return int(n).to_bytes(4, "big", signed=False)

def _pack_signing_bytes_v3(comp: Dict[str, object]) -> bytes:
    mode_b = b"\x01" if comp["mode"] == "text" else b"\x02"
    sender_id = bytes(comp["sender_id"])[:255]
    rx_fp = bytes(comp["rx_fp"])
    pt_h = bytes(comp["pt_h"])
    blob_h = bytes(comp["blob_h"])
    enc_key = bytes(comp["enc_key"])
    iat = int(comp["iat"])
    exp = int(comp["exp"])
    fn = comp.get("fn", None)
    fn_b = bytes(fn) if fn is not None else b""
    
    out = bytearray()
    out += b"SQR3"
    out += mode_b
    out += _u32(iat)
    out += _u32(exp)
    out += bytes([len(sender_id)]) + sender_id
    out += rx_fp
    out += pt_h
    out += blob_h
    out += _u16(len(enc_key)) + enc_key
    out += _u16(len(fn_b)) + fn_b
    return bytes(out)

def build_payload_components(plaintext_bytes: bytes, receiver_pub, sender_sign_priv, mode: str,
                             filename: Optional[str] = None, sender_id: str = "User", ttl_seconds: int = 3600) -> Dict[str, object]:
    if mode not in ("text", "file"): raise ValueError("mode must be 'text' or 'file'")
    aes_key = os.urandom(32)
    enc = aes_gcm_encrypt(plaintext_bytes, aes_key, _AAD_V3)
    blob = enc["nonce"] + enc["ciphertext"] + enc["tag"]
    enc_key = rsa_oaep_encrypt(aes_key, receiver_pub)
    iat = now_unix()
    exp = iat + ttl_seconds if ttl_seconds > 0 else 0
    comp: Dict[str, object] = {
        "v": 3, "mode": mode, "iat": iat, "exp": exp,
        "sender_id": sender_id.encode("utf-8"),
        "rx_fp": key_fingerprint_bytes(receiver_pub),
        "enc_key": enc_key, "pt_h": sha256_bytes(plaintext_bytes),
        "blob_h": sha256_bytes(blob), "blob": blob,
    }
    if mode == "file": comp["fn"] = (filename or "file.bin").encode("utf-8")
    else: comp["fn"] = None
    sig_msg = _pack_signing_bytes_v3(comp)
    comp["sig"] = rsa_pss_sign(sig_msg, sender_sign_priv)
    return comp

def decrypt_and_verify_components(comp: Dict[str, object], receiver_priv, sender_verify_pub,
                                  enforce_expiry: bool = True, enforce_recipient_fp: bool = True) -> Tuple[dict, bytes]:
    if int(comp.get("v", 3)) != 3: raise ValueError("Unsupported components version")
    now_t = now_unix()
    exp = int(comp.get("exp", 0))
    if enforce_expiry and exp and now_t > exp: raise ValueError("QR payload expired")
    if enforce_recipient_fp:
        rx_fp_expected = key_fingerprint_bytes(receiver_priv.public_key())
        if bytes(comp["rx_fp"]) != rx_fp_expected: raise ValueError("Recipient fingerprint mismatch")
    if not rsa_pss_verify(_pack_signing_bytes_v3(comp), bytes(comp["sig"]), sender_verify_pub):
        raise ValueError("Signature verification failed")
    aes_key = rsa_oaep_decrypt(bytes(comp["enc_key"]), receiver_priv)
    blob = bytes(comp["blob"])
    nonce, tag, ciphertext = blob[:12], blob[-16:], blob[12:-16]
    plaintext = aes_gcm_decrypt(nonce, ciphertext, tag, aes_key, _AAD_V3)
    if sha256_bytes(plaintext) != bytes(comp["pt_h"]): raise ValueError("Plaintext integrity check failed")
    meta = {
        "v": 3, "mode": comp["mode"], 
        "sender_id": bytes(comp["sender_id"]).decode("utf-8", errors="replace"),
        "iat": int(comp["iat"]), "exp": int(comp["exp"]),
    }
    if comp.get("fn"): meta["fn"] = bytes(comp["fn"]).decode("utf-8", errors="replace")
    return meta, plaintext

# =========================================================
# User storage (FIXED FOR EXECUTABLE PERSISTENCE)
# =========================================================
if getattr(sys, 'frozen', False):
    # If running as an EXE, BASE_DIR is the folder containing the EXE
    BASE_DIR = Path(sys.executable).parent
else:
    # If running as a script, BASE_DIR is the folder containing this file
    BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "app_data"
USERS_DIR = DATA_DIR / "users"

def list_users() -> list:
    if not USERS_DIR.exists(): return []
    return sorted(p.name for p in USERS_DIR.iterdir() if p.is_dir())

def create_user(username: str, password: str):
    u_dir = USERS_DIR / username
    if u_dir.exists(): raise ValueError("User already exists")
    (u_dir / "keys").mkdir(parents=True, exist_ok=True)
    (u_dir / "contacts").mkdir(parents=True, exist_ok=True)
    e_priv, e_pub = gen_rsa_keypair()
    s_priv, s_pub = gen_rsa_keypair()
    (u_dir / "keys/enc_public.pem").write_bytes(export_pub_pem(e_pub))
    (u_dir / "keys/sign_public.pem").write_bytes(export_pub_pem(s_pub))
    (u_dir / "keys/enc_private.pem").write_bytes(export_priv_pem_encrypted(e_priv, password))
    (u_dir / "keys/sign_private.pem").write_bytes(export_priv_pem_encrypted(s_priv, password))
    meta = {"username": username, "enc_fp": key_fingerprint(e_pub), "sign_fp": key_fingerprint(s_pub)}
    (u_dir / "user.json").write_text(json.dumps(meta, indent=2))

def login_user(username: str, password: str) -> dict:
    u_dir = USERS_DIR / username
    if not u_dir.exists(): raise ValueError("User not found")
    enc_priv = import_priv_pem_encrypted((u_dir / "keys/enc_private.pem").read_bytes(), password)
    sign_priv = import_priv_pem_encrypted((u_dir / "keys/sign_private.pem").read_bytes(), password)
    meta = json.loads((u_dir / "user.json").read_text())
    return {
        **meta, "enc_priv": enc_priv, "sign_priv": sign_priv,
        "enc_pub": import_pub_pem((u_dir / "keys/enc_public.pem").read_bytes()),
        "sign_pub": import_pub_pem((u_dir / "keys/sign_public.pem").read_bytes()),
        "contacts_dir": str(u_dir / "contacts"),
    }