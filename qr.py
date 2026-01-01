import os
import time
from typing import Dict, List, Tuple, Optional, Union

import qrcode
from PIL import Image
from pyzbar.pyzbar import decode

from crypto import b64url_encode, b64url_decode

# =========================================================
# Secure QR (v3) multi-part format
# - No JSON in QR
# - Base64url applied once (to the packed binary QR frame)
# - RSA key + signature stored only in part 0
# =========================================================

_MAGIC = b"SQRQ"  # Secure QR - QR frame
_VER = 1

# QR generation defaults - PC Optimized to prevent 24MB bloat
_DEFAULT_ERR = qrcode.constants.ERROR_CORRECT_M
_DEFAULT_BOX_SIZE = 5  # Reduced from 18 to keep file sizes small
_DEFAULT_BORDER = 4    # Reduced from 8 to save space

def _u32(n: int) -> bytes:
    return int(n).to_bytes(4, "big", signed=False)

def _u16(n: int) -> bytes:
    return int(n).to_bytes(2, "big", signed=False)

def _read_u16(b: bytes, off: int) -> Tuple[int, int]:
    return int.from_bytes(b[off:off + 2], "big"), off + 2

def _read_u32(b: bytes, off: int) -> Tuple[int, int]:
    return int.from_bytes(b[off:off + 4], "big"), off + 4

def make_qr_png(
    data: str,
    out_path: str,
    err=_DEFAULT_ERR,
    box_size: int = _DEFAULT_BOX_SIZE,
    border: int = _DEFAULT_BORDER,
) -> str:
    """Generate a QR PNG image using Pillow."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=err,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)

    pil_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    pil_img.save(out_path)
    return out_path

def scan_qr_from_image_file(path: str) -> str:
    """Decode a QR code from an image file using pyzbar."""
    try:
        with Image.open(path) as img:
            img_gray = img.convert('L')
            decoded_objects = decode(img_gray)
            
            if not decoded_objects:
                decoded_objects = decode(img)

            if decoded_objects:
                return decoded_objects[0].data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error reading or decoding image {path}: {str(e)}")

    raise ValueError(f"No QR code found or could not decode: {path}")

def _chunk_bytes(b: bytes, chunk_size: int) -> List[bytes]:
    return [b[i:i + chunk_size] for i in range(0, len(b), chunk_size)]

def _pack_part(
    session_id: bytes,
    part_idx: int,
    total: int,
    chunk: bytes,
    meta: Optional[Dict[str, object]] = None,
) -> bytes:
    """Pack a v3 QR frame. meta is included ONLY in part 0."""
    flags = 0
    body = b""

    if meta is not None:
        flags |= 0x01
        mode = str(meta["mode"])
        mode_b = b"\x01" if mode == "text" else b"\x02"
        iat = int(meta["iat"])
        exp = int(meta["exp"])
        sender_id = bytes(meta["sender_id"])
        rx_fp = bytes(meta["rx_fp"])      
        enc_key = bytes(meta["enc_key"])
        sig = bytes(meta["sig"])
        pt_h = bytes(meta["pt_h"])        
        blob_h = bytes(meta["blob_h"])    
        fn = meta.get("fn", None)
        fn_b = bytes(fn) if fn is not None else b""

        if len(sender_id) > 255:
            sender_id = sender_id[:255]
        if len(fn_b) > 65535:
            fn_b = fn_b[:65535]

        body = (
            mode_b +
            _u32(iat) +
            _u32(exp) +
            bytes([len(sender_id)]) + sender_id +
            rx_fp +
            pt_h +
            blob_h +
            _u16(len(enc_key)) + enc_key +
            _u16(len(sig)) + sig +
            _u16(len(fn_b)) + fn_b
        )

    header = (
        _MAGIC +
        bytes([_VER]) +
        bytes([flags]) +
        session_id +
        _u16(part_idx) +
        _u16(total)
    )

    return header + body + chunk

def _unpack_part(frame: bytes) -> Dict[str, object]:
    """Unpack binary protocol frame."""
    if len(frame) < 18:
        raise ValueError("Invalid QR frame")
    if frame[:4] != _MAGIC:
        raise ValueError("Not a SecureQR frame")
    ver = frame[4]
    if ver != _VER:
        raise ValueError("Unsupported SecureQR frame version")

    flags = frame[5]
    session_id = frame[6:14]
    idx = int.from_bytes(frame[14:16], "big")
    total = int.from_bytes(frame[16:18], "big")
    off = 18

    meta = None
    if flags & 0x01:
        mode_code = frame[off]
        off += 1
        iat, off = _read_u32(frame, off)
        exp, off = _read_u32(frame, off)
        sid_len = frame[off]
        off += 1
        sender_id = frame[off:off + sid_len]
        off += sid_len
        rx_fp = frame[off:off + 32]
        off += 32
        pt_h = frame[off:off + 32]
        off += 32
        blob_h = frame[off:off + 32]
        off += 32
        enc_key_len, off = _read_u16(frame, off)
        enc_key = frame[off:off + enc_key_len]
        off += enc_key_len
        sig_len, off = _read_u16(frame, off)
        sig = frame[off:off + sig_len]
        off += sig_len
        fn_len, off = _read_u16(frame, off)
        fn = frame[off:off + fn_len]
        off += fn_len

        meta = {
            "mode": "text" if mode_code == 1 else "file",
            "iat": iat, "exp": exp,
            "sender_id": sender_id, "rx_fp": rx_fp,
            "enc_key": enc_key, "sig": sig,
            "pt_h": pt_h, "blob_h": blob_h,
            "fn": fn if fn_len else None,
        }

    chunk = frame[off:]
    return {
        "session_id": session_id, "idx": idx, "total": total,
        "meta": meta, "chunk": chunk,
    }

def generate_qr_auto_v3(
    comp: Dict[str, object],
    out_dir: str,
    prefix: str = "secure_qr",
    max_chunk_bytes: int = 700,
    progress_callback=None
) -> List[str]:
    """Create v3 QR image(s) with custom naming and progress callback."""
    os.makedirs(out_dir, exist_ok=True)

    blob = bytes(comp["blob"])
    session_id = os.urandom(8)

    chunks = _chunk_bytes(blob, max_chunk_bytes)
    total = len(chunks) if chunks else 1

    paths: List[str] = []
    for idx, ch in enumerate(chunks):
        meta = None
        if idx == 0:
            meta = {
                "mode": comp["mode"], "iat": comp["iat"], "exp": comp["exp"],
                "sender_id": comp["sender_id"], "rx_fp": comp["rx_fp"],
                "enc_key": comp["enc_key"], "sig": comp["sig"],
                "pt_h": comp["pt_h"], "blob_h": comp["blob_h"],
                "fn": comp.get("fn", None),
            }

        frame = _pack_part(session_id, idx, total, ch, meta=meta)
        qr_text = b64url_encode(frame)

        out_path = os.path.join(out_dir, f"{prefix}_{idx + 1:03d}_of_{total:03d}.png")
        make_qr_png(qr_text, out_path)
        paths.append(out_path)
        
        if progress_callback:
            progress_callback(idx + 1, total)

    return paths

def collect_payload_from_qr_images(image_paths: List[str]) -> Dict[str, object]:
    """Reconstruct v3 payload from multiple images."""
    if not image_paths:
        raise ValueError("No QR images provided.")

    sessions: Dict[bytes, Dict[str, object]] = {}
    unreadable_count = 0

    for path in image_paths:
        try:
            s = scan_qr_from_image_file(path)
            frame = b64url_decode(s)
            part = _unpack_part(frame)
        except Exception:
            unreadable_count += 1
            continue

        sid = bytes(part["session_id"])
        if sid not in sessions:
            sessions[sid] = {"total": int(part["total"]), "parts": {}, "meta": None}
        sessions[sid]["parts"][int(part["idx"])] = bytes(part["chunk"])
        if part.get("meta") is not None:
            sessions[sid]["meta"] = part["meta"]

    for _, s in sessions.items():
        total = int(s["total"])
        parts: Dict[int, bytes] = s["parts"]
        if len(parts) == total and s.get("meta") is not None:
            meta = s["meta"]
            blob = b"".join(parts[i] for i in range(total))
            return {
                "v": 3, "mode": meta["mode"], "sender_id": meta["sender_id"],
                "rx_fp": meta["rx_fp"], "iat": meta["iat"], "exp": meta["exp"],
                "enc_key": meta["enc_key"], "sig": meta["sig"], "blob": blob,
                "blob_h": meta["blob_h"], "pt_h": meta["pt_h"],
                "fn": meta.get("fn", None),
            }

    raise ValueError(f"No complete session found. {unreadable_count} images were unreadable.")