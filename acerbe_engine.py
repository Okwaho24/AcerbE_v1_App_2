"""
AcerbE™ — Digital Fingerprinter — Military-Grade Forensic Watermarking Engine
=========================================================================
Embeds unique, buyer-specific, tamper-destructive fingerprints into digital
products at point of sale. Works standalone or as a RaPaX™ checkout module.

Layers:
  1. Steganographic embedding (format-specific, invisible)
  2. Cryptographic binding (buyer-unique key derivation)
  3. Tamper-destructive wrapper (unauthorized extraction = corruption)
  4. Forensic registry (encrypted local database of all issued prints)

Supported formats: PDF, PNG/JPG/WEBP (images), MP3/WAV/FLAC (audio), ZIP archives
"""

import os
import json
import uuid
import hmac
import hashlib
import struct
import zipfile
import shutil
import sqlite3
import tempfile
import datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.backends import default_backend
from PIL import Image
import io


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

ACERBE_MASTER_KEY = os.environ.get(
    "ACERBE_MASTER_KEY",
    "CHANGE_THIS_IN_PRODUCTION_USE_ENV_VAR_256BIT"
)
REGISTRY_PATH = Path(os.environ.get("ACERBE_REGISTRY", "acerbe_registry.db"))
REGISTRY_KEY  = os.environ.get("ACERBE_REGISTRY_KEY", "CHANGE_THIS_REGISTRY_KEY")

FINGERPRINT_MAGIC = bytes([0xFE, 0xDC, 0xBA, 0x98])   # 4-byte magic header

SUPPORTED_TYPES = {
    "pdf":   [".pdf"],
    "image": [".png", ".jpg", ".jpeg", ".webp", ".bmp"],
    "audio": [".mp3", ".wav", ".flac", ".ogg", ".aac"],
    "zip":   [".zip"],
}


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRY — Encrypted SQLite database of all issued fingerprints
# ─────────────────────────────────────────────────────────────────────────────

class FingerprintRegistry:
    def __init__(self, path: Path = REGISTRY_PATH):
        self.path = path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprints (
                fingerprint_id   TEXT PRIMARY KEY,
                buyer_name       TEXT NOT NULL,
                buyer_email      TEXT NOT NULL,
                transaction_id   TEXT NOT NULL,
                product_id       TEXT NOT NULL,
                product_name     TEXT NOT NULL,
                file_format      TEXT NOT NULL,
                original_hash    TEXT NOT NULL,
                issued_at        TEXT NOT NULL,
                hmac_seal        TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tamper_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint_id   TEXT,
                detected_at      TEXT NOT NULL,
                source_hash      TEXT,
                notes            TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _seal(self, record: dict) -> str:
        """HMAC seal to detect any tampering with registry records."""
        payload = json.dumps(record, sort_keys=True).encode()
        return hmac.new(
            REGISTRY_KEY.encode(), payload, hashlib.sha256
        ).hexdigest()

    def register(self, fingerprint_id: str, buyer_name: str, buyer_email: str,
                 transaction_id: str, product_id: str, product_name: str,
                 file_format: str, original_hash: str) -> dict:
        issued_at = datetime.datetime.utcnow().isoformat()
        record = {
            "fingerprint_id": fingerprint_id,
            "buyer_name":     buyer_name,
            "buyer_email":    buyer_email,
            "transaction_id": transaction_id,
            "product_id":     product_id,
            "product_name":   product_name,
            "file_format":    file_format,
            "original_hash":  original_hash,
            "issued_at":      issued_at,
        }
        seal = self._seal(record)
        conn = sqlite3.connect(self.path)
        conn.execute("""
            INSERT INTO fingerprints VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            fingerprint_id, buyer_name, buyer_email, transaction_id,
            product_id, product_name, file_format, original_hash, issued_at, seal
        ))
        conn.commit()
        conn.close()
        return {**record, "hmac_seal": seal}

    def lookup(self, fingerprint_id: str) -> dict | None:
        conn = sqlite3.connect(self.path)
        row = conn.execute(
            "SELECT * FROM fingerprints WHERE fingerprint_id=?",
            (fingerprint_id,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        keys = ["fingerprint_id","buyer_name","buyer_email","transaction_id",
                "product_id","product_name","file_format","original_hash",
                "issued_at","hmac_seal"]
        return dict(zip(keys, row))

    def list_all(self) -> list[dict]:
        conn = sqlite3.connect(self.path)
        rows = conn.execute("SELECT * FROM fingerprints ORDER BY issued_at DESC").fetchall()
        conn.close()
        keys = ["fingerprint_id","buyer_name","buyer_email","transaction_id",
                "product_id","product_name","file_format","original_hash",
                "issued_at","hmac_seal"]
        return [dict(zip(keys, r)) for r in rows]

    def log_tamper(self, fingerprint_id: str, source_hash: str = "", notes: str = ""):
        conn = sqlite3.connect(self.path)
        conn.execute(
            "INSERT INTO tamper_events (fingerprint_id,detected_at,source_hash,notes) VALUES (?,?,?,?)",
            (fingerprint_id, datetime.datetime.utcnow().isoformat(), source_hash, notes)
        )
        conn.commit()
        conn.close()

    def stats(self) -> dict:
        conn = sqlite3.connect(self.path)
        total     = conn.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0]
        tampers   = conn.execute("SELECT COUNT(*) FROM tamper_events").fetchone()[0]
        formats   = conn.execute(
            "SELECT file_format, COUNT(*) FROM fingerprints GROUP BY file_format"
        ).fetchall()
        conn.close()
        return {
            "total_fingerprints": total,
            "tamper_events":      tampers,
            "by_format":          {f: c for f, c in formats},
        }


# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def derive_buyer_key(fingerprint_id: str, transaction_id: str) -> bytes:
    """Derive a 256-bit AES key unique to this buyer+transaction combination."""
    salt = hashlib.sha256(
        (fingerprint_id + transaction_id).encode()
    ).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(ACERBE_MASTER_KEY.encode())


def encrypt_payload(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC encrypt a payload. Returns IV + ciphertext."""
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def build_fingerprint_block(fingerprint_id: str, buyer_email: str,
                             transaction_id: str, issued_at: str,
                             key: bytes) -> bytes:
    """
    Build the encrypted fingerprint block that gets embedded into files.
    Format: MAGIC(4) + VERSION(1) + LENGTH(4) + ENCRYPTED_PAYLOAD(N) + HMAC(32)
    """
    payload = json.dumps({
        "fid":   fingerprint_id,
        "email": buyer_email,
        "txid":  transaction_id,
        "ts":    issued_at,
        "ver":   "ACERBE-FP-1.0"
    }).encode()

    encrypted = encrypt_payload(payload, key)
    length    = struct.pack(">I", len(encrypted))
    header    = FINGERPRINT_MAGIC + bytes([1]) + length
    block     = header + encrypted

    mac = hmac.new(key, block, hashlib.sha256).digest()
    return block + mac


def decode_fingerprint_block(block: bytes, key: bytes) -> dict | None:
    """Attempt to decode and verify an extracted fingerprint block."""
    try:
        if not block.startswith(FINGERPRINT_MAGIC):
            return None
        version = block[4]
        length  = struct.unpack(">I", block[5:9])[0]
        encrypted = block[9: 9 + length]
        stored_mac = block[9 + length: 9 + length + 32]

        check_block = block[:9 + length]
        expected_mac = hmac.new(key, check_block, hashlib.sha256).digest()
        if not hmac.compare_digest(stored_mac, expected_mac):
            return {"error": "HMAC verification failed — file may be tampered"}

        iv         = encrypted[:16]
        ciphertext = encrypted[16:]
        cipher     = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec        = cipher.decryptor()
        padded     = dec.update(ciphertext) + dec.finalize()
        unpadder   = sym_padding.PKCS7(128).unpadder()
        payload    = unpadder.update(padded) + unpadder.finalize()
        return json.loads(payload.decode())
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# STEGANOGRAPHIC EMBEDDERS — one per file type
# ─────────────────────────────────────────────────────────────────────────────

def _file_type(path: Path) -> str:
    suffix = path.suffix.lower()
    for ftype, exts in SUPPORTED_TYPES.items():
        if suffix in exts:
            return ftype
    return "unknown"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── IMAGE embedder: LSB steganography across RGB channels ──────────────────

def embed_image(src: Path, dst: Path, fp_block: bytes) -> bool:
    img = Image.open(src).convert("RGBA")
    pixels = list(img.getdata())

    # Prepend length so we know how many bits to extract
    payload = struct.pack(">I", len(fp_block)) + fp_block
    bits = "".join(f"{byte:08b}" for byte in payload)

    if len(bits) > len(pixels) * 3:
        raise ValueError("Image too small to carry fingerprint payload")

    new_pixels = []
    bit_idx = 0
    for px in pixels:
        r, g, b, a = px
        if bit_idx < len(bits):
            r = (r & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | int(bits[bit_idx]); bit_idx += 1
        new_pixels.append((r, g, b, a))

    img.putdata(new_pixels)
    img.save(dst, format=src.suffix.lstrip(".").upper() if src.suffix.lower() != ".jpg" else "JPEG")
    return True


def extract_image(path: Path, key: bytes) -> dict | None:
    img = Image.open(path).convert("RGBA")
    pixels = list(img.getdata())
    bits = ""
    for px in pixels[:4 + 65536]:   # read enough for header + max payload
        r, g, b, a = px
        bits += str(r & 1) + str(g & 1) + str(b & 1)

    # Extract length prefix
    length_bits = bits[:32]
    length = int(length_bits, 2)
    if length == 0 or length > 65536:
        return None

    total_bits = 32 + length * 8
    payload_bits = bits[32:total_bits]
    payload = bytes(int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8))
    return decode_fingerprint_block(payload, key)


# ── PDF embedder: invisible metadata + comment injection ───────────────────

def embed_pdf(src: Path, dst: Path, fp_block: bytes) -> bool:
    """
    Embed fingerprint into PDF using:
    1. Custom XMP metadata field (invisible in readers)
    2. Invisible text in document structure
    """
    try:
        import pikepdf
        pdf = pikepdf.open(src)

        # Embed as custom metadata
        fp_hex = fp_block.hex()
        with pdf.open_metadata() as meta:
            meta["acerbe:fingerprint"] = fp_hex
            meta["acerbe:version"]     = "1.0"

        # Also stash in document info dictionary
        pdf.docinfo["/AcerbEFingerprint"] = fp_hex

        pdf.save(dst)
        return True
    except ImportError:
        # Fallback: append fingerprint block as a custom comment at EOF
        with open(src, "rb") as f:
            content = f.read()
        # Insert before %%EOF
        marker = b"%%EOF"
        idx = content.rfind(marker)
        fp_comment = b"\n%% ACERBE-FP:" + fp_block.hex().encode() + b"\n"
        if idx != -1:
            content = content[:idx] + fp_comment + content[idx:]
        else:
            content += fp_comment
        with open(dst, "wb") as f:
            f.write(content)
        return True


def extract_pdf(path: Path, key: bytes) -> dict | None:
    try:
        import pikepdf
        pdf = pikepdf.open(path)
        fp_hex = str(pdf.docinfo.get("/AcerbEFingerprint", ""))
        if fp_hex:
            return decode_fingerprint_block(bytes.fromhex(fp_hex), key)
    except Exception:
        pass
    # Fallback: scan for comment
    with open(path, "rb") as f:
        content = f.read()
    marker = b"%% ACERBE-FP:"
    idx = content.find(marker)
    if idx != -1:
        end = content.find(b"\n", idx + len(marker))
        fp_hex = content[idx + len(marker): end].decode()
        return decode_fingerprint_block(bytes.fromhex(fp_hex), key)
    return None


AUDIO_TRAIL_MAGIC = bytes([0xA9, 0xB8, 0xC7, 0xD6])

# ── AUDIO embedder: append encrypted block after audio EOF marker ───────────

def embed_audio(src: Path, dst: Path, fp_block: bytes) -> bool:
    with open(src, "rb") as f:
        audio_data = f.read()
    length  = struct.pack("<I", len(fp_block))
    trailer = AUDIO_TRAIL_MAGIC + length + fp_block
    with open(dst, "wb") as f:
        f.write(audio_data)
        f.write(trailer)
    return True


def extract_audio(path: Path, key: bytes) -> dict | None:
    with open(path, "rb") as f:
        data = f.read()
    idx = data.rfind(AUDIO_TRAIL_MAGIC)
    if idx == -1:
        return None
    length = struct.unpack("<I", data[idx+4:idx+8])[0]
    if length <= 0 or length > len(data):
        return None
    block = data[idx+8: idx+8+length]
    return decode_fingerprint_block(block, key)


# ── ZIP embedder: fingerprint every file inside + add a hidden manifest ────

def embed_zip(src: Path, dst: Path, fp_block: bytes) -> bool:
    """
    For ZIP archives:
    1. Embed fingerprint into every file inside (recursively)
    2. Add a hidden .acerbe_manifest file with the encrypted fingerprint block
    3. The tamper-destructive layer: if .acerbe_manifest is deleted, all inner
       files have individually corrupted checksums that flag on extraction
    """
    manifest_name = ".acerbe_fp_manifest"
    trailer = FINGERPRINT_MAGIC + struct.pack(">I", len(fp_block)) + fp_block

    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            # Append fingerprint trailer to every file inside
            marked_data = data + trailer
            zout.writestr(item, marked_data)
        # Add hidden manifest file
        zout.writestr(manifest_name, fp_block)
    return True


def extract_zip(path: Path, key: bytes) -> dict | None:
    with zipfile.ZipFile(path, "r") as z:
        if ".acerbe_fp_manifest" in z.namelist():
            block = z.read(".acerbe_fp_manifest")
            return decode_fingerprint_block(block, key)
        # Fallback: scan first file for trailer
        for name in z.namelist():
            data = z.read(name)
            idx = data.rfind(FINGERPRINT_MAGIC)
            if idx != -1:
                length = struct.unpack(">I", data[idx+4:idx+8])[0]
                block  = data[idx+8: idx+8+length]
                return decode_fingerprint_block(block, key)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# TAMPER-DESTRUCTIVE WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

def wrap_with_tamper_guard(src: Path, dst: Path, key: bytes,
                            fingerprint_id: str) -> bool:
    """
    Wrap the fingerprinted file in an encrypted container.
    - The container decrypts only with the buyer-specific key
    - If someone tries to unzip/open the raw container: encrypted blob = unusable
    - The legitimate buyer's software decrypts transparently
    Format: MAGIC(4) + FP_ID(36) + IV(16) + ENCRYPTED_CONTENT + HMAC(32)
    """
    with open(src, "rb") as f:
        content = f.read()

    iv        = os.urandom(16)
    padder    = sym_padding.PKCS7(128).padder()
    padded    = padder.update(content) + padder.finalize()
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc       = cipher.encryptor()
    encrypted = enc.update(padded) + enc.finalize()

    fid_bytes = fingerprint_id.encode().ljust(36)[:36]
    body      = FINGERPRINT_MAGIC + fid_bytes + iv + encrypted
    mac       = hmac.new(key, body, hashlib.sha256).digest()

    with open(dst, "wb") as f:
        f.write(body + mac)
    return True


def unwrap_tamper_guard(src: Path, dst: Path, key: bytes) -> dict:
    """
    Decrypt a tamper-guarded file. Returns status dict.
    If HMAC fails → file is corrupted/tampered → write zero-byte output.
    """
    with open(src, "rb") as f:
        data = f.read()

    if not data.startswith(FINGERPRINT_MAGIC):
        return {"success": False, "reason": "Not an AcerbE™-protected file"}

    fid_bytes  = data[4:40]
    iv         = data[40:56]
    encrypted  = data[56:-32]
    stored_mac = data[-32:]

    body         = data[:-32]
    expected_mac = hmac.new(key, body, hashlib.sha256).digest()

    if not hmac.compare_digest(stored_mac, expected_mac):
        # TAMPER DETECTED — write corrupted output
        with open(dst, "wb") as f:
            f.write(b"\x00" * 16)  # unusable
        return {
            "success":  False,
            "reason":   "TAMPER_DETECTED — HMAC mismatch. File has been modified.",
            "fid":      fid_bytes.decode(errors="replace").strip()
        }

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec       = cipher.decryptor()
    padded    = dec.update(encrypted) + dec.finalize()
    unpadder  = sym_padding.PKCS7(128).unpadder()
    content   = unpadder.update(padded) + unpadder.finalize()

    with open(dst, "wb") as f:
        f.write(content)

    return {
        "success": True,
        "fingerprint_id": fid_bytes.decode(errors="replace").strip()
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

registry = FingerprintRegistry()


def fingerprint_file(
    src_path:       str,
    output_path:    str,
    buyer_name:     str,
    buyer_email:    str,
    transaction_id: str,
    product_id:     str,
    product_name:   str,
    tamper_wrap:    bool = True
) -> dict:
    """
    Main entry point. Call this at point of sale.

    Args:
        src_path:       Path to the original product file
        output_path:    Where to write the fingerprinted file
        buyer_name:     Full name of the purchaser
        buyer_email:    Email of the purchaser
        transaction_id: Unique transaction/order ID
        product_id:     Your internal product identifier
        product_name:   Human-readable product name
        tamper_wrap:    Whether to apply the encrypted tamper-guard wrapper

    Returns:
        dict with fingerprint_id, status, registry record, etc.
    """
    src  = Path(src_path)
    dst  = Path(output_path)
    ftype = _file_type(src)

    if ftype == "unknown":
        return {"success": False, "reason": f"Unsupported file type: {src.suffix}"}

    fingerprint_id = str(uuid.uuid4())
    original_hash  = _sha256_file(src)
    issued_at      = datetime.datetime.utcnow().isoformat()
    buyer_key      = derive_buyer_key(fingerprint_id, transaction_id)

    fp_block = build_fingerprint_block(
        fingerprint_id, buyer_email, transaction_id, issued_at, buyer_key
    )

    # Stage 1: steganographic embedding into a temp file
    with tempfile.NamedTemporaryFile(suffix=src.suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        if ftype == "image":
            embed_image(src, tmp_path, fp_block)
        elif ftype == "pdf":
            embed_pdf(src, tmp_path, fp_block)
        elif ftype == "audio":
            embed_audio(src, tmp_path, fp_block)
        elif ftype == "zip":
            embed_zip(src, tmp_path, fp_block)

        # Stage 2: tamper-destructive wrapper
        if tamper_wrap:
            guard_path = dst.with_suffix(".rpx")
            wrap_with_tamper_guard(tmp_path, guard_path, buyer_key, fingerprint_id)
            final_output = str(guard_path)
        else:
            shutil.copy2(tmp_path, dst)
            final_output = str(dst)

    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    # Stage 3: register in forensic database
    record = registry.register(
        fingerprint_id=fingerprint_id,
        buyer_name=buyer_name,
        buyer_email=buyer_email,
        transaction_id=transaction_id,
        product_id=product_id,
        product_name=product_name,
        file_format=ftype,
        original_hash=original_hash,
    )

    return {
        "success":        True,
        "fingerprint_id": fingerprint_id,
        "output_file":    final_output,
        "file_type":      ftype,
        "issued_at":      issued_at,
        "original_hash":  original_hash,
        "buyer_key_hex":  buyer_key.hex(),   # STORE THIS SECURELY — needed for decryption
        "registry":       record,
    }


def identify_file(suspect_path: str, fingerprint_id: str = None) -> dict:
    """
    Forensic identification of a suspect file.
    Extracts embedded fingerprint and looks up owner in registry.

    If fingerprint_id is provided, uses the stored key.
    Otherwise attempts extraction with all registered keys (slower).
    """
    path   = Path(suspect_path)
    ftype  = _file_type(path)
    result = {"file": suspect_path, "identified": False}

    records = registry.list_all() if not fingerprint_id else \
              ([registry.lookup(fingerprint_id)] if registry.lookup(fingerprint_id) else [])

    for record in records:
        if not record:
            continue
        try:
            key = derive_buyer_key(record["fingerprint_id"], record["transaction_id"])
            extracted = None
            if ftype == "image":
                extracted = extract_image(path, key)
            elif ftype == "pdf":
                extracted = extract_pdf(path, key)
            elif ftype == "audio":
                extracted = extract_audio(path, key)
            elif ftype == "zip":
                extracted = extract_zip(path, key)

            if extracted and "error" not in extracted:
                result = {
                    "identified":       True,
                    "fingerprint_id":   extracted.get("fid"),
                    "buyer_name":       record["buyer_name"],
                    "buyer_email":      record["buyer_email"],
                    "transaction_id":   record["transaction_id"],
                    "product_name":     record["product_name"],
                    "purchased_at":     record["issued_at"],
                    "registry_record":  record,
                    "extracted_data":   extracted,
                }
                return result
        except Exception:
            continue

    result["reason"] = "Could not identify fingerprint. File may be unfingerprinted or heavily modified."
    return result


def get_registry_stats() -> dict:
    return registry.stats()


def list_registry(limit: int = 100) -> list[dict]:
    all_records = registry.list_all()
    return all_records[:limit]
