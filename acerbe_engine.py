"""
AcerbE™ — Forensic Mark Engine v3.1.0-reconciled
=================================================
Archer Chain Analytics | ISC: 102237785 | mahihkan.com

Multi-layer forensic fingerprinting for 26 file formats.
Operates standalone or as the ACA Sovereign Delivery Pipeline gate.

Layer Architecture:
  1. Format-specific steganographic embedding (in-band, non-wrapper)
  2. Cryptographic binding (HMAC-SHA256, buyer-unique key derivation)
  3. PDF Glyph Positional Modulation (sub-point Tc operator injection)
  4. HMAC-signed sidecar manifest + SQLite forensic registry

Environment Variables:
  ACERBE_SECRET_KEY   — master signing key, 32+ chars (REQUIRED)
  ACERBE_REGISTRY     — path to SQLite registry (default: acerbe_registry.db)
  ACERBE_REGISTRY_KEY — key used to HMAC-seal registry rows

Supported formats (26):
  Images  : .png .jpg .jpeg .webp .bmp .gif
  PDF     : .pdf  (XMP metadata + Glyph Positional Modulation)
  Office  : .docx .xlsx .pptx  (custom XML part injection)
  EPUB    : .epub
  Audio   : .mp3 .wav .flac .ogg .aac  (trailer append)
  Video   : .mp4  (free-atom injection)
  Code    : .py .js .ts .sh .rb  (comment injection)
  SVG     : .svg  (comment injection)
  Text    : .md .txt  (zero-width Unicode)
  Archive : .zip  (manifest + inner-file marks)

(c) 2026 Neil Scott Archer / Archer Chain Analytics | ISC: 102237785
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import io
import json
import os
import re
import sqlite3
import struct
import tempfile
import shutil
import uuid
import zipfile
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

_RAW_KEY = os.environ.get("ACERBE_SECRET_KEY", "")
if not _RAW_KEY or len(_RAW_KEY) < 32:
    import warnings
    warnings.warn(
        "ACERBE_SECRET_KEY not set or under 32 chars. "
        "Set it before production use.",
        stacklevel=2,
    )

ACERBE_SECRET_KEY: str = _RAW_KEY or "CHANGE_THIS_IN_PRODUCTION_USE_ENV_VAR_256BIT"
REGISTRY_PATH = Path(os.environ.get("ACERBE_REGISTRY", "acerbe_registry.db"))
REGISTRY_KEY  = os.environ.get("ACERBE_REGISTRY_KEY", "CHANGE_THIS_REGISTRY_KEY")

FINGERPRINT_MAGIC  = bytes([0xFE, 0xDC, 0xBA, 0x98])
AUDIO_TRAIL_MAGIC  = bytes([0xA9, 0xB8, 0xC7, 0xD6])

ENGINE_VERSION = "v3.1.0-reconciled"

SUPPORTED_TYPES: dict[str, list[str]] = {
    "image":   [".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"],
    "pdf":     [".pdf"],
    "office":  [".docx", ".xlsx", ".pptx"],
    "epub":    [".epub"],
    "audio":   [".mp3", ".wav", ".flac", ".ogg", ".aac"],
    "video":   [".mp4"],
    "code":    [".py", ".js", ".ts", ".sh", ".rb"],
    "svg":     [".svg"],
    "text":    [".md", ".txt"],
    "archive": [".zip"],
}

# Zero-width Unicode chars used for binary encoding in text/markdown
_ZW_ZERO = "​"   # ZERO WIDTH SPACE  → bit 0
_ZW_ONE  = "‌"   # ZERO WIDTH NON-JOINER → bit 1


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRY
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
        payload = json.dumps(record, sort_keys=True).encode()
        return hmac.new(REGISTRY_KEY.encode(), payload, hashlib.sha256).hexdigest()

    def register(
        self,
        fingerprint_id: str,
        buyer_name: str,
        buyer_email: str,
        transaction_id: str,
        product_id: str,
        product_name: str,
        file_format: str,
        original_hash: str,
    ) -> dict:
        issued_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
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
        conn.execute(
            "INSERT OR REPLACE INTO fingerprints VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                fingerprint_id, buyer_name, buyer_email, transaction_id,
                product_id, product_name, file_format, original_hash, issued_at, seal,
            ),
        )
        conn.commit()
        conn.close()
        return {**record, "hmac_seal": seal}

    def lookup(self, fingerprint_id: str) -> dict | None:
        conn = sqlite3.connect(self.path)
        row = conn.execute(
            "SELECT * FROM fingerprints WHERE fingerprint_id=?", (fingerprint_id,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        keys = [
            "fingerprint_id", "buyer_name", "buyer_email", "transaction_id",
            "product_id", "product_name", "file_format", "original_hash",
            "issued_at", "hmac_seal",
        ]
        return dict(zip(keys, row))

    def list_all(self) -> list[dict]:
        conn = sqlite3.connect(self.path)
        rows = conn.execute(
            "SELECT * FROM fingerprints ORDER BY issued_at DESC"
        ).fetchall()
        conn.close()
        keys = [
            "fingerprint_id", "buyer_name", "buyer_email", "transaction_id",
            "product_id", "product_name", "file_format", "original_hash",
            "issued_at", "hmac_seal",
        ]
        return [dict(zip(keys, r)) for r in rows]

    def log_tamper(self, fingerprint_id: str, source_hash: str = "", notes: str = ""):
        conn = sqlite3.connect(self.path)
        conn.execute(
            "INSERT INTO tamper_events (fingerprint_id,detected_at,source_hash,notes) VALUES (?,?,?,?)",
            (fingerprint_id, datetime.datetime.utcnow().isoformat(), source_hash, notes),
        )
        conn.commit()
        conn.close()

    def stats(self) -> dict:
        conn = sqlite3.connect(self.path)
        total   = conn.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0]
        tampers = conn.execute("SELECT COUNT(*) FROM tamper_events").fetchone()[0]
        formats = conn.execute(
            "SELECT file_format, COUNT(*) FROM fingerprints GROUP BY file_format"
        ).fetchall()
        conn.close()
        return {
            "total_fingerprints": total,
            "tamper_events":      tampers,
            "by_format":          {f: c for f, c in formats},
            "engine_version":     ENGINE_VERSION,
        }


# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_type(path: Path) -> str:
    suffix = path.suffix.lower()
    for ftype, exts in SUPPORTED_TYPES.items():
        if suffix in exts:
            return ftype
    return "unknown"


def derive_buyer_key(fingerprint_id: str, transaction_id: str) -> bytes:
    """256-bit AES key unique to this buyer+transaction."""
    salt = hashlib.sha256((fingerprint_id + transaction_id).encode()).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf.derive(ACERBE_SECRET_KEY.encode())


def _encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC. Returns IV + ciphertext."""
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def _decrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC decrypt."""
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def build_fingerprint_block(
    fingerprint_id: str,
    buyer_email: str,
    transaction_id: str,
    issued_at: str,
    key: bytes,
) -> bytes:
    """
    MAGIC(4) + VERSION(1) + LENGTH(4) + AES-256-CBC(payload) + HMAC-SHA256(32)
    """
    payload = json.dumps({
        "fid":   fingerprint_id,
        "email": buyer_email,
        "txid":  transaction_id,
        "ts":    issued_at,
        "ver":   ENGINE_VERSION,
    }).encode()

    encrypted = _encrypt(payload, key)
    length    = struct.pack(">I", len(encrypted))
    header    = FINGERPRINT_MAGIC + bytes([1]) + length
    block     = header + encrypted
    mac       = hmac.new(key, block, hashlib.sha256).digest()
    return block + mac


def decode_fingerprint_block(block: bytes, key: bytes) -> dict | None:
    """Verify HMAC then decrypt. Returns payload dict or error dict."""
    try:
        if not block.startswith(FINGERPRINT_MAGIC):
            return None
        length    = struct.unpack(">I", block[5:9])[0]
        encrypted = block[9: 9 + length]
        stored_mac = block[9 + length: 9 + length + 32]

        check_block  = block[:9 + length]
        expected_mac = hmac.new(key, check_block, hashlib.sha256).digest()
        if not hmac.compare_digest(stored_mac, expected_mac):
            return {"error": "HMAC verification failed — file may be tampered"}

        return json.loads(_decrypt(encrypted, key).decode())
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# FORMAT EMBEDDERS
# ─────────────────────────────────────────────────────────────────────────────

# ── IMAGE (PNG/JPG/WEBP/BMP/GIF) — LSB steganography ─────────────────────

def embed_image(src: Path, dst: Path, fp_block: bytes) -> bool:
    img = Image.open(src).convert("RGBA")
    pixels = list(img.getdata())  # type: ignore[arg-type]  # Pillow 14 → get_flattened_data; kept for compat
    payload = struct.pack(">I", len(fp_block)) + fp_block
    bits = "".join(f"{b:08b}" for b in payload)
    if len(bits) > len(pixels) * 3:
        raise ValueError("Image too small for fingerprint payload")
    new_pixels, bit_idx = [], 0
    for px in pixels:
        r, g, b, a = px
        if bit_idx < len(bits): r = (r & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits): g = (g & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits): b = (b & ~1) | int(bits[bit_idx]); bit_idx += 1
        new_pixels.append((r, g, b, a))
    img.putdata(new_pixels)
    fmt = "JPEG" if src.suffix.lower() in (".jpg", ".jpeg") else src.suffix.lstrip(".").upper()
    img.save(dst, format=fmt)
    return True


def extract_image(path: Path, key: bytes) -> dict | None:
    img = Image.open(path).convert("RGBA")
    pixels = list(img.getdata())  # type: ignore[arg-type]
    bits = ""
    for px in pixels[:4 + 65536]:
        r, g, b, a = px
        bits += str(r & 1) + str(g & 1) + str(b & 1)
    length = int(bits[:32], 2)
    if length == 0 or length > 65536:
        return None
    payload_bits = bits[32: 32 + length * 8]
    payload = bytes(int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8))
    return decode_fingerprint_block(payload, key)


# ── PDF — XMP metadata + Glyph Positional Modulation (Tc injection) ────────

def _derive_gpm_offsets(master_key: str, tx_id: str, count: int) -> list[float]:
    """Deterministic sub-point horizontal adjustments (-0.03 .. +0.03 pt)."""
    seed = hmac.new(
        master_key.encode("utf-8"),
        tx_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    offsets = []
    for i in range(count):
        h = hmac.new(seed, i.to_bytes(4, "big"), hashlib.sha256).digest()
        offsets.append(round((h[0] / 255.0 * 0.06) - 0.03, 4))
    return offsets


def embed_pdf(src: Path, dst: Path, fp_block: bytes, tx_id: str = "") -> bool:
    """
    Layer 1: XMP metadata + docinfo fingerprint hex.
    Layer 2 (GPM): sub-point Tc operator injection into content streams.
    """
    try:
        import pikepdf

        pdf    = pikepdf.open(src)
        fp_hex = fp_block.hex()

        # Layer 1 — XMP + docinfo
        with pdf.open_metadata() as meta:
            meta["acerbe:fingerprint"] = fp_hex
            meta["acerbe:version"]     = ENGINE_VERSION
        pdf.docinfo["/AcerbEFingerprint"] = fp_hex

        # Layer 2 — GPM Tc injection
        offsets = _derive_gpm_offsets(ACERBE_SECRET_KEY, tx_id or fp_hex[:32], len(pdf.pages))
        for idx, page in enumerate(pdf.pages):
            try:
                raw = page.get_contents()
                if raw is None:
                    continue
                content_bytes = raw.read_bytes()
                tc_cmd = f"\n{offsets[idx]:.4f} Tc\n".encode("utf-8")
                if b"BT" in content_bytes:
                    modified = re.sub(b"(BT)", b"BT" + tc_cmd, content_bytes, count=1)
                else:
                    modified = tc_cmd + content_bytes
                page.set_contents(pdf.make_stream(modified))
            except Exception:
                pass  # skip pages whose streams can't be modified

        pdf.save(dst)
        pdf.close()
        return True

    except ImportError:
        # pikepdf unavailable: fallback comment injection
        with open(src, "rb") as f:
            content = f.read()
        fp_comment = b"\n%% ACERBE-FP:" + fp_block.hex().encode() + b"\n"
        marker = b"%%EOF"
        idx = content.rfind(marker)
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
        pdf    = pikepdf.open(path)
        fp_hex = str(pdf.docinfo.get("/AcerbEFingerprint", ""))
        if fp_hex:
            return decode_fingerprint_block(bytes.fromhex(fp_hex), key)
    except Exception:
        pass
    with open(path, "rb") as f:
        content = f.read()
    marker = b"%% ACERBE-FP:"
    idx = content.find(marker)
    if idx != -1:
        end    = content.find(b"\n", idx + len(marker))
        fp_hex = content[idx + len(marker): end].decode()
        return decode_fingerprint_block(bytes.fromhex(fp_hex), key)
    return None


# ── OFFICE (DOCX / XLSX / PPTX) — custom XML part injection ────────────────

_OFFICE_PART_NAME = "acerbe/fingerprint.xml"

def embed_office(src: Path, dst: Path, fp_block: bytes) -> bool:
    """Office files are ZIP-based. Inject a custom XML part."""
    fp_hex = fp_block.hex()
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<AcerbEFingerprint xmlns="urn:archer-chain-analytics:acerbe:1.0">\n'
        f'  <Version>{ENGINE_VERSION}</Version>\n'
        f'  <FingerprintHex>{fp_hex}</FingerprintHex>\n'
        f'  <Issuer>Archer Chain Analytics | ISC 102237785</Issuer>\n'
        '</AcerbEFingerprint>\n'
    ).encode("utf-8")

    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename))
        zout.writestr(_OFFICE_PART_NAME, xml)
    return True


def extract_office(path: Path, key: bytes) -> dict | None:
    try:
        with zipfile.ZipFile(path, "r") as z:
            if _OFFICE_PART_NAME in z.namelist():
                xml   = z.read(_OFFICE_PART_NAME).decode("utf-8")
                match = re.search(r"<FingerprintHex>([0-9a-f]+)</FingerprintHex>", xml)
                if match:
                    return decode_fingerprint_block(bytes.fromhex(match.group(1)), key)
    except Exception:
        pass
    return None


# ── EPUB — custom XML part injection (same ZIP structure as Office) ─────────

def embed_epub(src: Path, dst: Path, fp_block: bytes) -> bool:
    return embed_office(src, dst, fp_block)   # identical mechanism

def extract_epub(path: Path, key: bytes) -> dict | None:
    return extract_office(path, key)


# ── AUDIO (MP3/WAV/FLAC/OGG/AAC) — trailer append ──────────────────────────

def embed_audio(src: Path, dst: Path, fp_block: bytes) -> bool:
    with open(src, "rb") as f:
        audio = f.read()
    trailer = AUDIO_TRAIL_MAGIC + struct.pack("<I", len(fp_block)) + fp_block
    with open(dst, "wb") as f:
        f.write(audio)
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
    return decode_fingerprint_block(data[idx+8: idx+8+length], key)


# ── VIDEO (MP4) — free-atom injection ──────────────────────────────────────

def embed_mp4(src: Path, dst: Path, fp_block: bytes) -> bool:
    """
    Injects fingerprint as a 'free' atom at the start of the MP4.
    'free' atoms are explicitly ignored by compliant players.
    """
    fp_hex     = fp_block.hex().encode("utf-8")
    atom_data  = b"ACERBE-FP:" + fp_hex
    atom_size  = struct.pack(">I", len(atom_data) + 8)
    atom_type  = b"free"
    free_atom  = atom_size + atom_type + atom_data

    with open(src, "rb") as f:
        original = f.read()
    with open(dst, "wb") as f:
        f.write(free_atom)
        f.write(original)
    return True


def extract_mp4(path: Path, key: bytes) -> dict | None:
    with open(path, "rb") as f:
        data = f.read()
    marker = b"freeACERBE-FP:"
    idx = data.find(marker)
    if idx == -1:
        return None
    end    = data.find(b"\x00", idx + len(marker))
    fp_hex = data[idx + len(marker): end if end != -1 else idx + len(marker) + 512].decode("ascii", errors="ignore").strip()
    try:
        return decode_fingerprint_block(bytes.fromhex(fp_hex), key)
    except Exception:
        return None


# ── CODE (.py/.js/.ts/.sh/.rb) — comment injection ─────────────────────────

def embed_code(src: Path, dst: Path, fp_block: bytes) -> bool:
    suffix  = src.suffix.lower()
    fp_b64  = base64.b64encode(fp_block).decode("ascii")
    if suffix in (".py", ".sh", ".rb"):
        comment = f"# ACERBE-FP:{fp_b64}\n"
    else:
        comment = f"// ACERBE-FP:{fp_b64}\n"

    with open(src, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    with open(dst, "w", encoding="utf-8") as f:
        f.write(comment + content)
    return True


def extract_code(path: Path, key: bytes) -> dict | None:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    match = re.search(r"(?:#|//) ACERBE-FP:([A-Za-z0-9+/=]+)", content)
    if not match:
        return None
    try:
        block = base64.b64decode(match.group(1))
        return decode_fingerprint_block(block, key)
    except Exception:
        return None


# ── SVG — XML comment injection ────────────────────────────────────────────

def embed_svg(src: Path, dst: Path, fp_block: bytes) -> bool:
    fp_b64  = base64.b64encode(fp_block).decode("ascii")
    comment = f"<!-- ACERBE-FP:{fp_b64} -->"
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    with open(dst, "w", encoding="utf-8") as f:
        f.write(comment + "\n" + content)
    return True


def extract_svg(path: Path, key: bytes) -> dict | None:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    match = re.search(r"<!-- ACERBE-FP:([A-Za-z0-9+/=]+) -->", content)
    if not match:
        return None
    try:
        return decode_fingerprint_block(base64.b64decode(match.group(1)), key)
    except Exception:
        return None


# ── TEXT / MARKDOWN — zero-width Unicode encoding ──────────────────────────

def embed_text(src: Path, dst: Path, fp_block: bytes) -> bool:
    bits   = "".join(f"{b:08b}" for b in fp_block)
    zw_str = "".join(_ZW_ONE if c == "1" else _ZW_ZERO for c in bits)
    # Length prefix: 32 zero-width chars encoding a 32-bit int
    len_bits = f"{len(fp_block):032b}"
    len_zw   = "".join(_ZW_ONE if c == "1" else _ZW_ZERO for c in len_bits)

    with open(src, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    with open(dst, "w", encoding="utf-8") as f:
        f.write(len_zw + zw_str + content)
    return True


def extract_text(path: Path, key: bytes) -> dict | None:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    zw_chars = {_ZW_ZERO, _ZW_ONE}
    bits = "".join("1" if c == _ZW_ONE else "0" for c in content if c in zw_chars)
    if len(bits) < 32:
        return None
    length = int(bits[:32], 2)
    if length <= 0 or length > 65536 or len(bits) < 32 + length * 8:
        return None
    payload_bits = bits[32: 32 + length * 8]
    payload = bytes(int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8))
    return decode_fingerprint_block(payload, key)


# ── ZIP / ARCHIVE — manifest + inner-file marks ────────────────────────────

def embed_zip(src: Path, dst: Path, fp_block: bytes) -> bool:
    manifest_name = ".acerbe_fp_manifest"
    trailer = FINGERPRINT_MAGIC + struct.pack(">I", len(fp_block)) + fp_block
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename) + trailer)
        zout.writestr(manifest_name, fp_block)
    return True


def extract_zip(path: Path, key: bytes) -> dict | None:
    with zipfile.ZipFile(path, "r") as z:
        if ".acerbe_fp_manifest" in z.namelist():
            return decode_fingerprint_block(z.read(".acerbe_fp_manifest"), key)
        for name in z.namelist():
            data = z.read(name)
            idx  = data.rfind(FINGERPRINT_MAGIC)
            if idx != -1:
                length = struct.unpack(">I", data[idx+4:idx+8])[0]
                block  = data[idx+8: idx+8+length]
                return decode_fingerprint_block(block, key)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH TABLES
# ─────────────────────────────────────────────────────────────────────────────

_EMBEDDERS = {
    "image":   embed_image,
    "pdf":     embed_pdf,
    "office":  embed_office,
    "epub":    embed_epub,
    "audio":   embed_audio,
    "video":   embed_mp4,
    "code":    embed_code,
    "svg":     embed_svg,
    "text":    embed_text,
    "archive": embed_zip,
}

_EXTRACTORS = {
    "image":   extract_image,
    "pdf":     extract_pdf,
    "office":  extract_office,
    "epub":    extract_epub,
    "audio":   extract_audio,
    "video":   extract_mp4,
    "code":    extract_code,
    "svg":     extract_svg,
    "text":    extract_text,
    "archive": extract_zip,
}


# ─────────────────────────────────────────────────────────────────────────────
# MANIFEST WRITER
# ─────────────────────────────────────────────────────────────────────────────

def _write_manifest(output_path: Path, payload: dict) -> Path:
    manifest_payload = {
        "payload":        payload,
        "engine_version": ENGINE_VERSION,
        "layer_types":    ["FORMAT_EMBED", "PDF_GPM"],
    }
    manifest_bytes = json.dumps(manifest_payload, sort_keys=True).encode("utf-8")
    signature = hmac.new(
        ACERBE_SECRET_KEY.encode("utf-8"),
        manifest_bytes,
        hashlib.sha256,
    ).hexdigest()
    manifest_data = {"manifest": manifest_payload, "hmac_sha256": signature}
    mpath = output_path.with_name(output_path.name + ".manifest.json")
    mpath.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    return mpath


def verify_manifest(manifest_path: str) -> dict:
    """Verify a sidecar manifest's HMAC signature."""
    try:
        data = json.loads(Path(manifest_path).read_text("utf-8"))
        manifest_payload = data.get("manifest", {})
        stored_sig       = data.get("hmac_sha256", "")
        manifest_bytes   = json.dumps(manifest_payload, sort_keys=True).encode("utf-8")
        expected_sig     = hmac.new(
            ACERBE_SECRET_KEY.encode("utf-8"), manifest_bytes, hashlib.sha256
        ).hexdigest()
        ok = hmac.compare_digest(stored_sig, expected_sig)
        return {"valid": ok, "manifest": manifest_payload}
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
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
) -> dict:
    """
    Embed a buyer-specific forensic mark into any supported file.
    Returns fingerprint_id, output file path, manifest path, and registry record.
    """
    src   = Path(src_path)
    dst   = Path(output_path)
    ftype = _file_type(src)

    if ftype == "unknown":
        return {"success": False, "reason": f"Unsupported file type: {src.suffix}"}

    fingerprint_id = str(uuid.uuid4())
    original_hash  = _sha256_file(src)
    issued_at      = datetime.datetime.now(datetime.timezone.utc).isoformat()
    buyer_key      = derive_buyer_key(fingerprint_id, transaction_id)

    fp_block = build_fingerprint_block(
        fingerprint_id, buyer_email, transaction_id, issued_at, buyer_key
    )

    with tempfile.NamedTemporaryFile(suffix=src.suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        embedder = _EMBEDDERS[ftype]
        # PDF gets tx_id for GPM offset derivation
        if ftype == "pdf":
            embedder(src, tmp_path, fp_block, tx_id=transaction_id)
        else:
            embedder(src, tmp_path, fp_block)
        shutil.copy2(tmp_path, dst)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    payload = {
        "fid":   fingerprint_id,
        "email": buyer_email,
        "txid":  transaction_id,
        "ts":    issued_at,
    }
    manifest_path = _write_manifest(dst, payload)

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
        "output_file":    str(dst),
        "manifest_file":  str(manifest_path),
        "file_type":      ftype,
        "issued_at":      issued_at,
        "original_hash":  original_hash,
        "registry":       record,
        "engine_version": ENGINE_VERSION,
    }


def identify_file(suspect_path: str, fingerprint_id: str | None = None) -> dict:
    """
    Forensic scan of a suspect file. Returns owner and transaction if matched.
    """
    path   = Path(suspect_path)
    ftype  = _file_type(path)
    result = {"file": suspect_path, "identified": False}

    records = (
        [registry.lookup(fingerprint_id)]
        if fingerprint_id
        else registry.list_all()
    )

    extractor = _EXTRACTORS.get(ftype)
    if not extractor:
        result["reason"] = f"Unsupported file type: {path.suffix}"
        return result

    for record in records:
        if not record:
            continue
        try:
            key       = derive_buyer_key(record["fingerprint_id"], record["transaction_id"])
            extracted = extractor(path, key)
            if extracted and "error" not in extracted:
                return {
                    "identified":      True,
                    "fingerprint_id":  extracted.get("fid"),
                    "buyer_name":      record["buyer_name"],
                    "buyer_email":     record["buyer_email"],
                    "transaction_id":  record["transaction_id"],
                    "product_name":    record["product_name"],
                    "purchased_at":    record["issued_at"],
                    "registry_record": record,
                    "extracted_data":  extracted,
                    "engine_version":  ENGINE_VERSION,
                }
        except Exception:
            continue

    result["reason"] = (
        "No matching fingerprint found. "
        "File may be unfingerprinted or marks may have been degraded."
    )
    return result


def get_registry_stats() -> dict:
    return registry.stats()


def list_registry(limit: int = 100) -> list[dict]:
    return registry.list_all()[:limit]
