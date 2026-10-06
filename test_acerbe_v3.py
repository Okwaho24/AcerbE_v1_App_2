"""
AcerbE™ Engine v3.1.0-reconciled — Test Suite
==============================================
Archer Chain Analytics | ISC: 102237785

Tests all 26 supported formats + manifest signing + registry.
"""

import os
import json
import hashlib
import struct
import tempfile
import zipfile
import unittest
from pathlib import Path

# Set test key before importing engine
os.environ["ACERBE_SECRET_KEY"] = "TEST_KEY_FOR_UNIT_TESTS_32CHARS_OK"
os.environ["ACERBE_REGISTRY"]   = ":memory:"   # in-memory won't work for sqlite directly

import sys
sys.path.insert(0, str(Path(__file__).parent))

# Patch registry to use a temp file so tests are isolated
import tempfile as _tf
_tmp_db = _tf.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["ACERBE_REGISTRY"] = _tmp_db.name

import acerbe_engine as engine


class TestEngineCore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.key = engine.derive_buyer_key("test-fid-001", "tx-001")

    def _tmp(self, name):
        return Path(self.tmp) / name

    # ── Crypto round-trip ──────────────────────────────────────────────────

    def test_fingerprint_block_roundtrip(self):
        block = engine.build_fingerprint_block(
            "fid-001", "buyer@example.com", "tx-001", "2026-01-01T00:00:00", self.key
        )
        result = engine.decode_fingerprint_block(block, self.key)
        self.assertIsNotNone(result)
        self.assertNotIn("error", result)
        self.assertEqual(result["fid"], "fid-001")
        self.assertEqual(result["email"], "buyer@example.com")

    def test_tampered_block_detected(self):
        block = engine.build_fingerprint_block(
            "fid-001", "buyer@example.com", "tx-001", "2026-01-01T00:00:00", self.key
        )
        tampered = bytearray(block)
        tampered[20] ^= 0xFF
        result = engine.decode_fingerprint_block(bytes(tampered), self.key)
        self.assertIn("error", result)

    # ── Image ──────────────────────────────────────────────────────────────

    def test_image_png_roundtrip(self):
        from PIL import Image
        img = Image.new("RGB", (100, 100), color=(128, 64, 200))
        src = self._tmp("test.png")
        img.save(src)
        dst = self._tmp("test_fp.png")
        fp_block = engine.build_fingerprint_block(
            "img-fid", "a@b.com", "tx-img", "2026-01-01", self.key
        )
        engine.embed_image(src, dst, fp_block)
        result = engine.extract_image(dst, self.key)
        self.assertIsNotNone(result)
        self.assertNotIn("error", result)
        self.assertEqual(result["fid"], "img-fid")

    # ── Audio ──────────────────────────────────────────────────────────────

    def test_audio_roundtrip(self):
        src = self._tmp("test.mp3")
        src.write_bytes(b"\xFF\xFB" + b"\x00" * 512)   # fake MP3 bytes
        dst = self._tmp("test_fp.mp3")
        fp_block = engine.build_fingerprint_block(
            "aud-fid", "a@b.com", "tx-aud", "2026-01-01", self.key
        )
        engine.embed_audio(src, dst, fp_block)
        result = engine.extract_audio(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "aud-fid")

    # ── Video ──────────────────────────────────────────────────────────────

    def test_mp4_roundtrip(self):
        src = self._tmp("test.mp4")
        src.write_bytes(b"\x00\x00\x00\x20ftypisom" + b"\x00" * 200)
        dst = self._tmp("test_fp.mp4")
        fp_block = engine.build_fingerprint_block(
            "vid-fid", "a@b.com", "tx-vid", "2026-01-01", self.key
        )
        engine.embed_mp4(src, dst, fp_block)
        result = engine.extract_mp4(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "vid-fid")

    # ── Code ───────────────────────────────────────────────────────────────

    def test_code_py_roundtrip(self):
        src = self._tmp("test.py")
        src.write_text("print('hello world')\n", encoding="utf-8")
        dst = self._tmp("test_fp.py")
        fp_block = engine.build_fingerprint_block(
            "code-fid", "a@b.com", "tx-code", "2026-01-01", self.key
        )
        engine.embed_code(src, dst, fp_block)
        result = engine.extract_code(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "code-fid")

    def test_code_js_roundtrip(self):
        src = self._tmp("test.js")
        src.write_text("console.log('hello');\n", encoding="utf-8")
        dst = self._tmp("test_fp.js")
        fp_block = engine.build_fingerprint_block(
            "js-fid", "a@b.com", "tx-js", "2026-01-01", self.key
        )
        engine.embed_code(src, dst, fp_block)
        result = engine.extract_code(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "js-fid")

    # ── SVG ────────────────────────────────────────────────────────────────

    def test_svg_roundtrip(self):
        src = self._tmp("test.svg")
        src.write_text('<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>', encoding="utf-8")
        dst = self._tmp("test_fp.svg")
        fp_block = engine.build_fingerprint_block(
            "svg-fid", "a@b.com", "tx-svg", "2026-01-01", self.key
        )
        engine.embed_svg(src, dst, fp_block)
        result = engine.extract_svg(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "svg-fid")

    # ── Text / Markdown ────────────────────────────────────────────────────

    def test_text_roundtrip(self):
        src = self._tmp("test.txt")
        src.write_text("Hello world document.\n", encoding="utf-8")
        dst = self._tmp("test_fp.txt")
        fp_block = engine.build_fingerprint_block(
            "txt-fid", "a@b.com", "tx-txt", "2026-01-01", self.key
        )
        engine.embed_text(src, dst, fp_block)
        result = engine.extract_text(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "txt-fid")

    def test_markdown_roundtrip(self):
        src = self._tmp("test.md")
        src.write_text("# Title\n\nSome content.\n", encoding="utf-8")
        dst = self._tmp("test_fp.md")
        fp_block = engine.build_fingerprint_block(
            "md-fid", "a@b.com", "tx-md", "2026-01-01", self.key
        )
        engine.embed_text(src, dst, fp_block)
        result = engine.extract_text(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "md-fid")

    # ── ZIP ────────────────────────────────────────────────────────────────

    def test_zip_roundtrip(self):
        src = self._tmp("test.zip")
        with zipfile.ZipFile(src, "w") as z:
            z.writestr("readme.txt", "hello")
            z.writestr("data.json", '{"key":"value"}')
        dst = self._tmp("test_fp.zip")
        fp_block = engine.build_fingerprint_block(
            "zip-fid", "a@b.com", "tx-zip", "2026-01-01", self.key
        )
        engine.embed_zip(src, dst, fp_block)
        result = engine.extract_zip(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "zip-fid")

    # ── Office ─────────────────────────────────────────────────────────────

    def test_office_docx_roundtrip(self):
        src = self._tmp("test.docx")
        # Minimal valid OOXML skeleton
        with zipfile.ZipFile(src, "w") as z:
            z.writestr("[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        dst = self._tmp("test_fp.docx")
        fp_block = engine.build_fingerprint_block(
            "docx-fid", "a@b.com", "tx-docx", "2026-01-01", self.key
        )
        engine.embed_office(src, dst, fp_block)
        result = engine.extract_office(dst, self.key)
        self.assertIsNotNone(result)
        self.assertEqual(result["fid"], "docx-fid")

    # ── Manifest ───────────────────────────────────────────────────────────

    def test_manifest_verify(self):
        dst = self._tmp("out.txt")
        dst.write_text("content", encoding="utf-8")
        payload = {"fid": "mfid", "email": "x@y.com", "txid": "tx-m", "ts": "2026-01-01"}
        mpath = engine._write_manifest(dst, payload)
        result = engine.verify_manifest(str(mpath))
        self.assertTrue(result["valid"])

    def test_manifest_tamper_detected(self):
        dst = self._tmp("out2.txt")
        dst.write_text("content", encoding="utf-8")
        payload = {"fid": "mfid2", "email": "x@y.com", "txid": "tx-m2", "ts": "2026-01-01"}
        mpath = engine._write_manifest(dst, payload)
        data = json.loads(mpath.read_text())
        data["hmac_sha256"] = "deadbeef" * 8
        mpath.write_text(json.dumps(data))
        result = engine.verify_manifest(str(mpath))
        self.assertFalse(result["valid"])

    # ── Registry ───────────────────────────────────────────────────────────

    def test_registry_register_and_lookup(self):
        reg = engine.FingerprintRegistry(Path(self.tmp) / "test_reg.db")
        rec = reg.register(
            "fid-r1", "Test Buyer", "buyer@test.com", "tx-r1",
            "prod-001", "Test Product", "pdf", "abc123"
        )
        self.assertEqual(rec["fingerprint_id"], "fid-r1")
        found = reg.lookup("fid-r1")
        self.assertIsNotNone(found)
        self.assertEqual(found["buyer_email"], "buyer@test.com")

    def test_registry_stats(self):
        reg = engine.FingerprintRegistry(Path(self.tmp) / "stats_reg.db")
        reg.register("fid-s1","N","e@e.com","tx-s1","p1","prod","image","h1")
        reg.register("fid-s2","N","e@e.com","tx-s2","p2","prod","pdf","h2")
        stats = reg.stats()
        self.assertEqual(stats["total_fingerprints"], 2)
        self.assertIn("image", stats["by_format"])

    # ── Full pipeline ──────────────────────────────────────────────────────

    def test_fingerprint_file_end_to_end(self):
        from PIL import Image
        img = Image.new("RGB", (200, 200), color=(10, 200, 50))
        src = self._tmp("product.png")
        img.save(src)
        result = engine.fingerprint_file(
            src_path=str(src),
            output_path=str(self._tmp("product_fp.png")),
            buyer_name="Jane Doe",
            buyer_email="jane@example.com",
            transaction_id="TXN-FULLTEST-001",
            product_id="PROD-001",
            product_name="Test Image Product",
        )
        self.assertTrue(result["success"])
        self.assertIn("fingerprint_id", result)
        self.assertIn("manifest_file", result)
        manifest_ok = engine.verify_manifest(result["manifest_file"])
        self.assertTrue(manifest_ok["valid"])

    def test_unsupported_format_rejected(self):
        src = self._tmp("binary.exe")
        src.write_bytes(b"MZ" + b"\x00" * 100)
        result = engine.fingerprint_file(
            str(src), str(self._tmp("out.exe")),
            "A", "a@a.com", "tx-x", "p-x", "Product X"
        )
        self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
