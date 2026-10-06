#!/usr/bin/env python3
"""
Live PDF GPM (Glyph Positional Modulation) Verification
Validates stream manipulation and sub-point character spacing.
"""

import sys
import os
import json
import unittest

try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    import pypdf
    HAS_PIKEPDF = False

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.engine import embed_pdf_watermark

def extract_raw_bytes(page):
    """Safely extracts raw content stream bytes across pikepdf and pypdf backends."""
    if HAS_PIKEPDF:
        contents = page.get("/Contents")
        if contents is None:
            return b""
        if isinstance(contents, pikepdf.Array):
            return b"".join(bytes(s.read_bytes()) for s in contents)
        return bytes(contents.read_bytes())

    contents = page.get_contents()
    if contents is None:
        return b""
    if isinstance(contents, list):
        return b"\n".join([obj.get_data() for obj in contents if hasattr(obj, "get_data")])
    if hasattr(contents, "get_data"):
        return contents.get_data()
    return b""

class TestLiveGPM(unittest.TestCase):

    def test_live_gpm_watermarking(self):
        input_pdf = "tests/output/live_sample_input.pdf"
        output_pdf = "tests/output/live_sample_gpm_marked.pdf"
        os.makedirs("tests/output", exist_ok=True)

        if HAS_PIKEPDF:
            pdf = pikepdf.Pdf.new()
            for i in range(3):
                page = pikepdf.Page(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Page,
                        MediaBox=pikepdf.Array([0, 0, 612, 792]),
                    )
                )
                stream_data = (
                    f"BT /F1 12 Tf 72 700 Td (AcerbE GPM Test Page {i+1}) Tj ET"
                ).encode("latin-1")
                page.obj["/Contents"] = pdf.make_stream(stream_data)
                pdf.pages.append(page)
            pdf.save(input_pdf)
            pdf.close()
        else:
            writer = pypdf.PdfWriter()
            for i in range(3):
                page = writer.add_blank_page(width=612, height=792)
                stream = pypdf.generic.DecodedStreamObject()
                stream.set_data(f"BT /F1 12 Tf 72 700 Td (AcerbE GPM Test Page {i+1}) Tj ET".encode('utf-8'))
                page[pypdf.generic.NameObject("/Contents")] = stream
            with open(input_pdf, "wb") as f_out:
                writer.write(f_out)

        self.assertTrue(os.path.exists(input_pdf))

        secret_key = os.environ.get("ACERBE_SECRET_KEY", "f" * 64)
        payload = {
            "txid": "TX-GPM-LIVE-2026-X",
            "email": "verification@mahihkan.com",
            "product_id": "PROD-EBOOK-001"
        }

        res = embed_pdf_watermark(input_pdf, output_pdf, payload, secret_key)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["modified_pages"], 3)
        self.assertTrue(os.path.exists(output_pdf))

        reader = pikepdf.Pdf.open(output_pdf) if HAS_PIKEPDF else pypdf.PdfReader(output_pdf)
        pages = reader.pages

        tc_operator_found = False
        for page in pages:
            raw_bytes = extract_raw_bytes(page)
            if b"Tc" in raw_bytes:
                tc_operator_found = True

        if HAS_PIKEPDF:
            reader.close()

        self.assertTrue(tc_operator_found, "'Tc' character spacing operator missing from content streams.")

if __name__ == "__main__":
    unittest.main()
