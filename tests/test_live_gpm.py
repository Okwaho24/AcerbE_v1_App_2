#!/usr/bin/env python3
"""
Live PDF GPM (Glyph Positional Modulation) Verification
Validates stream manipulation and sub-point character spacing.
"""

import sys
import os
import json

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
        contents = page.get_contents()
        return contents.read_bytes() if contents else b""
    
    contents = page.get_contents()
    if contents is None:
        return b""
    if isinstance(contents, list):
        return b"\n".join([obj.get_data() for obj in contents if hasattr(obj, "get_data")])
    if hasattr(contents, "get_data"):
        return contents.get_data()
    return b""

def run_live_gpm_test():
    print("=== Starting Live PDF GPM Embedder Test ===")
    
    input_pdf = "tests/output/live_sample_input.pdf"
    output_pdf = "tests/output/live_sample_gpm_marked.pdf"
    os.makedirs("tests/output", exist_ok=True)

    if HAS_PIKEPDF:
        pdf = pikepdf.Pdf.new()
        for i in range(3):
            page = pdf.add_blank_page(page_size=(612, 792))
            stream_data = f"BT /F1 12 Tf 72 700 Td (AcerbE GPM Test Page {i+1}) Tj ET".encode('utf-8')
            page.set_contents(pdf.make_stream(stream_data))
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

    print(f"[+] Generated 3-page target PDF fixture: {input_pdf}")

    secret_key = os.environ.get("ACERBE_SECRET_KEY", "f" * 64)
    payload = {
        "txid": "TX-GPM-LIVE-2026-X",
        "email": "verification@mahihkan.com",
        "product_id": "PROD-EBOOK-001"
    }

    print("[+] Invoking embed_pdf_watermark (Glyph Positional Modulation)...")
    res = embed_pdf_watermark(input_pdf, output_pdf, payload, secret_key)
    print("[✔] Embedding result:", json.dumps(res, indent=2))

    reader = pikepdf.Pdf.open(output_pdf) if HAS_PIKEPDF else pypdf.PdfReader(output_pdf)
    pages = reader.pages

    tc_operator_found = False
    for idx, page in enumerate(pages):
        raw_bytes = extract_raw_bytes(page)
        if b"Tc" in raw_bytes:
            tc_operator_found = True
            print(f"[✔] Confirmed 'Tc' operator injection on Page {idx + 1}")

    if HAS_PIKEPDF:
        reader.close()

    if not tc_operator_found:
        print("[-] FAIL: 'Tc' character spacing operator not found in output content streams.")
        sys.exit(1)

    print("=== Live GPM Embedder Test PASSED ===")

if __name__ == "__main__":
    run_live_gpm_test()
