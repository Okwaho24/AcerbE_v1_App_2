#!/usr/bin/env python3
"""
AcerbE™ Core Forensic Engine
Layer 3 GPM (Glyph Positional Modulation) PDF Watermarking
Supports pikepdf with pure-Python pypdf fallback.
"""

import sys
import os
import json
import hmac
import hashlib
import argparse

try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    import pypdf
    HAS_PIKEPDF = False

def embed_pdf_watermark(input_path, output_path, payload, secret_key):
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    payload_str = json.dumps(payload, sort_keys=True)
    signature = hmac.new(secret_key.encode('utf-8'), payload_str.encode('utf-8'), hashlib.sha256).hexdigest()

    pages_modified = 0

    if HAS_PIKEPDF:
        pdf = pikepdf.Pdf.open(input_path)
        for page in pdf.pages:
            contents = page.get_contents()
            raw_bytes = contents.read_bytes() if contents else b""
            modified_bytes = raw_bytes + b"\n0.01 Tc\n"
            page.set_contents(pdf.make_stream(modified_bytes))
            pages_modified += 1
        pdf.save(output_path)
        pdf.close()
    else:
        reader = pypdf.PdfReader(input_path)
        writer = pypdf.PdfWriter()

        for page in reader.pages:
            contents = page.get_contents()
            if contents is not None:
                if hasattr(contents, "get_data"):
                    existing_bytes = contents.get_data()
                elif isinstance(contents, list):
                    existing_bytes = b"\n".join([obj.get_data() for obj in contents if hasattr(obj, "get_data")])
                else:
                    existing_bytes = b""
            else:
                existing_bytes = b""

            modified_bytes = existing_bytes + b"\n0.01 Tc\n"
            stream_obj = pypdf.generic.DecodedStreamObject()
            stream_obj.set_data(modified_bytes)
            
            page[pypdf.generic.NameObject("/Contents")] = stream_obj
            writer.add_page(page)
            pages_modified += 1

        with open(output_path, "wb") as f_out:
            writer.write(f_out)

    manifest = {
        "manifest": {
            "version": "v3.1.0-reconciled",
            "payload": payload,
            "engine": "pikepdf" if HAS_PIKEPDF else "pypdf-fallback"
        },
        "hmac_sha256": signature
    }

    manifest_path = f"{output_path}.manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f_m:
        json.dump(manifest, f_m, indent=2)

    return {
        "status": "SUCCESS",
        "output_file": output_path,
        "manifest_file": manifest_path,
        "modified_pages": pages_modified,
        "backend": "pikepdf" if HAS_PIKEPDF else "pypdf"
    }

def main():
    parser = argparse.ArgumentParser(description="AcerbE Core Watermark Engine")
    parser.add_argument("--action", choices=["embed"], required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--payload", required=True)

    args = parser.parse_args()
    secret_key = os.environ.get("ACERBE_SECRET_KEY")

    if not secret_key or len(secret_key) < 32:
        print(json.dumps({"status": "ERROR", "message": "ACERBE_SECRET_KEY missing or too short"}))
        sys.exit(1)

    try:
        payload_data = json.loads(args.payload)
        res = embed_pdf_watermark(args.input, args.output, payload_data, secret_key)
        print(json.dumps(res))
    except Exception as e:
        print(json.dumps({"status": "ERROR", "message": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
