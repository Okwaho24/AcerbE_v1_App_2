"""
AcerbE™ — Local Application Server
====================================
Bridges the dashboard UI to the live Python engine.
Buyer double-clicks launch.py (or launch.bat on Windows) and this starts
automatically. Browser opens to the dashboard. Everything works live.
"""

import os
import sys
import json
import uuid
import threading
import webbrowser
import tempfile
import shutil
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add current directory to path so engine imports work
sys.path.insert(0, str(Path(__file__).parent))
import acerbe_engine as engine

HOST = "127.0.0.1"
PORT = 7749
DASHBOARD = Path(__file__).parent / "dashboard_live.html"
UPLOAD_DIR = Path(tempfile.mkdtemp(prefix="acerbe_uploads_"))
OUTPUT_DIR = Path(__file__).parent / "stamped_output"
OUTPUT_DIR.mkdir(exist_ok=True)


class AcerbEHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress default server logs

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path: Path):
        data = path.read_bytes()
        ext  = path.suffix.lower()
        ctype = {
            ".html": "text/html",
            ".js":   "application/javascript",
            ".css":  "text/css",
            ".json": "application/json",
        }.get(ext, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == "/" or path == "/index.html":
            self.send_file(DASHBOARD)

        elif path == "/api/stats":
            self.send_json(engine.get_registry_stats())

        elif path == "/api/registry":
            qs    = parse_qs(parsed.query)
            limit = int(qs.get("limit", ["200"])[0])
            self.send_json(engine.list_registry(limit=limit))

        elif path == "/api/lookup":
            qs  = parse_qs(parsed.query)
            fid = qs.get("id", [""])[0]
            rec = engine.registry.lookup(fid)
            self.send_json(rec if rec else {"error": "Not found"})

        elif path.startswith("/api/download/"):
            filename = path.replace("/api/download/", "")
            fpath    = OUTPUT_DIR / filename
            if fpath.exists():
                data = fpath.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", len(data))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_json({"error": "File not found"}, 404)

        elif path == "/api/shutdown":
            self.send_json({"status": "shutting down"})
            threading.Thread(target=self.server.shutdown).start()

        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed   = urlparse(self.path)
        path     = parsed.path
        length   = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)

        if path == "/api/stamp":
            try:
                # Multipart not needed — we accept JSON with base64 or just metadata
                # For file upload we use a two-step: POST metadata + file separately
                body = json.loads(raw_body)
                buyer_name  = body.get("buyer_name", "").strip()
                buyer_email = body.get("buyer_email", "").strip()
                txid        = body.get("transaction_id", "").strip()
                product_id  = body.get("product_id", "").strip()
                product_name= body.get("product_name", "").strip()
                file_token  = body.get("file_token", "").strip()
                tamper_wrap = body.get("tamper_wrap", True)

                if not all([buyer_name, buyer_email, txid, product_id, product_name, file_token]):
                    self.send_json({"success": False, "reason": "Missing required fields"})
                    return

                src_path = UPLOAD_DIR / file_token
                if not src_path.exists():
                    self.send_json({"success": False, "reason": "Uploaded file not found. Please re-upload."})
                    return

                out_name = src_path.stem + "_" + txid[:8] + src_path.suffix
                out_path = OUTPUT_DIR / out_name

                result = engine.fingerprint_file(
                    src_path=str(src_path),
                    output_path=str(out_path),
                    buyer_name=buyer_name,
                    buyer_email=buyer_email,
                    transaction_id=txid,
                    product_id=product_id,
                    product_name=product_name,
                    tamper_wrap=tamper_wrap,
                )

                if result["success"]:
                    out_filename = Path(result["output_file"]).name
                    result["download_url"] = f"/api/download/{out_filename}"

                self.send_json(result)

            except Exception as e:
                self.send_json({"success": False, "reason": str(e)})

        elif path == "/api/upload":
            # Receive raw file bytes, store with token, return token
            try:
                content_type = self.headers.get("Content-Type", "")
                filename     = self.headers.get("X-Filename", "upload.bin")
                token        = str(uuid.uuid4()) + "_" + filename
                dest         = UPLOAD_DIR / token
                dest.write_bytes(raw_body)
                self.send_json({"token": token, "size": len(raw_body), "filename": filename})
            except Exception as e:
                self.send_json({"success": False, "reason": str(e)})

        elif path == "/api/scan":
            try:
                body     = json.loads(raw_body)
                file_token = body.get("file_token", "").strip()
                fpid_hint  = body.get("fingerprint_id", None)

                src_path = UPLOAD_DIR / file_token
                if not src_path.exists():
                    self.send_json({"identified": False, "reason": "File not found. Please re-upload."})
                    return

                result = engine.identify_file(str(src_path), fpid_hint or None)
                self.send_json(result)
            except Exception as e:
                self.send_json({"identified": False, "reason": str(e)})

        else:
            self.send_json({"error": "Unknown endpoint"}, 404)


def run_server():
    server = HTTPServer((HOST, PORT), AcerbEHandler)
    print(f"  AcerbE™ running at http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  AcerbE™ — Military-Grade Digital Fingerprinter")
    print("="*50)
    print(f"  Starting local server...")

    # Open browser after short delay
    def open_browser():
        import time
        time.sleep(1.2)
        webbrowser.open(f"http://{HOST}:{PORT}")

    threading.Thread(target=open_browser, daemon=True).start()
    run_server()
