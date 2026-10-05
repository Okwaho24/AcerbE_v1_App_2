"""
AcerbE™ Server — Fixed for RaPaX Integration
Adds /fingerprint endpoint (RaPaX contract) + auth validation
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
sys.path.insert(0, os.path.dirname(__file__))

try:
    import acerbe_engine as engine
except ImportError:
    print("ERROR: acerbe_engine.py not found in this directory.")
    sys.exit(1)

HOST = os.getenv("ACERBE_HOST", "127.0.0.1")
PORT = int(os.getenv("ACERBE_PORT", "7749"))
API_KEY = os.getenv("ACERBE_API_KEY", "")

UPLOAD_DIR = Path(tempfile.mkdtemp(prefix="acerbe_uploads_"))
OUTPUT_DIR = Path(__file__).parent / "stamped_output"
OUTPUT_DIR.mkdir(exist_ok=True)

print(f"[AcerbE] Upload directory: {UPLOAD_DIR}")
print(f"[AcerbE] Output directory: {OUTPUT_DIR}")


class AcerbEHandler(BaseHTTPRequestHandler):
    """HTTP request handler for AcerbE™ server."""

    def send_json(self, data, status=200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-AcerbE-Key")
        self.end_headers()

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        """Handle GET requests."""
        path = self.path.split("?")[0]

        if path == "/":
            self.send_json({"status": "AcerbE™ running", "version": "1.0.0", "port": PORT})

        elif path.startswith("/api/download/"):
            filename = path.replace("/api/download/", "")
            file_path = OUTPUT_DIR / filename

            if not file_path.exists():
                self.send_json({"error": "File not found"}, 404)
                return

            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(file_data)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)

        else:
            self.send_json({"error": "Unknown endpoint"}, 404)

    def do_POST(self):
        """Handle POST requests."""
        # ─── API Key Validation ───────────────────────────────────────
        if API_KEY:
            provided_key = self.headers.get("X-AcerbE-Key", "")
            if provided_key != API_KEY:
                self.send_json({"error": "Unauthorized: invalid API key"}, 401)
                return

        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)

        # ─── RaPaX-Compatible /fingerprint Endpoint ───────────────────
        if path == "/fingerprint":
            try:
                body = json.loads(raw_body)
                file_path = body.get("file_path", "").strip()
                buyer_name = body.get("buyer_name", "").strip()
                buyer_email = body.get("buyer_email", "").strip()
                transaction_id = body.get("transaction_id", "").strip()
                product_id = body.get("product_id", "").strip()
                product_name = body.get("product_name", "Unknown").strip()

                # Validate required fields
                if not all([file_path, buyer_name, buyer_email, transaction_id, product_id]):
                    self.send_json({
                        "success": False,
                        "reason": "Missing required fields: file_path, buyer_name, buyer_email, transaction_id, product_id"
                    })
                    return

                # Check file exists
                if not Path(file_path).exists():
                    self.send_json({
                        "success": False,
                        "reason": f"File not found: {file_path}"
                    })
                    return

                # Generate output filename
                out_name = Path(file_path).stem + "_" + transaction_id[:8] + Path(file_path).suffix
                out_path = OUTPUT_DIR / out_name

                # Call fingerprinting engine
                result = engine.fingerprint_file(
                    src_path=str(file_path),
                    output_path=str(out_path),
                    buyer_name=buyer_name,
                    buyer_email=buyer_email,
                    transaction_id=transaction_id,
                    product_id=product_id,
                    product_name=product_name,
                    tamper_wrap=True,
                )

                if result["success"]:
                    # Return RaPaX-compatible response
                    self.send_json({
                        "success": True,
                        "fingerprinted_file_path": result["output_file"],
                        "fingerprint_id": result["fingerprint_id"],
                        "hash": result.get("file_hash", ""),
                    })
                else:
                    self.send_json(result)

            except json.JSONDecodeError:
                self.send_json({"success": False, "reason": "Invalid JSON"})
            except Exception as e:
                self.send_json({"success": False, "reason": str(e)})

        # ─── Legacy /api/stamp Endpoint ────────────────────────────────
        elif path == "/api/stamp":
            try:
                body = json.loads(raw_body)
                buyer_name = body.get("buyer_name", "").strip()
                buyer_email = body.get("buyer_email", "").strip()
                txid = body.get("transaction_id", "").strip()
                product_id = body.get("product_id", "").strip()
                product_name = body.get("product_name", "").strip()
                file_token = body.get("file_token", "").strip()
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

        # ─── /api/upload Endpoint ──────────────────────────────────────
        elif path == "/api/upload":
            try:
                filename = self.headers.get("X-Filename", "upload.bin")
                token = str(uuid.uuid4()) + "_" + filename
                dest = UPLOAD_DIR / token
                dest.write_bytes(raw_body)
                self.send_json({"token": token, "size": len(raw_body), "filename": filename})
            except Exception as e:
                self.send_json({"success": False, "reason": str(e)})

        # ─── /api/scan Endpoint ────────────────────────────────────────
        elif path == "/api/scan":
            try:
                body = json.loads(raw_body)
                file_token = body.get("file_token", "").strip()
                fpid_hint = body.get("fingerprint_id", None)

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
    """Start the HTTP server."""
    server = HTTPServer((HOST, PORT), AcerbEHandler)
    print(f"✓ AcerbE™ listening at http://{HOST}:{PORT}")
    print(f"✓ /fingerprint (RaPaX contract)")
    print(f"✓ /api/stamp, /api/upload, /api/scan (legacy)")
    server.serve_forever()


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  AcerbE™ — Military-Grade Digital Fingerprinter")
    print("="*60)
    print(f"  HOST: {HOST}")
    print(f"  PORT: {PORT}")
    if API_KEY:
        print(f"  API Key: required (via X-AcerbE-Key header)")
    else:
        print(f"  API Key: not configured (set ACERBE_API_KEY env var)")
    print("="*60 + "\n")

    # Open browser after short delay
    def open_browser():
        import time
        time.sleep(1.2)
        webbrowser.open(f"http://{HOST}:{PORT}")

    threading.Thread(target=open_browser, daemon=True).start()
    run_server()
