/**
 * AcerbE™ REST API — Forensic Watermark Endpoint
 * Archer Chain Analytics™ | ISC: 102237785
 * © 2026 Neil Scott Archer. All rights reserved.
 */

"use strict";

const express  = require("express");
const multer   = require("multer");
const { spawn } = require("child_process");
const fs       = require("fs");
const path     = require("path");

const app    = express();
const upload = multer({ dest: "tests/output/" });
const PORT   = process.env.PORT || 8000;

const API_BEARER_TOKEN = process.env.ACERBE_API_TOKEN;
if (!API_BEARER_TOKEN) {
  process.stderr.write("CRITICAL: ACERBE_API_TOKEN not set — refusing to start\n");
  process.exit(1);
}

// ── Auth middleware ────────────────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const auth  = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token || token !== API_BEARER_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ── POST /api/v1/watermark ─────────────────────────────────────────────────────
app.post(
  "/api/v1/watermark",
  authenticateToken,
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const inputPath  = req.file.path;
    const outputPath = inputPath + "_stamped.pdf";

    let payload;
    try {
      payload = req.body.payload ? JSON.parse(req.body.payload) : { audit: "ACERB-2026" };
    } catch {
      return res.status(400).json({ error: "Invalid payload JSON" });
    }

    const enginePath = path.resolve(__dirname, "../core/engine.py");
    const args = [
      enginePath,
      "--action", "embed",
      "--input",  inputPath,
      "--output", outputPath,
      "--payload", JSON.stringify(payload),
    ];

    const child = spawn("python3", args, {
      env: { ...process.env },
      shell: false,
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

    child.on("close", (code) => {
      // Clean up temp upload regardless of outcome
      try { fs.unlinkSync(inputPath); } catch { /* ignore */ }

      if (code !== 0) {
        return res.status(500).json({ error: "Engine failure", details: stderr });
      }

      let result;
      try {
        result = JSON.parse(stdout);
      } catch {
        return res.status(500).json({ error: "Unparseable engine output", raw: stdout });
      }

      const manifestPath = outputPath + ".manifest.json";
      const manifest = fs.existsSync(manifestPath)
        ? JSON.parse(fs.readFileSync(manifestPath, "utf8"))
        : null;

      res.json({ status: "SUCCESS", output_pdf: outputPath, manifest, engine: result });
    });
  }
);

// ── GET /health ────────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => res.json({ status: "healthy" }));

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(PORT);
