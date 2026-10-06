> **NOTICE: PRIVATE AND PROPRIETARY PROPERTY OF ARCHER CHAIN ANALYTICS**
> 
> This repository contains confidential and proprietary information. 
> Access is restricted to authorized personnel only. 
> Copyright © 2026 Archer Chain Analytics.
> 
# AcerbE™ — Forensic Mark Engine
### AcerbE™ Forensic Mark Engine · v3.1.0-reconciled

---

## What It Does

Embeds a **unique, buyer-specific, tamper-destructive digital fingerprint** into every
product file at the moment of sale. If a buyer shares or resells your product, you can
identify exactly who bought it, when, and via which transaction — by scanning any copy.

---

## Four Protection Layers

| Layer | Method | Purpose |
|-------|--------|---------|
| 1 · Steganography | LSB pixel injection (images), XMP+GPM (PDF), zero-width Unicode (text/md), free-atom (MP4), comment injection (code), part injection (OOXML) | Invisible in-band embedding |
| 2 · Crypto Binding | AES-256-CBC + PBKDF2-derived key, unique per buyer+transaction | No two buyers share a key |
| 3 · Manifest Integrity | HMAC-SHA256 sidecar `.manifest.json` | Any modification = HMAC fail = forensic alert |
| 4 · Forensic Registry | HMAC-sealed SQLite records | Traceable: name, email, transaction ID, timestamp |

---

## File Structure

```
acerbe_engine/
├── acerbe_engine.py       ← Core engine — 26 formats, GPM PDF, HMAC registry (v3.1.0-reconciled)
├── acerbe_cli.py          ← Command-line interface
├── acerbe_integration.py  ← RaPaX™ vending machine plug-in
├── server.py              ← HTTP server — /fingerprint (RaPaX) + /api/stamp|upload|scan
├── test_acerbe_v3.py      ← Full test suite (18/18 pass)
├── dashboard_live.html    ← Standalone web dashboard
└── README.md              ← This file
```

---

## Quick Start

### Install dependencies
```bash
pip install Pillow pikepdf cryptography
```

### Set environment variables (production)
```bash
export ACERBE_MASTER_KEY="your-256-bit-secret-key-here"
export ACERBE_REGISTRY_KEY="your-registry-hmac-key-here"
export ACERBE_REGISTRY="/secure/path/to/acerbe_registry.db"
```

### Stamp a product at sale
```bash
python acerbe_cli.py stamp product.pdf output/ \
  --buyer-name  "Jane Smith"         \
  --buyer-email "jane@example.com"   \
  --txid        "TX-2024-001"        \
  --product-id  "PROD-EBOOK-001"     \
  --product-name "My Digital Product"
```

### Forensic scan of a suspected pirated copy
```bash
python acerbe_cli.py scan suspected_copy.pdf
```

### List registry
```bash
python acerbe_cli.py list
python acerbe_cli.py stats
```

---

## RaPaX™ Integration (One Line)

Drop this into your checkout handler. Call it after payment is confirmed.
Deliver ONLY the `stamped_file` to the buyer — never the original.

```python
from acerbe_integration import acerbe_on_sale

result = acerbe_on_sale(
    product_file   = "/products/my_ebook.pdf",
    buyer_name     = order.buyer_name,
    buyer_email    = order.buyer_email,
    transaction_id = order.id,
    product_id     = product.sku,
    product_name   = product.title,
)

if result["success"]:
    deliver_to_buyer(result["stamped_file"])  # ← deliver THIS, never original
    log_securely(result["buyer_key_hex"])      # ← store this for decryption
```

---

## Python API

```python
import acerbe_engine as fp

# Stamp
result = fp.fingerprint_file(
    src_path       = "product.pdf",
    output_path    = "product_stamped.pdf",
    buyer_name     = "Jane Smith",
    buyer_email    = "jane@example.com",
    transaction_id = "TX-001",
    product_id     = "PROD-001",
    product_name   = "My Product",
    tamper_wrap    = True,  # wraps in .rpx encrypted container
)

# Forensic scan
match = fp.identify_file("suspected_pirate_copy.pdf")
if match["identified"]:
    print(match["buyer_name"], match["buyer_email"])

# Registry
fp.get_registry_stats()
fp.list_registry(limit=50)
fp.registry.lookup("fingerprint-uuid-here")
```

---

## Supported Formats

| Format | Embedding Method |
|--------|-----------------|
| PNG / JPG / WEBP / BMP | LSB steganography across RGB channels |
| PDF | XMP metadata + document info dictionary |
| MP3 / WAV / FLAC / OGG | Trailing-byte injection (players ignore extra bytes) |
| ZIP archives | Hidden `.acerbe_fp_manifest` + inner file marking |

---

## Security Notes

1. **Master key** — set `ACERBE_MASTER_KEY` in environment. Never hardcode. Use a cryptographically random 256-bit value.
2. **Registry key** — set `ACERBE_REGISTRY_KEY`. Used to HMAC-seal every registry record. Separate from master key.
3. **Buyer keys** — each stamped file's decryption key is derived from master key + fingerprint ID + transaction ID. Log `buyer_key_hex` from each stamp result to a secure store.
4. **Registry DB** — store `acerbe_registry.db` in a secure, backed-up location with restricted filesystem permissions (600).
5. **Never deliver originals** — always deliver the `.rpx` stamped output, never the source file.

---

## Dashboard

Open `dashboard.html` in any modern browser for the full visual interface:
- Stamp products with form UI
- Run forensic scans
- Browse the registry
- View stats and activity feed

No server required — works entirely in-browser for the UI layer.
The Python engine is invoked via CLI or API for actual file processing.

---

## License

Proprietary — RaPaX™ Platform  
© 2024 — All rights reserved

---

## Ownership & Legal

**© 2026 Neil Scott Archer / Archer Chain Analytics**
- **ISC Registration:** 102237785
- **CRA BN:** 709110639
- **Address:** 417 Avenue G S, 5th Ave N, Saskatoon SK S7M 1V5
- **Contact:** archerchainanalytics@gmail.com

All rights reserved. Exclusive property of Neil Scott Archer operating as Archer Chain Analytics. Unauthorized use prohibited. Trademark applications pending with CIPO.

---
