"""
AcerbE™ Fingerprinter — Vending Machine Integration Module
=========================================================
Drop this into RaPaX™ checkout pipeline. Call acerbe_on_sale() at the moment
a transaction completes. The fingerprinted, tamper-guarded file is what
gets delivered to the buyer — never the raw original.
"""

import os
import uuid
from pathlib import Path
from acerbe_engine import fingerprint_file, identify_file, get_registry_stats


class AcerbEFingerprintMiddleware:
    """
    Plug this into the RaPaX™ checkout pipeline.

    Example usage in RaPaX™ checkout handler:
    ----------------------------------------
        from acerbe_integration import AcerbEFingerprintMiddleware

        middleware = AcerbEFingerprintMiddleware(output_dir="/var/acerbe/stamped")

        result = middleware.on_sale(
            product_file="/products/my_ebook.pdf",
            buyer_name="Jane Smith",
            buyer_email="jane@example.com",
            transaction_id=order.id,
            product_id=product.sku,
            product_name=product.title,
        )

        if result["success"]:
            deliver_to_buyer(result["stamped_file"])  # deliver THIS, not original
        else:
            handle_error(result["reason"])
    """

    def __init__(self, output_dir: str = "./stamped_products"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def on_sale(
        self,
        product_file:   str,
        buyer_name:     str,
        buyer_email:    str,
        transaction_id: str,
        product_id:     str,
        product_name:   str,
    ) -> dict:
        """
        Called at point of sale. Returns the stamped file path for delivery.
        NEVER deliver the original file — only deliver result["stamped_file"].
        """
        src      = Path(product_file)
        stem     = src.stem
        suffix   = src.suffix
        out_name = f"{stem}_{transaction_id[:8]}{suffix}"
        out_path = self.output_dir / out_name

        result = fingerprint_file(
            src_path=str(src),
            output_path=str(out_path),
            buyer_name=buyer_name,
            buyer_email=buyer_email,
            transaction_id=transaction_id,
            product_id=product_id,
            product_name=product_name,
            tamper_wrap=True,
        )

        if result["success"]:
            return {
                "success":        True,
                "stamped_file":   result["output_file"],
                "fingerprint_id": result["fingerprint_id"],
                "issued_at":      result["issued_at"],
                "buyer_key_hex":  result["buyer_key_hex"],  # log this
            }
        return result

    def investigate(self, suspect_file: str, fingerprint_id: str = None) -> dict:
        """
        Forensic investigation of a suspected pirated file.
        Returns full buyer identity if fingerprint is recoverable.
        """
        return identify_file(suspect_file, fingerprint_id)

    def dashboard_stats(self) -> dict:
        return get_registry_stats()


# ── Convenience function for simple integration ──────────────────────────────

def acerbe_on_sale(
    product_file:   str,
    buyer_name:     str,
    buyer_email:    str,
    transaction_id: str = None,
    product_id:     str = None,
    product_name:   str = "Unknown Product",
    output_dir:     str = "./stamped_products",
) -> dict:
    """
    One-line integration for RaPaX™ checkout.

    Returns dict with stamped_file path ready for delivery.
    """
    mw = AcerbEFingerprintMiddleware(output_dir=output_dir)
    return mw.on_sale(
        product_file=product_file,
        buyer_name=buyer_name,
        buyer_email=buyer_email,
        transaction_id=transaction_id or str(uuid.uuid4()),
        product_id=product_id or "PROD-001",
        product_name=product_name,
    )
