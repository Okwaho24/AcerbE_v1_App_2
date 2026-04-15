#!/usr/bin/env python3
"""
AcerbE™ Fingerprinter — Command Line Interface
Usage:
  acerbe_cli.py stamp   <file> <output> --buyer-name "..." --buyer-email "..." --txid "..." --product-id "..." --product-name "..."
  acerbe_cli.py scan    <file> [--fingerprint-id "..."]
  acerbe_cli.py lookup  <fingerprint-id>
  acerbe_cli.py list    [--limit N]
  acerbe_cli.py stats
  acerbe_cli.py unwrap  <file.rpx> <output> --fingerprint-id "..." --txid "..."
"""

import sys
import json
import argparse
from pathlib import Path
import acerbe_engine as fp


def cmd_stamp(args):
    print(f"\n[AcerbE™] Stamping: {args.file}")
    result = fp.fingerprint_file(
        src_path=args.file,
        output_path=args.output,
        buyer_name=args.buyer_name,
        buyer_email=args.buyer_email,
        transaction_id=args.txid,
        product_id=args.product_id,
        product_name=args.product_name,
        tamper_wrap=not args.no_wrap,
    )
    if result["success"]:
        print(f"  Fingerprint ID : {result['fingerprint_id']}")
        print(f"  Output file    : {result['output_file']}")
        print(f"  File type      : {result['file_type']}")
        print(f"  Issued at      : {result['issued_at']}")
        print(f"  Original hash  : {result['original_hash']}")
        print(f"\n  *** STORE THIS KEY SECURELY ***")
        print(f"  Buyer key (hex): {result['buyer_key_hex']}")
    else:
        print(f"  ERROR: {result.get('reason')}")
        sys.exit(1)


def cmd_scan(args):
    print(f"\n[AcerbE™] Scanning: {args.file}")
    result = fp.identify_file(args.file, getattr(args, "fingerprint_id", None))
    if result["identified"]:
        print(f"  IDENTIFIED")
        print(f"  Fingerprint ID : {result['fingerprint_id']}")
        print(f"  Buyer name     : {result['buyer_name']}")
        print(f"  Buyer email    : {result['buyer_email']}")
        print(f"  Transaction ID : {result['transaction_id']}")
        print(f"  Product        : {result['product_name']}")
        print(f"  Purchased at   : {result['purchased_at']}")
    else:
        print(f"  NOT IDENTIFIED: {result.get('reason')}")


def cmd_lookup(args):
    record = fp.registry.lookup(args.fingerprint_id)
    if record:
        print(json.dumps(record, indent=2))
    else:
        print(f"No record found for fingerprint ID: {args.fingerprint_id}")


def cmd_list(args):
    records = fp.list_registry(limit=getattr(args, "limit", 100))
    if not records:
        print("No fingerprints registered yet.")
        return
    print(f"\n{'ID':36}  {'Buyer':20}  {'Product':20}  {'Issued':24}")
    print("-" * 105)
    for r in records:
        print(f"  {r['fingerprint_id']}  {r['buyer_name'][:20]:20}  {r['product_name'][:20]:20}  {r['issued_at']}")


def cmd_stats(args):
    stats = fp.get_registry_stats()
    print(f"\n  Total fingerprints : {stats['total_fingerprints']}")
    print(f"  Tamper events      : {stats['tamper_events']}")
    print(f"  By format          : {json.dumps(stats['by_format'])}")


def cmd_unwrap(args):
    key = fp.derive_buyer_key(args.fingerprint_id, args.txid)
    result = fp.unwrap_tamper_guard(Path(args.file), Path(args.output), key)
    if result["success"]:
        print(f"  Unwrapped successfully to: {args.output}")
    else:
        print(f"  FAILED: {result['reason']}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(prog="acerbe_cli", description="AcerbE™ — Digital Fingerprinter")
    sub = parser.add_subparsers(dest="command")

    # stamp
    p = sub.add_parser("stamp")
    p.add_argument("file"); p.add_argument("output")
    p.add_argument("--buyer-name", required=True)
    p.add_argument("--buyer-email", required=True)
    p.add_argument("--txid", required=True)
    p.add_argument("--product-id", required=True)
    p.add_argument("--product-name", required=True)
    p.add_argument("--no-wrap", action="store_true")

    # scan
    p = sub.add_parser("scan")
    p.add_argument("file")
    p.add_argument("--fingerprint-id", default=None)

    # lookup
    p = sub.add_parser("lookup")
    p.add_argument("fingerprint_id")

    # list
    p = sub.add_parser("list")
    p.add_argument("--limit", type=int, default=100)

    # stats
    sub.add_parser("stats")

    # unwrap
    p = sub.add_parser("unwrap")
    p.add_argument("file"); p.add_argument("output")
    p.add_argument("--fingerprint-id", required=True)
    p.add_argument("--txid", required=True)

    args = parser.parse_args()
    dispatch = {
        "stamp": cmd_stamp, "scan": cmd_scan, "lookup": cmd_lookup,
        "list": cmd_list, "stats": cmd_stats, "unwrap": cmd_unwrap,
    }
    if args.command in dispatch:
        dispatch[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
