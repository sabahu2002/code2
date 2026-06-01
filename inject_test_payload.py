#!/usr/bin/env python3
"""
inject_test_payload.py — Add harmless test payloads to sticker files
to verify sticker_payload_detector.py catches them.

All payloads are INERT (no real malware). They use real file signatures
but contain no executable code — safe for local testing only.

Usage:
    python3 inject_test_payload.py clean.webp --mode append_mz
    python3 inject_test_payload.py clean.webp --mode all --outdir ./infected/
    python3 inject_test_payload.py clean.webp --list
"""

import argparse
import os
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Inert payload builders — real magic bytes, zero executable content
# ---------------------------------------------------------------------------

def payload_mz() -> bytes:
    """Windows PE stub: MZ header + zeroed body. Not executable."""
    return b"\x4d\x5a" + b"\x90\x00" + b"\x00" * 56

def payload_elf() -> bytes:
    """ELF header stub: correct magic + zeroed fields. Not executable."""
    return b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56

def payload_zip() -> bytes:
    """Empty ZIP local-file header (no files inside). Not executable."""
    # PK\x03\x04 + version + flags + ... all zeroed
    return b"PK\x03\x04" + b"\x00" * 26

def payload_pdf() -> bytes:
    """Minimal PDF header comment. Not executable."""
    return b"%PDF-1.4\n%Inert test payload\n%%EOF\n"

def payload_shebang() -> bytes:
    """Shebang line with a comment only — no commands."""
    return b"#!/bin/sh\n# INERT TEST PAYLOAD - no commands here\n"

def payload_elf_in_body() -> bytes:
    """ELF magic prefixed with padding so it lands in the file body."""
    return b"\x00" * 16 + b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40

MODES = {
    "append_mz":      ("MZ (Windows PE) appended after image end",   payload_mz),
    "append_elf":     ("ELF binary appended after image end",         payload_elf),
    "append_zip":     ("ZIP/APK header appended after image end",     payload_zip),
    "append_pdf":     ("PDF header appended after image end",         payload_pdf),
    "append_shebang": ("Shell shebang appended after image end",      payload_shebang),
    "body_elf":       ("ELF magic injected into file body",           payload_elf_in_body),
}

# ---------------------------------------------------------------------------
# Inject helpers
# ---------------------------------------------------------------------------

def inject_append(data: bytes, payload: bytes) -> bytes:
    """Append payload after the image data (after the end marker)."""
    return data + payload


def inject_body(data: bytes, payload: bytes, offset: int = 32) -> bytes:
    """Insert payload at a given offset inside the file body."""
    return data[:offset] + payload + data[offset:]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def process(input_path: str, mode: str, outdir: str | None) -> str:
    data = Path(input_path).read_bytes()
    label, builder = MODES[mode]
    payload = builder()

    if mode.startswith("body_"):
        result = inject_body(data, payload)
    else:
        result = inject_append(data, payload)

    stem   = Path(input_path).stem
    suffix = Path(input_path).suffix or ".webp"
    out_name = f"{stem}__{mode}{suffix}"
    out_path = os.path.join(outdir or os.path.dirname(input_path) or ".", out_name)

    Path(out_path).write_bytes(result)
    return out_path


def main():
    parser = argparse.ArgumentParser(
        description="Inject inert test payloads into sticker files."
    )
    parser.add_argument("file", nargs="?", help="Input sticker file (WebP/PNG/JPEG)")
    parser.add_argument(
        "--mode", choices=list(MODES) + ["all"],
        default="append_mz",
        help="Payload type to inject (default: append_mz)",
    )
    parser.add_argument("--outdir", help="Directory for output files (default: same as input)")
    parser.add_argument("--list", action="store_true", help="List available modes and exit")
    args = parser.parse_args()

    if args.list:
        print("Available modes:")
        for name, (desc, _) in MODES.items():
            print(f"  {name:<20} {desc}")
        return

    if not args.file:
        parser.error("A sticker file is required unless --list is used.")

    if not os.path.isfile(args.file):
        sys.exit(f"ERROR: File not found: {args.file}")

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)

    modes = list(MODES) if args.mode == "all" else [args.mode]

    for mode in modes:
        out = process(args.file, mode, args.outdir)
        label = MODES[mode][0]
        print(f"  Created : {out}")
        print(f"  Payload : {label}")
        print()


if __name__ == "__main__":
    main()
