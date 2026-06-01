#!/usr/bin/env python3
"""
WhatsApp Sticker Hidden Payload Detector
Defensive steganography research tool.

Checks for:
  - Appended data after image end marker
  - Executable file signatures (magic bytes) embedded in the file
  - Suspicious EXIF/metadata
  - LSB anomalies (chi-square test on pixel LSBs)
  - Unusually high entropy regions
"""

import sys
import math
import struct
import argparse
import zipfile
import io
from pathlib import Path
from collections import Counter

# ---------------------------------------------------------------------------
# Known file magic bytes (executable / script / archive signatures)
# ---------------------------------------------------------------------------
MAGIC_SIGNATURES = {
    b"\x4d\x5a": "Windows PE executable (MZ)",
    b"\x7fELF": "ELF binary (Linux/Android)",
    b"\xca\xfe\xba\xbe": "Mach-O fat binary",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    b"PK\x03\x04": "ZIP / APK / JAR archive",
    b"\x1f\x8b": "Gzip compressed data",
    b"BZh": "Bzip2 compressed data",
    b"\xfd7zXZ": "XZ compressed data",
    b"Rar!": "RAR archive",
    b"\x25\x50\x44\x46": "PDF document",
    b"#!/": "Shell script (shebang)",
    b"#!": "Script (shebang)",
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00": None,  # skip null blocks
}

# Image end markers — data after these is suspicious
IMAGE_END_MARKERS = {
    "jpeg": b"\xff\xd9",
    "png": b"\x00\x00\x00\x00IEND\xaeB`\x82",
    "webp_riff": None,  # handled separately via RIFF chunk length
}


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ---------------------------------------------------------------------------
# Detect image format
# ---------------------------------------------------------------------------

def detect_format(data: bytes) -> str:
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:2] == b"\xff\xd8":
        return "jpeg"
    return "unknown"


# ---------------------------------------------------------------------------
# Check for appended data after image end
# ---------------------------------------------------------------------------

def check_appended_data(data: bytes, fmt: str) -> dict:
    findings = {}

    if fmt == "jpeg":
        end = data.rfind(b"\xff\xd9")
        if end == -1:
            findings["missing_end_marker"] = "No JPEG EOI marker found"
            return findings
        tail = data[end + 2:]
        if tail.strip(b"\x00"):
            findings["appended_bytes"] = len(tail)
            findings["appended_entropy"] = round(entropy(tail), 3)

    elif fmt == "png":
        marker = b"IEND\xaeB`\x82"
        end = data.rfind(marker)
        if end == -1:
            findings["missing_end_marker"] = "No PNG IEND chunk found"
            return findings
        tail = data[end + len(marker):]
        if tail.strip(b"\x00"):
            findings["appended_bytes"] = len(tail)
            findings["appended_entropy"] = round(entropy(tail), 3)

    elif fmt == "webp":
        # RIFF container: bytes 4-7 are file size (little-endian), total = size + 8
        if len(data) < 12:
            findings["too_short"] = "File too short to be valid WebP"
            return findings
        riff_size = struct.unpack_from("<I", data, 4)[0]
        expected_len = riff_size + 8
        if len(data) > expected_len:
            tail = data[expected_len:]
            if tail.strip(b"\x00"):
                findings["appended_bytes"] = len(tail)
                findings["appended_entropy"] = round(entropy(tail), 3)

    return findings


# ---------------------------------------------------------------------------
# Scan entire file for executable magic bytes
# ---------------------------------------------------------------------------

def scan_magic_bytes(data: bytes) -> list[dict]:
    hits = []
    for magic, label in MAGIC_SIGNATURES.items():
        if label is None:
            continue
        offset = 0
        while True:
            pos = data.find(magic, offset)
            if pos == -1:
                break
            # Skip if this is at offset 0 and is the image header itself
            # (WebP, PNG, JPEG are not executables)
            hits.append({"offset": pos, "signature": label, "magic_hex": magic.hex()})
            offset = pos + 1
    return hits


# ---------------------------------------------------------------------------
# LSB chi-square test (detects uniform LSB distribution = steganography)
# ---------------------------------------------------------------------------

def lsb_chi_square(pixel_bytes: bytes) -> float:
    """
    Returns chi-square statistic for LSB uniformity.
    A value close to 0 means LSBs are suspiciously uniform (possible LSB stego).
    Natural images tend to have structured LSBs (higher chi-square deviation).
    """
    lsbs = [b & 1 for b in pixel_bytes]
    ones = sum(lsbs)
    zeros = len(lsbs) - ones
    total = len(lsbs)
    if total == 0:
        return 0.0
    expected = total / 2
    chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
    return round(chi2, 4)


def extract_pixel_bytes(data: bytes, fmt: str) -> bytes | None:
    """Extract raw pixel data using stdlib only (no Pillow required)."""
    try:
        # For a quick approximation without Pillow, use raw file bytes
        # (skips headers; not perfect but useful for entropy/LSB heuristics)
        if fmt == "png":
            # PNG pixel data lives in IDAT chunks — extract chunk data
            idat = b""
            i = 8  # skip PNG signature
            while i < len(data) - 12:
                length = struct.unpack_from(">I", data, i)[0]
                chunk_type = data[i + 4: i + 8]
                chunk_data = data[i + 8: i + 8 + length]
                if chunk_type == b"IDAT":
                    idat += chunk_data
                i += 12 + length
            return idat if idat else None
        elif fmt in ("jpeg", "webp"):
            return data  # use compressed bytes as proxy
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# High-entropy region scanner
# ---------------------------------------------------------------------------

def scan_high_entropy_regions(data: bytes, block_size: int = 256, threshold: float = 7.8) -> list[dict]:
    regions = []
    for i in range(0, len(data) - block_size, block_size):
        block = data[i: i + block_size]
        e = entropy(block)
        if e >= threshold:
            regions.append({"offset": i, "entropy": round(e, 3)})
    return regions


# ---------------------------------------------------------------------------
# Metadata / comment extraction (PNG tEXt, EXIF-like patterns)
# ---------------------------------------------------------------------------

def extract_metadata(data: bytes, fmt: str) -> dict:
    meta = {}
    if fmt == "png":
        i = 8
        while i < len(data) - 12:
            try:
                length = struct.unpack_from(">I", data, i)[0]
                chunk_type = data[i + 4: i + 8]
                chunk_data = data[i + 8: i + 8 + length]
                if chunk_type in (b"tEXt", b"zTXt", b"iTXt"):
                    meta[f"{chunk_type.decode()}@{i}"] = repr(chunk_data[:200])
                i += 12 + length
            except struct.error:
                break
    elif fmt in ("jpeg", "webp"):
        # Scan for EXIF header
        pos = data.find(b"Exif\x00\x00")
        if pos != -1:
            meta["exif_offset"] = pos
            meta["exif_snippet"] = repr(data[pos: pos + 64])
        # XMP
        pos = data.find(b"<x:xmpmeta")
        if pos != -1:
            end = data.find(b"</x:xmpmeta>", pos)
            meta["xmp"] = data[pos: end + 12].decode(errors="replace")[:500]
    return meta


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_file(path: str) -> dict:
    data = Path(path).read_bytes()
    fmt = detect_format(data)
    report = {
        "file": path,
        "size_bytes": len(data),
        "format": fmt,
        "overall_entropy": round(entropy(data), 3),
        "findings": [],
        "warnings": [],
        "info": [],
    }

    def warn(msg):
        report["warnings"].append(msg)

    def finding(msg):
        report["findings"].append(msg)

    def info(msg):
        report["info"].append(msg)

    if fmt == "unknown":
        warn("Unrecognized image format — not a JPEG, PNG, or WebP")

    # 1. Appended data
    appended = check_appended_data(data, fmt)
    if "appended_bytes" in appended:
        finding(
            f"Appended data detected: {appended['appended_bytes']} bytes "
            f"after image end marker (entropy={appended.get('appended_entropy', 'n/a')})"
        )
    if "missing_end_marker" in appended:
        warn(appended["missing_end_marker"])

    # 2. Executable magic bytes (skip first 12 bytes = image header)
    magic_hits = scan_magic_bytes(data[12:])
    for hit in magic_hits:
        hit["offset"] += 12  # adjust for skipped header
        finding(
            f"Executable signature found: '{hit['signature']}' "
            f"at offset {hit['offset']} (magic={hit['magic_hex']})"
        )

    # 3. High-entropy regions
    high_e = scan_high_entropy_regions(data)
    if len(high_e) > 5:
        warn(
            f"{len(high_e)} high-entropy blocks (>=7.8 bits/byte) detected — "
            "possible encrypted/compressed payload"
        )
        info(f"First high-entropy block: offset={high_e[0]['offset']}, entropy={high_e[0]['entropy']}")
    elif high_e:
        info(f"{len(high_e)} high-entropy block(s) found (may be normal for compressed images)")

    # 4. LSB analysis
    pixel_bytes = extract_pixel_bytes(data, fmt)
    if pixel_bytes and len(pixel_bytes) >= 512:
        chi2 = lsb_chi_square(pixel_bytes)
        if chi2 < 0.5:
            finding(
                f"LSB distribution is suspiciously uniform (chi²={chi2}) — "
                "consistent with LSB steganography"
            )
        else:
            info(f"LSB chi-square={chi2} (no strong LSB stego signal)")

    # 5. Metadata
    meta = extract_metadata(data, fmt)
    for key, val in meta.items():
        info(f"Metadata [{key}]: {val[:120]}")

    # 6. ZIP/APK embedded (common Android attack vector)
    if data[12:].find(b"PK\x03\x04") != -1:
        finding("ZIP/APK archive signature found inside file body — high suspicion")

    # 7. Overall entropy verdict
    if report["overall_entropy"] > 7.9:
        warn(f"Overall file entropy is very high ({report['overall_entropy']}) — may contain encrypted data")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_report(report: dict):
    sep = "-" * 60
    print(sep)
    print(f"File    : {report['file']}")
    print(f"Format  : {report['format'].upper()}")
    print(f"Size    : {report['size_bytes']} bytes")
    print(f"Entropy : {report['overall_entropy']} bits/byte")
    print(sep)

    if report["findings"]:
        print("\n[!] FINDINGS (suspicious):")
        for f in report["findings"]:
            print(f"    • {f}")
    else:
        print("\n[✓] No payload signatures detected.")

    if report["warnings"]:
        print("\n[~] WARNINGS:")
        for w in report["warnings"]:
            print(f"    • {w}")

    if report["info"]:
        print("\n[i] INFO:")
        for i in report["info"]:
            print(f"    • {i}")

    verdict = "CLEAN" if not report["findings"] else "SUSPICIOUS"
    print(f"\nVerdict: {verdict}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Detect hidden payloads in WhatsApp sticker files (WebP/PNG/JPEG)."
    )
    parser.add_argument("files", nargs="+", help="Sticker image file(s) to analyze")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    if args.json:
        import json
        results = [analyze_file(f) for f in args.files]
        print(json.dumps(results, indent=2))
    else:
        for path in args.files:
            try:
                report = analyze_file(path)
                print_report(report)
            except FileNotFoundError:
                print(f"ERROR: File not found: {path}")
            except Exception as e:
                print(f"ERROR analyzing {path}: {e}")


if __name__ == "__main__":
    main()
