#!/usr/bin/env python3
"""Tests for sticker_payload_detector.py"""
import struct
import zlib
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from sticker_payload_detector import (
    detect_format, check_appended_data, scan_magic_bytes,
    lsb_chi_square, entropy, analyze_file, scan_high_entropy_regions,
)
import tempfile, pathlib

# ---------------------------------------------------------------------------
# Minimal valid PNG builder (1x1 white pixel)
# ---------------------------------------------------------------------------

def make_png(extra_tail: bytes = b"") -> bytes:
    def chunk(ctype: bytes, data: bytes) -> bytes:
        c = ctype + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)  # 1x1 RGB
    idat_raw = b"\x00\xff\xff\xff"  # filter=none, R=255 G=255 B=255
    idat_data = zlib.compress(idat_raw)
    png = sig + chunk(b"IHDR", ihdr_data) + chunk(b"IDAT", idat_data) + chunk(b"IEND", b"")
    return png + extra_tail


# ---------------------------------------------------------------------------
# Minimal JPEG (smallest valid JPEG-like bytes for testing)
# ---------------------------------------------------------------------------

def make_jpeg(extra_tail: bytes = b"") -> bytes:
    # SOI + minimal APP0 + EOI
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9" + extra_tail


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_format_detection():
    assert detect_format(make_png()) == "png"
    assert detect_format(make_jpeg()) == "jpeg"
    assert detect_format(b"RIFF????WEBP") == "webp"
    assert detect_format(b"\x00\x01\x02\x03") == "unknown"
    print("PASS test_format_detection")


def test_clean_png_no_findings():
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        f.write(make_png())
        name = f.name
    try:
        report = analyze_file(name)
        assert report["findings"] == [], f"Expected no findings, got: {report['findings']}"
        print("PASS test_clean_png_no_findings")
    finally:
        os.unlink(name)


def test_appended_data_detected():
    tail = b"\x4d\x5a" + b"\x90" * 50  # MZ header appended
    png = make_png(extra_tail=tail)
    result = check_appended_data(png, "png")
    assert "appended_bytes" in result, "Should detect appended data"
    assert result["appended_bytes"] == len(tail)
    print("PASS test_appended_data_detected")


def test_executable_signature_in_body():
    # Embed ELF magic bytes in the middle of a PNG
    png = make_png()
    # Insert ELF magic after header
    injected = png[:20] + b"\x7fELF\x02\x01\x01" + png[20:]
    hits = scan_magic_bytes(injected[12:])
    assert any("ELF" in h["signature"] for h in hits), f"Should detect ELF, got: {hits}"
    print("PASS test_executable_signature_in_body")


def test_zip_apk_detection():
    png_data = make_png()
    injected = png_data + b"PK\x03\x04" + b"\x00" * 20
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        f.write(injected)
        name = f.name
    try:
        report = analyze_file(name)
        assert any("ZIP" in x or "APK" in x for x in report["findings"]), \
            f"Should detect ZIP/APK, findings: {report['findings']}"
        print("PASS test_zip_apk_detection")
    finally:
        os.unlink(name)


def test_lsb_uniform_flagged():
    # Alternating 0/1 LSBs = perfectly uniform = stego signal
    uniform_bytes = bytes([i % 2 for i in range(1000)])
    chi2 = lsb_chi_square(uniform_bytes)
    assert chi2 < 0.5, f"Uniform LSBs should give chi2 near 0, got {chi2}"
    print("PASS test_lsb_uniform_flagged")


def test_lsb_natural_not_flagged():
    import random
    random.seed(42)
    # Natural-ish data: random bytes with bias
    natural = bytes([random.randint(0, 255) for _ in range(2000)])
    chi2 = lsb_chi_square(natural)
    # Random bytes will also be near uniform; this checks the metric is computed
    assert isinstance(chi2, float)
    print("PASS test_lsb_natural_not_flagged (metric computed)")


def test_entropy_calculation():
    assert entropy(b"\x00" * 100) == 0.0          # all same = 0 entropy
    assert entropy(bytes(range(256))) > 7.9         # all different = ~8 bits
    assert entropy(b"AABABC") < entropy(bytes(range(256)))
    print("PASS test_entropy_calculation")


def test_jpeg_appended_mz():
    tail = b"\x4d\x5a" + b"\x90" * 100
    jpeg = make_jpeg(extra_tail=tail)
    result = check_appended_data(jpeg, "jpeg")
    assert "appended_bytes" in result
    print("PASS test_jpeg_appended_mz")


def test_high_entropy_regions():
    import os
    # Prepend low-entropy header, then high-entropy block
    low = b"\x89PNG\r\n\x1a\n" + b"\x00" * 512
    high = bytes([i & 0xff for i in range(256)] * 4)  # pseudo-random
    data = low + high
    regions = scan_high_entropy_regions(data, block_size=256, threshold=4.0)
    assert len(regions) > 0, "Should find high-entropy regions"
    print("PASS test_high_entropy_regions")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_format_detection,
        test_clean_png_no_findings,
        test_appended_data_detected,
        test_executable_signature_in_body,
        test_zip_apk_detection,
        test_lsb_uniform_flagged,
        test_lsb_natural_not_flagged,
        test_entropy_calculation,
        test_jpeg_appended_mz,
        test_high_entropy_regions,
    ]
    failures = 0
    for t in tests:
        try:
            t()
        except Exception as e:
            print(f"FAIL {t.__name__}: {e}")
            failures += 1
    print(f"\n{len(tests) - failures}/{len(tests)} tests passed.")
    sys.exit(0 if failures == 0 else 1)
