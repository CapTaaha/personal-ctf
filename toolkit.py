#!/usr/bin/env python3
"""Menu-driven, dependency-free utilities for authorized labs and CTF practice."""

from __future__ import annotations

import base64
import binascii
import re
import struct
import sys
from pathlib import Path
from typing import Callable

import hash_identifier
import log_analyzer


SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".php",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".ts",
    ".tsx",
}
SKIPPED_DIRECTORIES = {".git", ".venv", "__pycache__", "node_modules", "venv"}
SCAN_PATTERNS = (
    ("Dynamic code execution", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("OS command execution", re.compile(r"\bos\s*\.\s*system\s*\(")),
    ("Subprocess with shell enabled", re.compile(r"\bshell\s*=\s*True\b")),
)


class ToolkitError(Exception):
    """An expected input error suitable for display in the CLI."""


def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ToolkitError(f"Invalid Base64 input: {exc}") from exc


def encode_hex(text: str) -> str:
    return text.encode("utf-8").hex()


def decode_hex(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ToolkitError(f"Invalid hexadecimal input: {exc}") from exc


def rot13(text: str) -> str:
    """Apply ROT13 to ASCII letters, preserving case and other characters."""
    result: list[str] = []
    for character in text:
        if "a" <= character <= "z":
            result.append(chr((ord(character) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= character <= "Z":
            result.append(chr((ord(character) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(character)
    return "".join(result)


def caesar(text: str, shift: int) -> str:
    """Shift ASCII letters while preserving case and non-letter characters."""
    result: list[str] = []
    for character in text:
        if "a" <= character <= "z":
            result.append(chr((ord(character) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= character <= "Z":
            result.append(chr((ord(character) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(character)
    return "".join(result)


def solve_caesar(text: str) -> list[tuple[int, str]]:
    """Return all Caesar shifts, with the candidate shift shown explicitly."""
    return [(shift, caesar(text, shift)) for shift in range(26)]


def vigenere(text: str, key: str, *, decode: bool = False) -> str:
    """Encode or decode ASCII text with a Vigenere key."""
    if not key or re.fullmatch(r"[A-Za-z]+", key) is None:
        raise ToolkitError("The Vigenere key must contain ASCII letters only")

    shifts = [ord(character.lower()) - ord("a") for character in key]
    direction = -1 if decode else 1
    result: list[str] = []
    key_index = 0
    for character in text:
        if "a" <= character <= "z":
            offset = ord("a")
        elif "A" <= character <= "Z":
            offset = ord("A")
        else:
            result.append(character)
            continue
        shift = shifts[key_index % len(shifts)] * direction
        result.append(chr((ord(character) - offset + shift) % 26 + offset))
        key_index += 1
    return "".join(result)


def extract_bmp_lsb(path: Path) -> bytes:
    """Extract one MSB-first bit per RGB color channel from an uncompressed BMP."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ToolkitError(f"Could not read image {path}: {exc}") from exc

    if len(data) < 54 or data[:2] != b"BM":
        raise ToolkitError("Unsupported image: expected a Windows BMP file")

    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    dib_size = struct.unpack_from("<I", data, 14)[0]
    if dib_size < 40 or len(data) < 14 + dib_size:
        raise ToolkitError("Unsupported BMP: expected an INFOHEADER or newer header")
    width, signed_height, planes, bits_per_pixel = struct.unpack_from(
        "<iiHH", data, 18
    )
    compression = struct.unpack_from("<I", data, 30)[0]
    if width <= 0 or signed_height == 0 or planes != 1:
        raise ToolkitError("Invalid BMP dimensions or plane count")
    if bits_per_pixel not in (24, 32) or compression != 0:
        raise ToolkitError("Unsupported BMP: use an uncompressed 24-bit or 32-bit image")

    height = abs(signed_height)
    bytes_per_pixel = bits_per_pixel // 8
    row_stride = (width * bytes_per_pixel + 3) & ~3
    pixel_end = pixel_offset + row_stride * height
    if pixel_offset < 14 + dib_size or pixel_end > len(data):
        raise ToolkitError("Invalid or truncated BMP pixel data")

    bits: list[int] = []
    for row in range(height):
        stored_row = height - 1 - row if signed_height > 0 else row
        row_start = pixel_offset + stored_row * row_stride
        for column in range(width):
            pixel_start = row_start + column * bytes_per_pixel
            for channel in (2, 1, 0):
                bits.append(data[pixel_start + channel] & 1)

    payload = bytearray()
    for start in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[start : start + 8]:
            value = (value << 1) | bit
        if value == 0:
            break
        payload.append(value)
    return bytes(payload)


def scan_source(path: Path) -> list[dict[str, str | int]]:
    """Find selected risky source-code patterns in a file or source directory."""
    if not path.exists():
        raise ToolkitError(f"Path does not exist: {path}")
    if not path.is_file() and not path.is_dir():
        raise ToolkitError(f"Path is not a file or directory: {path}")

    if path.is_file():
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            raise ToolkitError(
                f"Unsupported source file type {path.suffix or '(no extension)'}"
            )
        candidates = [path]
    else:
        candidates = [
            candidate
            for candidate in path.rglob("*")
            if candidate.is_file()
            and candidate.suffix.lower() in SOURCE_EXTENSIONS
            and not any(part in SKIPPED_DIRECTORIES for part in candidate.parts)
        ]

    findings: list[dict[str, str | int]] = []
    for candidate in sorted(candidates):
        if candidate.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise ToolkitError(f"Could not read source file {candidate}: {exc}") from exc
        for line_number, line in enumerate(lines, start=1):
            for description, pattern in SCAN_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {
                            "file": str(candidate),
                            "line": line_number,
                            "pattern": description,
                            "source": line.strip(),
                        }
                    )
    return findings


def _show_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return f"Non-text data (hex): {data.hex()}"


def _read_file(path_text: str) -> str:
    path = Path(path_text)
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ToolkitError(f"Could not read {path}: {exc}") from exc


def _encoding_menu(input_fn: Callable[[str], str]) -> None:
    print("\nEncoding")
    print("1. Encode Base64")
    print("2. Decode Base64")
    print("3. Encode hexadecimal")
    print("4. Decode hexadecimal")
    print("5. Apply ROT13")
    choice = input_fn("Select an operation: ").strip()
    if choice == "5":
        print(rot13(input_fn("Text: ")))
        return
    text = input_fn("Input: ")
    if choice == "1":
        print(encode_base64(text))
    elif choice == "2":
        print(_show_bytes(decode_base64(text)))
    elif choice == "3":
        print(encode_hex(text))
    elif choice == "4":
        print(_show_bytes(decode_hex(text)))
    else:
        raise ToolkitError("Choose a listed encoding operation")


def _cipher_menu(input_fn: Callable[[str], str]) -> None:
    print("\nCiphers")
    print("1. Encode with Caesar")
    print("2. Decode with Caesar")
    print("3. Try all Caesar shifts")
    print("4. Encode with Vigenere")
    print("5. Decode with Vigenere")
    choice = input_fn("Select an operation: ").strip()
    text = input_fn("Text: ")
    if choice in {"1", "2"}:
        try:
            shift = int(input_fn("Shift (integer): "))
        except ValueError as exc:
            raise ToolkitError("Caesar shift must be an integer") from exc
        print(caesar(text, shift if choice == "1" else -shift))
    elif choice == "3":
        for shift, candidate in solve_caesar(text):
            print(f"{shift:2}: {candidate}")
    elif choice in {"4", "5"}:
        key = input_fn("Key (letters only): ")
        print(vigenere(text, key, decode=choice == "5"))
    else:
        raise ToolkitError("Choose a listed cipher operation")


def _log_analysis(input_fn: Callable[[str], str]) -> None:
    path_text = input_fn("Log file path: ").strip()
    path = Path(path_text)
    events = log_analyzer.parse_logs(_read_file(path_text), str(path))
    print(log_analyzer.render_text(log_analyzer.analyze_events(events)), end="")


def run_menu(
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> int:
    while True:
        output_fn("\nSwiss Army Knife CLI Toolkit")
        output_fn("1. Encode / decode (Base64, hex, ROT13)")
        output_fn("2. Caesar / Vigenere ciphers")
        output_fn("3. Extract LSB data from a BMP image")
        output_fn("4. Scan local source for risky code patterns")
        output_fn("5. Identify a likely hash format")
        output_fn("6. Analyze a local log file")
        output_fn("0. Exit")
        choice = input_fn("Select a utility: ").strip()

        try:
            if choice == "0":
                output_fn("Goodbye.")
                return 0
            if choice == "1":
                _encoding_menu(input_fn)
            elif choice == "2":
                _cipher_menu(input_fn)
            elif choice == "3":
                path = Path(input_fn("BMP image path: ").strip())
                payload = extract_bmp_lsb(path)
                output_fn(_show_bytes(payload) if payload else "No text payload found.")
            elif choice == "4":
                path = Path(input_fn("Source file or directory: ").strip())
                findings = scan_source(path)
                if not findings:
                    output_fn("No configured patterns found.")
                else:
                    for finding in findings:
                        output_fn(
                            f"{finding['file']}:{finding['line']}: "
                            f"{finding['pattern']} — {finding['source']}"
                        )
                output_fn(
                    "Pattern matches are triage hints, not proof of a vulnerability."
                )
            elif choice == "5":
                value = input_fn("Hash or encoded value: ")
                for candidate in hash_identifier.identify(value):
                    output_fn(f"- {candidate}")
                output_fn(
                    "Format and length are clues, not proof; several algorithms "
                    "share them."
                )
            elif choice == "6":
                _log_analysis(input_fn)
            else:
                raise ToolkitError("Choose one of the listed utilities")
        except ToolkitError as exc:
            output_fn(f"Error: {exc}")


def main() -> int:
    try:
        return run_menu()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
