#!/usr/bin/env python3
"""Suggest likely hash formats from their textual representation."""

import argparse
import re
import sys


HEX_LENGTHS = {
    32: ("MD5", "MD4", "NTLM"),
    40: ("SHA-1", "RIPEMD-160"),
    56: ("SHA-224",),
    64: ("SHA-256", "SHA3-256", "BLAKE2s-256"),
    96: ("SHA-384", "SHA3-384"),
    128: ("SHA-512", "SHA3-512", "BLAKE2b-512"),
}


def identify(value: str) -> list[str]:
    """Return possible formats based on common prefixes and encoded lengths."""
    value = value.strip()
    if not value:
        return ["No input provided"]

    prefixes = {
        "$2a$": "bcrypt",
        "$2b$": "bcrypt",
        "$2y$": "bcrypt",
        "$argon2id$": "Argon2id",
        "$argon2i$": "Argon2i",
        "$argon2d$": "Argon2d",
        "$scrypt$": "scrypt (modular crypt format)",
        "pbkdf2_sha256$": "Django PBKDF2-SHA256",
        "pbkdf2_sha1$": "Django PBKDF2-SHA1",
        "sha1$": "Django salted SHA-1",
        "md5$": "Django salted MD5",
        "{SHA}": "LDAP SHA-1 (Base64-encoded)",
        "{SSHA}": "LDAP salted SHA-1 (Base64-encoded)",
        "$1$": "md5crypt",
        "$5$": "sha256crypt",
        "$6$": "sha512crypt",
    }
    for prefix, format_name in prefixes.items():
        if value.startswith(prefix):
            return [format_name]
    if value.startswith("$pbkdf2-"):
        return ["PBKDF2 (modular crypt format)"]

    if re.fullmatch(r"[0-9a-fA-F]+", value):
        candidates = HEX_LENGTHS.get(len(value))
        if candidates:
            return list(candidates)
        if len(value) % 2 == 0:
            return [f"Hexadecimal digest of {len(value) // 2} bytes (algorithm unknown)"]
        return ["Hexadecimal-looking string; length is not a common digest length"]

    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value) and len(value) % 4 == 0:
        return [
            "Base64-encoded data; it may be a digest, but encoding alone "
            "cannot identify it"
        ]

    return ["Unrecognized format; it may be encoded, salted, truncated, or not a hash"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Suggest likely hash formats from a hash string."
    )
    parser.add_argument("value", nargs="?", help="Hash or encoded value to inspect")
    args = parser.parse_args()

    value = args.value
    if value is None:
        value = input("Hash: ")

    print("Possible format(s):")
    for candidate in identify(value):
        print(f"- {candidate}")
    print("Note: format and length are clues, not proof; several algorithms share them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
