import struct
import tempfile
import unittest
from pathlib import Path

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import toolkit


def make_bmp(payload: bytes, height: int = 1) -> bytes:
    encoded_bits = [
        (value >> bit) & 1
        for value in payload
        for bit in range(7, -1, -1)
    ]
    pixel_count = max((len(encoded_bits) + 2) // 3, 1)
    width = (pixel_count + height - 1) // height
    row_stride = (width * 3 + 3) & ~3
    pixels = bytearray(row_stride * height)
    for index, bit in enumerate(encoded_bits):
        visual_pixel = index // 3
        visual_row, column = divmod(visual_pixel, width)
        stored_row = height - 1 - visual_row
        channel = (2, 1, 0)[index % 3]
        pixels[stored_row * row_stride + column * 3 + channel] |= bit

    file_size = 54 + len(pixels)
    header = struct.pack(
        "<2sIHHI",
        b"BM",
        file_size,
        0,
        0,
        54,
    )
    dib_header = struct.pack(
        "<IiiHHIIiiII",
        40,
        width,
        height,
        1,
        24,
        0,
        len(pixels),
        2835,
        2835,
        0,
        0,
    )
    return header + dib_header + pixels


class EncodingTests(unittest.TestCase):
    def test_base64_and_hex_round_trip(self):
        text = "Hello, 世界!"
        self.assertEqual(text.encode("utf-8"), toolkit.decode_base64(toolkit.encode_base64(text)))
        self.assertEqual(text.encode("utf-8"), toolkit.decode_hex(toolkit.encode_hex(text)))

    def test_invalid_encodings_are_reported(self):
        with self.assertRaisesRegex(toolkit.ToolkitError, "Invalid Base64"):
            toolkit.decode_base64("not base64!")
        with self.assertRaisesRegex(toolkit.ToolkitError, "Invalid hexadecimal"):
            toolkit.decode_hex("xyz")

    def test_rot13_preserves_case_and_punctuation(self):
        self.assertEqual("Uryyb, Jbeyq!", toolkit.rot13("Hello, World!"))
        self.assertEqual("Hello, World!", toolkit.rot13("Uryyb, Jbeyq!"))


class CipherTests(unittest.TestCase):
    def test_caesar_and_all_shifts(self):
        self.assertEqual("Khoor, Zruog!", toolkit.caesar("Hello, World!", 3))
        self.assertEqual("Hello, World!", toolkit.caesar("Khoor, Zruog!", -3))
        candidates = toolkit.solve_caesar("Khoor")
        self.assertEqual(26, len(candidates))
        self.assertEqual((23, "Hello"), candidates[23])

    def test_vigenere_round_trip_preserves_nonletters(self):
        encoded = toolkit.vigenere("Attack at dawn!", "LEMON")
        self.assertEqual("Lxfopv ef rnhr!", encoded)
        self.assertEqual(
            "Attack at dawn!",
            toolkit.vigenere(encoded, "LEMON", decode=True),
        )

    def test_vigenere_rejects_empty_or_non_ascii_keys(self):
        for key in ("", "key 1", "clé"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(toolkit.ToolkitError, "ASCII letters"):
                    toolkit.vigenere("text", key)


class SteganographyTests(unittest.TestCase):
    def test_extracts_lsb_payload_from_24_bit_bmp(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "hidden.bmp"
            path.write_bytes(make_bmp(b"Hi!\0"))
            self.assertEqual(b"Hi!", toolkit.extract_bmp_lsb(path))

    def test_extracts_payload_in_visual_order_from_multrow_bmp(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "hidden.bmp"
            path.write_bytes(make_bmp(b"Top to bottom\0", height=2))
            self.assertEqual(b"Top to bottom", toolkit.extract_bmp_lsb(path))

    def test_rejects_unsupported_and_truncated_images(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "image.bmp"
            path.write_bytes(b"not an image")
            with self.assertRaisesRegex(toolkit.ToolkitError, "Windows BMP"):
                toolkit.extract_bmp_lsb(path)

            path.write_bytes(make_bmp(b"ok\0")[:-1])
            with self.assertRaisesRegex(toolkit.ToolkitError, "truncated"):
                toolkit.extract_bmp_lsb(path)


class SourceScannerTests(unittest.TestCase):
    def test_finds_risky_patterns_in_source_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "example.py"
            source.write_text(
                "eval(user_input)\nos.system(command)\n"
                "subprocess.run(command, shell=True)\n",
                encoding="utf-8",
            )
            (root / "notes.txt").write_text("eval(not_source)", encoding="utf-8")
            (root / "venv").mkdir()
            (root / "venv" / "ignored.py").write_text(
                "eval(ignored)", encoding="utf-8"
            )

            findings = toolkit.scan_source(root)
            self.assertEqual(
                [
                    "Dynamic code execution",
                    "OS command execution",
                    "Subprocess with shell enabled",
                ],
                [finding["pattern"] for finding in findings],
            )
            self.assertEqual([1, 2, 3], [finding["line"] for finding in findings])

    def test_reports_missing_path(self):
        with self.assertRaisesRegex(toolkit.ToolkitError, "does not exist"):
            toolkit.scan_source(Path("missing-source-directory"))


class MenuTests(unittest.TestCase):
    def test_menu_exits_cleanly(self):
        output = []
        choices = iter(["0"])
        self.assertEqual(0, toolkit.run_menu(lambda _: next(choices), output.append))
        self.assertIn("Goodbye.", output)


if __name__ == "__main__":
    unittest.main()
