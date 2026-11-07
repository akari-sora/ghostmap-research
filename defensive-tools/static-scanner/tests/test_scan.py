import importlib.util
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


SCANNER = Path(__file__).resolve().parents[1] / "ghostmap_audit.py"
spec = importlib.util.spec_from_file_location("ghostmap_audit", SCANNER)
scanner = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = scanner
spec.loader.exec_module(scanner)


class ScannerTests(unittest.TestCase):
    def test_local_central_filename_mismatch_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mismatch.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("good.txt", "ordinary content")
            data = bytearray(path.read_bytes())
            self.assertEqual(data[:4], b"PK\x03\x04")
            data[30:38] = b"evil.txt"
            path.write_bytes(data)

            result = scanner.audit(path)
            self.assertEqual(result["status"], "review_required")
            self.assertIn("LOCAL_CENTRAL_NAME_MISMATCH",
                          result["findings"][0]["issues"])

    def test_entry_limit_is_checked_before_zipfile_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "count.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("one.txt", "ordinary content")
            data = bytearray(path.read_bytes())
            end = data.rfind(b"PK\x05\x06")
            struct.pack_into("<H", data, end + 8, 2)
            struct.pack_into("<H", data, end + 10, 2)
            path.write_bytes(data)

            with mock.patch.object(scanner.zipfile, "ZipFile",
                                   side_effect=AssertionError("ZipFile called")):
                with self.assertRaisesRegex(ValueError, "max entries"):
                    scanner.audit(path, max_entries=1)

    def test_directory_size_is_checked_before_zipfile_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "directory.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("one.txt", "ordinary content")
            data = bytearray(path.read_bytes())
            end = data.rfind(b"PK\x05\x06")
            struct.pack_into("<I", data, end + 12, 65 * 1024 * 1024)
            path.write_bytes(data)

            with mock.patch.object(scanner.zipfile, "ZipFile",
                                   side_effect=AssertionError("ZipFile called")):
                with self.assertRaisesRegex(ValueError, "central directory"):
                    scanner.audit(path)

    def test_actual_entry_count_is_checked_before_zipfile_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "understated-count.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("one.txt", "one")
                archive.writestr("two.txt", "two")
            data = bytearray(path.read_bytes())
            end = data.rfind(b"PK\x05\x06")
            struct.pack_into("<H", data, end + 8, 1)
            struct.pack_into("<H", data, end + 10, 1)
            path.write_bytes(data)

            with mock.patch.object(scanner.zipfile, "ZipFile",
                                   side_effect=AssertionError("ZipFile called")):
                with self.assertRaisesRegex(ValueError, "max entries"):
                    scanner.audit(path, max_entries=1)

    def test_zip64_locator_is_rejected_before_zipfile_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zip64-locator.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("one.txt", "ordinary content")
            data = bytearray(path.read_bytes())
            end = data.rfind(b"PK\x05\x06")
            data[end:end] = b"PK\x06\x07" + bytes(16)
            path.write_bytes(data)

            with mock.patch.object(scanner.zipfile, "ZipFile",
                                   side_effect=AssertionError("ZipFile called")):
                with self.assertRaisesRegex(ValueError, "ZIP64"):
                    scanner.audit(path)

    def test_benign_zip_has_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "benign.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("readme.txt", "ordinary content")
            result = scanner.audit(path)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["entries_checked"], 1)
            self.assertEqual(result["findings"], [])

    def test_non_zip_input_is_not_reported_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "not-an-apk.apk"
            path.write_bytes(b"not a ZIP")
            with self.assertRaises(zipfile.BadZipFile):
                scanner.audit(path)


if __name__ == "__main__":
    unittest.main()
