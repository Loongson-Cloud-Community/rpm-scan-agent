"""The event identity, RPM metadata and scanner must refer to the same bytes."""

import hashlib
import json
import os
from pathlib import Path
import signal
import unittest

import test_scan_process as support


class InputSnapshotTests(support.ScanTestCase):
    def read_input(self, phase):
        return json.loads((self.root / f"{phase}-input.json").read_text())

    def test_metadata_and_scanner_use_the_same_private_copy(self):
        proc = self.start()
        _, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 0, stderr)
        query = self.read_input("query")
        scanned = self.read_input("scanner")
        self.assertEqual(query, scanned)
        self.assertNotEqual(Path(scanned["path"]), self.source)
        self.assertEqual(Path(scanned["path"]).name, self.source.name)
        self.assertEqual(scanned["sha256"], self.env["CURRENT_RPM_SHA256"])
        self.assertFalse(Path(scanned["path"]).exists(), "private input leaked after success")
        manifest = json.loads((self.output / "scan-manifest.json").read_text())
        self.assertEqual(manifest["rpm"]["sha256"], scanned["sha256"])
        self.assertEqual(manifest["rpm"]["size_bytes"], len(b"test package"))
        self.assertEqual(manifest["rpm"]["filename"], self.source.name)
        self.assertEqual(len(list(self.output.iterdir())), 5, "input must not be archived as a report")

    def test_replacing_original_after_metadata_does_not_change_scanned_bytes(self):
        proc = self.start(TEST_REPLACE_SOURCE="1")
        _, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 0, stderr)
        self.assertEqual(self.source.read_bytes(), b"replacement package")
        self.assertEqual(self.read_input("query"), self.read_input("scanner"))
        self.assertEqual(self.read_input("scanner")["sha256"], self.env["CURRENT_RPM_SHA256"])

    def test_replaced_input_is_rejected_before_query_or_scan(self):
        self.source.write_bytes(b"replacement before scanning")
        proc = self.start()
        _, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("SHA256", stderr)
        self.assertFalse((self.root / "queried").exists())
        self.assertFalse(self.output.exists())

    def test_expected_hash_is_required_and_validated(self):
        for value in ("", "a" * 63, "z" * 64, "0" * 65, "a" * 64 + "\n"):
            with self.subTest(value=value):
                proc = self.start(CURRENT_RPM_SHA256=value)
                _, stderr = proc.communicate(timeout=8)
                self.assertEqual(proc.returncode, 2, stderr)
                self.assertFalse((self.root / "queried").exists())

    def test_empty_input_is_rejected_even_with_a_matching_hash(self):
        self.source.write_bytes(b"")
        proc = self.start(CURRENT_RPM_SHA256=hashlib.sha256(b"").hexdigest())
        proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse((self.root / "queried").exists())

    def test_input_symlink_is_rejected(self):
        target = self.root / "another.rpm"
        target.write_bytes(self.source.read_bytes())
        self.source.unlink()
        self.source.symlink_to(target)
        proc = self.start()
        proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse((self.root / "queried").exists())

    def test_input_fifo_is_rejected_without_blocking(self):
        self.source.unlink()
        os.mkfifo(self.source)
        proc = self.start()
        proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse((self.root / "queried").exists())

    def test_private_copy_is_removed_on_scanner_failure(self):
        proc = self.start(TEST_EXIT="2")
        proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(Path(self.read_input("scanner")["path"]).exists())

    def test_private_copy_is_removed_on_cancellation(self):
        proc = self.start(TEST_MODE="running")
        self.wait_for(self.root / "pids.json")
        snapshot = Path(self.read_input("scanner")["path"])
        self.assertTrue(snapshot.exists())
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=9)
        self.assertEqual(proc.returncode, 143)
        self.assertFalse(snapshot.exists())
        self.assertTrue(self.source.exists(), "cleanup must not delete the original input")


if __name__ == "__main__":
    unittest.main()
