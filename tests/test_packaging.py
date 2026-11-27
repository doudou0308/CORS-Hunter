"""Check JAR packaging independently of Java or the Burp API."""
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from build import package_jar


class JarPackagingTests(unittest.TestCase):
    def test_identical_classes_produce_identical_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classes = root / "classes"
            files = {
                "hunter/Z.class": b"example-z",
                "hunter/A.class": b"example-a",
                "burp/BurpExtender.class": b"example-entry",
                "tests/RegressionTest.class": b"excluded",
            }
            for name, data in files.items():
                file = classes / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(data)

            first = root / "first.jar"
            second = root / "second.jar"
            package_jar(classes, first)
            for name in files:
                os.utime(classes / name, (1700000000, 1700000000))
            package_jar(classes, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(second) as archive:
                self.assertEqual(archive.namelist(), [
                    "META-INF/MANIFEST.MF",
                    "burp/BurpExtender.class",
                    "hunter/A.class",
                    "hunter/Z.class",
                ])
                self.assertEqual(archive.read("hunter/A.class"), b"example-a")
                self.assertIn(b"Implementation-Version: 1.0.1",
                              archive.read("META-INF/MANIFEST.MF"))
                for entry in archive.infolist():
                    self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
