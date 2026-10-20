
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from monitor import FileGuardMonitor, calculate_hash


def test_sha256():
    expected = hashlib.sha256(b"FileGuard").hexdigest()

    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        file = Path(folder) / "test.txt"
        file.write_text("FileGuard", encoding="utf-8")

        assert calculate_hash(file) == expected


def test_hash_changes(tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("Original", encoding="utf-8")

    first = calculate_hash(file)

    file.write_text("Modified", encoding="utf-8")

    assert calculate_hash(file) != first


def test_snapshot(tmp_path):
    file = tmp_path / "sample.txt"
    file.write_text("Test", encoding="utf-8")

    monitor = FileGuardMonitor(tmp_path)

    assert str(file) in monitor.snapshot()
