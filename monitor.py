
import csv
import hashlib
import json
import logging
import os
import threading
import time

from datetime import datetime, timezone
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"

LOG_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=str(LOG_DIR / "fileguard.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

EVENTS = {
    "FILE CREATED": "LOW",
    "FILE MODIFIED": "MEDIUM",
    "FILE DELETED": "HIGH",
    "FILE MOVED": "MEDIUM",
    "FILE RESTORED": "LOW",
    "FILE TAMPERED": "HIGH",
    "BASELINE CHANGED": "HIGH",
}


def calculate_hash(path):
    sha = hashlib.sha256()

    try:
        with open(path, "rb") as f:
            for chunk in iter(
                lambda: f.read(1024 * 1024), b""
            ):
                sha.update(chunk)
        return sha.hexdigest()
    except OSError:
        return None


class ChangeHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor

    def on_any_event(self, event):
        self.monitor.wakeup.set()


class FileGuardMonitor:
    def __init__(self, folder_path, callback=None):
        self.folder_path = Path(folder_path).resolve()
        self.callback = callback

        self.lock = threading.RLock()
        self.wakeup = threading.Event()
        self.shutdown = threading.Event()

        self.observer = None
        self.worker = None
        self.running = False

        self.baseline = {}
        self.last_state = {}
        self.event_history = []
        self.last_alerts = {}

        folder_id = hashlib.sha256(
            str(self.folder_path).encode()
        ).hexdigest()[:16]

        self.baseline_file = (
            LOG_DIR / f"baseline_{folder_id}.json"
        )
        self.baseline_digest_file = (
            LOG_DIR / f"baseline_{folder_id}.sha256"
        )
        self.audit_file = LOG_DIR / "audit.jsonl"

    def snapshot(self):
        result = {}

        for root, dirs, files in os.walk(
            self.folder_path, followlinks=False
        ):
            dirs[:] = [
                d for d in dirs
                if not (Path(root) / d).is_symlink()
            ]

            for filename in files:
                path = Path(root) / filename

                if path.is_symlink():
                    continue

                digest = calculate_hash(path)

                if digest is not None:
                    result[str(path)] = digest

        return result

    def write_baseline(self):
        data = json.dumps(
            self.baseline,
            indent=2,
            sort_keys=True
        )

        temp = self.baseline_file.with_suffix(".tmp")
        temp.write_text(data, encoding="utf-8")
        temp.replace(self.baseline_file)

        digest = calculate_hash(self.baseline_file)

        temp_digest = self.baseline_digest_file.with_suffix(
            ".sha256.tmp"
        )
        temp_digest.write_text(
            digest + "\n", encoding="utf-8"
        )
        temp_digest.replace(self.baseline_digest_file)

    def load_baseline(self):
        if not self.baseline_file.exists():
            if self.baseline_digest_file.exists():
                raise RuntimeError(
                    "Baseline missing but checksum exists."
                )

            self.baseline = self.snapshot()
            self.write_baseline()
            return False

        if not self.baseline_digest_file.exists():
            raise RuntimeError(
                "Baseline checksum missing. "
                "Manual investigation required."
            )

        actual = calculate_hash(self.baseline_file)
        expected = self.baseline_digest_file.read_text(
            encoding="utf-8"
        ).strip()

        if actual != expected:
            raise RuntimeError(
                "Baseline integrity check failed. "
                "Do not approve until investigated."
            )

        try:
            data = json.loads(
                self.baseline_file.read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, ValueError) as error:
            raise RuntimeError(
                f"Invalid baseline: {error}"
            )

        if not isinstance(data, dict):
            raise RuntimeError("Invalid baseline format")

        self.baseline = data
        return True

    def alert(self, event_type, path):
        now = time.monotonic()
        key = (event_type, str(path))

        # Suppress repeated identical alerts for 1 second.
        if now - self.last_alerts.get(key, -100) < 1:
            return

        self.last_alerts[key] = now

        severity = EVENTS.get(event_type, "MEDIUM")

        record = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(timespec="seconds"),
            "event": event_type,
            "severity": severity,
            "path": str(path)
        }

        self.event_history.append(record)

        with open(
            self.audit_file, "a", encoding="utf-8"
        ) as f:
            f.write(json.dumps(record) + "\n")

        logging.info(
            "%s | %s | %s",
            severity, event_type, path
        )

        print(
            f"[{severity}] {event_type}: {path}"
        )

        if self.callback:
            self.callback(event_type, str(path))

    def scan(self):
        with self.lock:
            current = self.snapshot()
            old = self.last_state

            for path in sorted(set(current) - set(old)):
                if path in self.baseline:
                    self.alert("FILE RESTORED", path)
                else:
                    self.alert("FILE CREATED", path)

            for path in sorted(set(old) - set(current)):
                self.alert("FILE DELETED", path)

            for path in sorted(set(current) & set(old)):
                if current[path] != old[path]:
                    self.alert("FILE MODIFIED", path)

            # Compare the current state with trusted baseline.
            for path, digest in current.items():
                if path in self.baseline:
                    if digest != self.baseline[path]:
                        if old.get(path) == self.baseline[path]:
                            self.alert("FILE TAMPERED", path)

            self.last_state = current

    def monitor_loop(self):
        while not self.shutdown.is_set():
            self.wakeup.wait(timeout=3)
            self.wakeup.clear()

            if self.shutdown.wait(0.35):
                break

            try:
                self.scan()
            except Exception:
                logging.exception("Monitoring scan failed")

    def start(self):
        if not self.folder_path.is_dir():
            raise ValueError("Monitoring folder not found")

        if self.running:
            return

        with self.lock:
            existing = self.load_baseline()
            self.last_state = self.snapshot()

            if existing:
                for path, digest in self.last_state.items():
                    if path in self.baseline:
                        if digest != self.baseline[path]:
                            self.alert("FILE TAMPERED", path)
                    else:
                        self.alert("FILE CREATED", path)

                for path in self.baseline:
                    if path not in self.last_state:
                        self.alert("FILE DELETED", path)

        self.shutdown.clear()
        self.wakeup.clear()

        self.observer = Observer()
        self.observer.schedule(
            ChangeHandler(self),
            str(self.folder_path),
            recursive=True
        )

        self.observer.start()
        self.running = True

        self.worker = threading.Thread(
            target=self.monitor_loop,
            daemon=True
        )
        self.worker.start()

        print(f"FileGuard monitoring: {self.folder_path}")

    def stop(self):
        if not self.running:
            return

        self.shutdown.set()
        self.wakeup.set()

        self.observer.stop()
        self.observer.join()
        self.worker.join()

        self.running = False

    def approve_baseline(self):
        with self.lock:
            self.baseline = self.snapshot()
            self.last_state = dict(self.baseline)
            self.write_baseline()

    def export_csv(self):
        output = REPORT_DIR / (
            "fileguard_" +
            datetime.now().strftime(
                "%Y%m%d_%H%M%S_%f"
            ) + ".csv"
        )

        with self.lock:
            rows = list(self.event_history)

        with open(
            output, "w", newline="",
            encoding="utf-8"
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "timestamp", "event",
                    "severity", "path"
                ]
            )
            writer.writeheader()
            writer.writerows(rows)

        return str(output)


if __name__ == "__main__":
    folder = BASE_DIR / "test_folder"
    folder.mkdir(exist_ok=True)

    monitor = FileGuardMonitor(folder)

    try:
        monitor.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("Monitoring stopped.")
