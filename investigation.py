
import csv
import hashlib
import json
import os
import re
import customtkinter as ctk

from pathlib import Path
from datetime import datetime
from tkinter import filedialog, messagebox

BASE = Path(__file__).resolve().parent
LOGS = BASE / "logs"
REPORTS = BASE / "reports"
REPORTS.mkdir(exist_ok=True)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG = "#08111F"
PANEL = "#132239"
CYAN = "#00D9FF"
GREEN = "#20E3A2"
RED = "#FF6077"

LOG_PATTERN = re.compile(
    r"^(.*?) \| INFO \| "
    r"(LOW|MEDIUM|HIGH) \| "
    r"(FILE [A-Z]+) \| (.*)$"
)


def sha256_file(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(
                lambda: f.read(65536), b""
            ):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def load_history():
    events = []
    logfile = LOGS / "fileguard.log"

    if not logfile.exists():
        return events

    with open(
        logfile, encoding="utf-8", errors="replace"
    ) as f:
        for line in f:
            match = LOG_PATTERN.match(line.strip())
            if match:
                timestamp, severity, event, path = (
                    match.groups()
                )
                events.append({
                    "timestamp": timestamp,
                    "severity": severity,
                    "event": event,
                    "path": path
                })

    return events


def find_baseline(folder):
    folder = Path(folder).resolve()
    identifier = hashlib.sha256(
        str(folder).encode()
    ).hexdigest()[:16]

    return LOGS / f"baseline_{identifier}.json"


class InvestigationApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("FileGuard | SOC Investigation")
        self.geometry("1100x760")
        self.minsize(850, 600)
        self.configure(fg_color=BG)

        self.folder = ctk.StringVar(
            value=str(BASE / "test_folder")
        )
        self.query = ctk.StringVar()
        self.severity = ctk.StringVar(value="ALL")

        self.history = []
        self.results = []

        self.build_ui()
        self.refresh()

    def build_ui(self):
        ctk.CTkLabel(
            self,
            text="FILEGUARD | SOC INVESTIGATION",
            font=("Arial", 25, "bold"),
            text_color=CYAN
        ).pack(
            anchor="w", padx=25, pady=(22, 5)
        )

        ctk.CTkLabel(
            self,
            text="Event History • SHA-256 Verification "
                 "• Security Reports",
            text_color="#A5B6CF"
        ).pack(anchor="w", padx=25)

        top = ctk.CTkFrame(
            self, fg_color=PANEL
        )
        top.pack(
            fill="x", padx=25, pady=18
        )

        ctk.CTkLabel(
            top, text="INVESTIGATION DIRECTORY",
            text_color=CYAN
        ).pack(anchor="w", padx=15, pady=8)

        folder_row = ctk.CTkFrame(
            top, fg_color="transparent"
        )
        folder_row.pack(
            fill="x", padx=15, pady=(0, 12)
        )

        ctk.CTkEntry(
            folder_row,
            textvariable=self.folder,
            height=38
        ).pack(
            side="left", fill="x", expand=True
        )

        ctk.CTkButton(
            folder_row,
            text="Browse",
            width=90,
            command=self.browse
        ).pack(side="left", padx=8)

        filters = ctk.CTkFrame(
            self, fg_color=PANEL
        )
        filters.pack(
            fill="x", padx=25, pady=5
        )

        ctk.CTkEntry(
            filters,
            textvariable=self.query,
            placeholder_text="Search file or event...",
            width=310,
            height=38
        ).pack(
            side="left", padx=10, pady=12
        )

        ctk.CTkOptionMenu(
            filters,
            variable=self.severity,
            values=["ALL", "LOW", "MEDIUM", "HIGH"]
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            filters,
            text="Search",
            command=self.apply_filter
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            filters,
            text="Refresh",
            command=self.refresh
        ).pack(side="left", padx=5)

        self.summary = ctk.CTkLabel(
            self,
            text="",
            font=("Arial", 13, "bold"),
            text_color=GREEN
        )
        self.summary.pack(
            anchor="w", padx=30, pady=12
        )

        self.output = ctk.CTkTextbox(
            self,
            fg_color=PANEL,
            font=("Consolas", 12),
            wrap="word"
        )
        self.output.pack(
            fill="both", expand=True,
            padx=25, pady=8
        )

        buttons = ctk.CTkFrame(
            self, fg_color="transparent"
        )
        buttons.pack(
            fill="x", padx=25, pady=18
        )

        for title, action in [
            ("Verify Baseline", self.verify),
            ("Export CSV", self.export_csv),
            ("Export JSON", self.export_json)
        ]:
            ctk.CTkButton(
                buttons,
                text=title,
                command=action,
                height=40
            ).pack(side="left", padx=5)

    def browse(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder.set(folder)

    def display(self, text):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", text)
        self.output.configure(state="disabled")

    def refresh(self):
        self.history = load_history()
        self.apply_filter()

    def apply_filter(self):
        keyword = self.query.get().lower().strip()
        level = self.severity.get()

        self.results = [
            event for event in self.history
            if (
                level == "ALL"
                or event["severity"] == level
            )
            and (
                keyword in event["path"].lower()
                or keyword in event["event"].lower()
            )
        ]

        high = sum(
            e["severity"] == "HIGH"
            for e in self.results
        )

        self.summary.configure(
            text=(
                f"EVENTS: {len(self.results)}"
                f"     HIGH ALERTS: {high}"
            )
        )

        lines = []

        for event in reversed(self.results[-500:]):
            lines.append(
                f"[{event['timestamp']}] "
                f"[{event['severity']}] "
                f"{event['event']}\n"
                f"  {event['path']}\n"
            )

        self.display(
            "\n".join(lines)
            if lines else "No matching events."
        )

    def verify(self):
        folder = Path(self.folder.get()).resolve()

        if not folder.is_dir():
            messagebox.showerror(
                "Error", "Select a valid directory."
            )
            return

        baseline_file = find_baseline(folder)

        if not baseline_file.exists():
            messagebox.showwarning(
                "No Baseline",
                "Start FileGuard Phase 4 monitoring "
                "to create a baseline first."
            )
            return

        try:
            baseline = json.loads(
                baseline_file.read_text(
                    encoding="utf-8"
                )
            )
            if not isinstance(baseline, dict):
                raise ValueError("Invalid baseline")

        except (OSError, ValueError) as error:
            messagebox.showerror(
                "Baseline Error", str(error)
            )
            return

        current = {}

        for root, dirs, files in os.walk(
            folder, followlinks=False
        ):
            dirs[:] = [
                d for d in dirs
                if not (Path(root) / d).is_symlink()
            ]

            for name in files:
                path = Path(root) / name

                if path.is_symlink():
                    continue

                digest = sha256_file(path)
                if digest is not None:
                    current[str(path)] = digest

        lines = ["SHA-256 BASELINE VERIFICATION\n"]
        changed = 0

        for path, original in sorted(
            baseline.items()
        ):
            if path not in current:
                lines.append(
                    f"[MISSING] {path}\n"
                )
                changed += 1

            elif current[path] != original:
                lines.append(
                    f"[TAMPERED] {path}\n"
                    f"  Baseline: {original}\n"
                    f"  Current : {current[path]}\n"
                )
                changed += 1

            else:
                lines.append(
                    f"[VERIFIED] {path}\n"
                )

        for path in sorted(
            set(current) - set(baseline)
        ):
            lines.append(
                f"[NEW FILE] {path}\n"
            )
            changed += 1

        lines.insert(
            1,
            f"Detected differences: {changed}\n"
        )

        self.display("\n".join(lines))

        self.summary.configure(
            text=f"BASELINE DIFFERENCES: {changed}",
            text_color=RED if changed else GREEN
        )

    def export_data(self, format_name):
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        path = REPORTS / (
            f"investigation_{timestamp}.{format_name}"
        )

        if format_name == "json":
            path.write_text(
                json.dumps(
                    self.results, indent=2
                ),
                encoding="utf-8"
            )
        else:
            with open(
                path, "w", newline="",
                encoding="utf-8"
            ) as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=[
                        "timestamp",
                        "severity",
                        "event",
                        "path"
                    ]
                )
                writer.writeheader()
                writer.writerows(self.results)

        messagebox.showinfo(
            "Report Exported", str(path)
        )

    def export_csv(self):
        self.export_data("csv")

    def export_json(self):
        self.export_data("json")


if __name__ == "__main__":
    app = InvestigationApp()
    app.mainloop()
