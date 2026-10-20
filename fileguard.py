
import csv
import json
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from tkinter import filedialog, messagebox

import customtkinter as ctk

from monitor import FileGuardMonitor, EVENTS
from investigation import load_history, find_baseline, sha256_file

BASE = Path(__file__).resolve().parent
TEST = BASE / "test_folder"
REPORTS = BASE / "reports"
TEST.mkdir(exist_ok=True)
REPORTS.mkdir(exist_ok=True)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG = "#08111F"
PANEL = "#132239"
CYAN = "#00D9FF"
GREEN = "#20E3A2"
RED = "#FF6077"
YELLOW = "#FFCA55"
MUTED = "#A5B6CF"


class FileGuardSOC(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("FileGuard | SOC Security Dashboard")
        self.geometry("1150x790")
        self.minsize(950, 650)
        self.configure(fg_color=BG)

        self.monitor = None
        self.events = Queue()
        self.folder = ctk.StringVar(value=str(TEST))
        self.query = ctk.StringVar()
        self.severity = ctk.StringVar(value="ALL")
        self.history = []
        self.filtered = []
        self.counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

        self.build_ui()
        self.refresh_history()
        self.after(150, self.process_events)
        self.protocol("WM_DELETE_WINDOW", self.close_app)

    def label(self, parent, text, size=14, color=MUTED):
        return ctk.CTkLabel(
            parent, text=text,
            font=("Arial", size, "bold"),
            text_color=color
        )

    def button(self, parent, text, command, color="#165B9E"):
        return ctk.CTkButton(
            parent, text=text, command=command,
            fg_color=color, height=38
        )

    def build_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=25, pady=(20, 8))

        self.label(
            header, "🛡 FILEGUARD | SECURITY OPERATIONS CENTER",
            25, CYAN
        ).pack(anchor="w")

        self.status = self.label(
            header, "● OFFLINE", 14, RED
        )
        self.status.pack(anchor="w", pady=5)

        self.tabs = ctk.CTkTabview(
            self, fg_color=PANEL,
            segmented_button_selected_color="#087C67"
        )
        self.tabs.pack(
            fill="both", expand=True,
            padx=20, pady=(5, 20)
        )

        for name in [
            "Overview", "Live Monitor",
            "Investigation", "Reports"
        ]:
            self.tabs.add(name)

        self.build_overview()
        self.build_monitor()
        self.build_investigation()
        self.build_reports()

    def build_overview(self):
        tab = self.tabs.tab("Overview")

        self.label(
            tab, "SECURITY EVENT OVERVIEW", 20, CYAN
        ).pack(anchor="w", padx=15, pady=15)

        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=10)

        self.stat_labels = {}

        for level, color in [
            ("LOW", GREEN),
            ("MEDIUM", YELLOW),
            ("HIGH", RED)
        ]:
            card = ctk.CTkFrame(row, fg_color=BG)
            card.pack(
                side="left", fill="x",
                expand=True, padx=6
            )

            self.label(
                card, level + " ALERTS", 13, color
            ).pack(pady=(18, 5))

            value = self.label(card, "0", 35, color)
            value.pack(pady=(0, 18))
            self.stat_labels[level] = value

        self.label(
            tab, "RECENT SECURITY EVENTS", 16, CYAN
        ).pack(anchor="w", padx=15, pady=10)

        self.overview_box = ctk.CTkTextbox(
            tab, fg_color=BG,
            font=("Consolas", 12)
        )
        self.overview_box.pack(
            fill="both", expand=True,
            padx=15, pady=(0, 15)
        )

    def build_monitor(self):
        tab = self.tabs.tab("Live Monitor")

        self.label(
            tab, "REAL-TIME FILE MONITORING", 20, CYAN
        ).pack(anchor="w", padx=15, pady=15)

        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=10)

        self.folder_entry = ctk.CTkEntry(
            row, textvariable=self.folder, height=40
        )
        self.folder_entry.pack(
            side="left", fill="x", expand=True
        )

        self.browse_btn = self.button(
            row, "Browse", self.browse
        )
        self.browse_btn.pack(side="left", padx=8)

        controls = ctk.CTkFrame(
            tab, fg_color="transparent"
        )
        controls.pack(fill="x", padx=15, pady=10)

        self.start_btn = self.button(
            controls, "▶ START", self.start_monitor,
            "#087C67"
        )
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = self.button(
            controls, "■ STOP", self.stop_monitor,
            "#A82B45"
        )
        self.stop_btn.pack(side="left", padx=5)
        self.stop_btn.configure(state="disabled")

        self.approve_btn = self.button(
            controls, "Approve Baseline",
            self.approve_baseline
        )
        self.approve_btn.pack(side="left", padx=5)
        self.approve_btn.configure(state="disabled")

        self.label(
            tab, "LIVE SECURITY LOGS", 16, CYAN
        ).pack(anchor="w", padx=15, pady=10)

        self.live_box = ctk.CTkTextbox(
            tab, fg_color=BG,
            font=("Consolas", 12)
        )
        self.live_box.pack(
            fill="both", expand=True,
            padx=15, pady=(0, 15)
        )

    def build_investigation(self):
        tab = self.tabs.tab("Investigation")

        self.label(
            tab, "SOC EVENT INVESTIGATION", 20, CYAN
        ).pack(anchor="w", padx=15, pady=15)

        row = ctk.CTkFrame(tab, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=10)

        ctk.CTkEntry(
            row, textvariable=self.query,
            placeholder_text="Search filename or event",
            width=280, height=38
        ).pack(side="left", padx=5)

        ctk.CTkOptionMenu(
            row, variable=self.severity,
            values=["ALL", "LOW", "MEDIUM", "HIGH"]
        ).pack(side="left", padx=5)

        self.button(
            row, "Search", self.filter_history
        ).pack(side="left", padx=5)

        self.button(
            row, "Refresh", self.refresh_history
        ).pack(side="left", padx=5)

        self.button(
            tab, "Verify SHA-256 Baseline",
            self.verify_baseline, "#087C67"
        ).pack(anchor="w", padx=20, pady=8)

        self.investigation_box = ctk.CTkTextbox(
            tab, fg_color=BG,
            font=("Consolas", 12)
        )
        self.investigation_box.pack(
            fill="both", expand=True,
            padx=15, pady=15
        )

    def build_reports(self):
        tab = self.tabs.tab("Reports")

        self.label(
            tab, "SECURITY INVESTIGATION REPORTS",
            20, CYAN
        ).pack(anchor="w", padx=15, pady=20)

        self.label(
            tab,
            "Export filtered investigation events.",
            13, MUTED
        ).pack(anchor="w", padx=15)

        self.button(
            tab, "Export CSV Report",
            lambda: self.export_report("csv")
        ).pack(anchor="w", padx=15, pady=15)

        self.button(
            tab, "Export JSON Report",
            lambda: self.export_report("json")
        ).pack(anchor="w", padx=15)

        self.label(
            tab,
            "Reports folder: " + str(REPORTS),
            12, MUTED
        ).pack(anchor="w", padx=15, pady=25)

    def write_box(self, box, text, clear=False):
        box.configure(state="normal")
        if clear:
            box.delete("1.0", "end")
        box.insert("end", text + "\n")
        box.see("end")
        box.configure(state="disabled")

    def browse(self):
        path = filedialog.askdirectory()
        if path:
            self.folder.set(path)

    def receive_event(self, event, path):
        self.events.put((event, path))

    def process_events(self):
        try:
            while True:
                event, path = self.events.get_nowait()
                level = EVENTS.get(event, "MEDIUM")
                now = datetime.now().strftime("%H:%M:%S")

                line = (
                    f"[{now}] [{level}] "
                    f"{event} | {path}"
                )

                self.write_box(self.live_box, line)
                self.write_box(self.overview_box, line)

                self.counts[level] += 1
                self.stat_labels[level].configure(
                    text=str(self.counts[level])
                )
        except Empty:
            pass

        self.after(150, self.process_events)

    def start_monitor(self):
        if self.monitor is not None:
            if self.monitor.running:
                return
            self.monitor = None

        path = self.folder.get().strip()

        if not Path(path).is_dir():
            messagebox.showerror(
                "Invalid Folder",
                "Select an existing folder."
            )
            return

        try:
            monitor = FileGuardMonitor(
                path, callback=self.receive_event
            )
            monitor.start()
            self.monitor = monitor
        except Exception as error:
            messagebox.showerror(
                "Monitor Error", str(error)
            )
            return

        self.status.configure(
            text="● MONITORING ACTIVE",
            text_color=GREEN
        )
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.approve_btn.configure(state="normal")
        self.folder_entry.configure(state="disabled")
        self.browse_btn.configure(state="disabled")

        self.write_box(
            self.live_box,
            "[SYSTEM] Monitoring started: " + path
        )

    def stop_monitor(self):
        if self.monitor is None:
            return

        if self.monitor.running:
            self.monitor.stop()

        self.status.configure(
            text="● OFFLINE", text_color=RED
        )
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.approve_btn.configure(state="disabled")
        self.folder_entry.configure(state="normal")
        self.browse_btn.configure(state="normal")

        self.write_box(
            self.live_box, "[SYSTEM] Monitoring stopped."
        )

    def approve_baseline(self):
        if self.monitor is None:
            return

        if not messagebox.askyesno(
            "Approve Baseline",
            "Trust current files and replace "
            "the saved baseline?"
        ):
            return

        try:
            self.monitor.approve_baseline()
            self.write_box(
                self.live_box,
                "[SYSTEM] Baseline approved."
            )
        except Exception as error:
            messagebox.showerror(
                "Baseline Error", str(error)
            )

    def refresh_history(self):
        self.history = load_history()
        self.filter_history()

    def filter_history(self):
        query = self.query.get().lower().strip()
        level = self.severity.get()

        self.filtered = [
            event for event in self.history
            if (
                level == "ALL"
                or event["severity"] == level
            )
            and (
                query in event["path"].lower()
                or query in event["event"].lower()
            )
        ]

        lines = [
            f"[{e['timestamp']}] "
            f"[{e['severity']}] {e['event']}\n"
            f"  {e['path']}"
            for e in reversed(self.filtered[-500:])
        ]

        result = (
            f"Matching events: {len(self.filtered)}\n\n"
            + "\n\n".join(lines)
        )
        self.write_box(
            self.investigation_box,
            result, clear=True
        )

    def verify_baseline(self):
        folder = Path(self.folder.get()).resolve()

        if not folder.is_dir():
            messagebox.showerror(
                "Error", "Invalid directory."
            )
            return

        baseline_file = find_baseline(folder)

        if not baseline_file.exists():
            messagebox.showwarning(
                "No Baseline",
                "Start monitoring to create a baseline."
            )
            return

        try:
            baseline = json.loads(
                baseline_file.read_text(
                    encoding="utf-8"
                )
            )
            if not isinstance(baseline, dict):
                raise ValueError("Invalid baseline data")
        except (OSError, ValueError) as error:
            messagebox.showerror(
                "Baseline Error", str(error)
            )
            return

        current = {}
        for path in folder.rglob("*"):
            if path.is_symlink() or not path.is_file():
                continue
            digest = sha256_file(path)
            if digest is not None:
                current[str(path)] = digest

        lines = ["SHA-256 INTEGRITY VERIFICATION", ""]
        differences = 0

        for path, original in sorted(baseline.items()):
            if path not in current:
                lines.append(f"[MISSING] {path}")
                differences += 1
            elif current[path] != original:
                lines.extend([
                    f"[TAMPERED] {path}",
                    f"  Original: {original}",
                    f"  Current : {current[path]}"
                ])
                differences += 1
            else:
                lines.append(f"[VERIFIED] {path}")

        for path in sorted(set(current) - set(baseline)):
            lines.append(f"[NEW FILE] {path}")
            differences += 1

        lines.insert(
            1, f"Total differences: {differences}\n"
        )

        self.write_box(
            self.investigation_box,
            "\n".join(lines), clear=True
        )
        self.tabs.set("Investigation")

    def export_report(self, extension):
        self.refresh_history()

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )
        output = REPORTS / (
            f"soc_report_{timestamp}.{extension}"
        )

        try:
            if extension == "json":
                output.write_text(
                    json.dumps(self.filtered, indent=2),
                    encoding="utf-8"
                )
            else:
                with open(
                    output, "w",
                    newline="", encoding="utf-8"
                ) as file:
                    writer = csv.DictWriter(
                        file,
                        fieldnames=[
                            "timestamp", "severity",
                            "event", "path"
                        ]
                    )
                    writer.writeheader()
                    writer.writerows(self.filtered)

            messagebox.showinfo(
                "Export Complete", str(output)
            )
        except OSError as error:
            messagebox.showerror(
                "Export Error", str(error)
            )

    def close_app(self):
        if self.monitor and self.monitor.running:
            self.monitor.stop()
        self.destroy()


if __name__ == "__main__":
    app = FileGuardSOC()
    app.mainloop()
