
import customtkinter as ctk
from tkinter import filedialog, messagebox
from pathlib import Path
from queue import Queue, Empty
from datetime import datetime

from monitor import FileGuardMonitor, EVENTS

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BASE = Path(__file__).resolve().parent
TEST = BASE / "test_folder"
TEST.mkdir(exist_ok=True)

BG = "#08111F"
PANEL = "#132239"
CYAN = "#00D9FF"
GREEN = "#20E3A2"
YELLOW = "#FFCA55"
RED = "#FF6077"


class FileGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("FileGuard | Advanced Integrity Monitor")
        self.geometry("1080x740")
        self.minsize(850, 600)
        self.configure(fg_color=BG)

        self.monitor = None
        self.events = Queue()
        self.counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0
        }
        self.folder = ctk.StringVar(value=str(TEST))

        self.build_ui()
        self.after(150, self.process_events)
        self.protocol("WM_DELETE_WINDOW", self.close_app)

    def build_ui(self):
        header = ctk.CTkFrame(
            self, fg_color="transparent"
        )
        header.pack(fill="x", padx=25, pady=20)

        ctk.CTkLabel(
            header, text="🛡 FILEGUARD",
            font=("Arial", 30, "bold"),
            text_color=CYAN
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="ADVANCED FILE INTEGRITY MONITOR",
            text_color="#A5B6CF"
        ).pack(anchor="w")

        self.status = ctk.CTkLabel(
            header, text="● OFFLINE",
            text_color=RED,
            font=("Arial", 15, "bold")
        )
        self.status.pack(anchor="e")

        folder_panel = ctk.CTkFrame(
            self, fg_color=PANEL
        )
        folder_panel.pack(
            fill="x", padx=25, pady=10
        )

        ctk.CTkLabel(
            folder_panel,
            text="MONITORING DIRECTORY",
            text_color=CYAN
        ).pack(anchor="w", padx=15, pady=10)

        row = ctk.CTkFrame(
            folder_panel, fg_color="transparent"
        )
        row.pack(fill="x", padx=15, pady=(0, 15))

        self.entry = ctk.CTkEntry(
            row, textvariable=self.folder, height=40
        )
        self.entry.pack(
            side="left", fill="x", expand=True
        )

        self.browse = ctk.CTkButton(
            row, text="Browse", width=90,
            command=self.choose_folder
        )
        self.browse.pack(side="left", padx=10)

        controls = ctk.CTkFrame(
            self, fg_color="transparent"
        )
        controls.pack(fill="x", padx=25, pady=12)

        self.start_btn = ctk.CTkButton(
            controls, text="▶ START",
            fg_color="#087C67",
            command=self.start_monitor
        )
        self.start_btn.pack(side="left", padx=4)

        self.stop_btn = ctk.CTkButton(
            controls, text="■ STOP",
            fg_color="#A82B45",
            state="disabled",
            command=self.stop_monitor
        )
        self.stop_btn.pack(side="left", padx=4)

        self.approve_btn = ctk.CTkButton(
            controls, text="Approve Baseline",
            state="disabled",
            command=self.approve
        )
        self.approve_btn.pack(side="left", padx=4)

        self.export_btn = ctk.CTkButton(
            controls, text="Export CSV",
            state="disabled",
            command=self.export
        )
        self.export_btn.pack(side="left", padx=4)

        stats = ctk.CTkFrame(
            self, fg_color="transparent"
        )
        stats.pack(fill="x", padx=25, pady=15)

        self.stat_labels = {}

        for severity, color in [
            ("LOW", GREEN),
            ("MEDIUM", YELLOW),
            ("HIGH", RED)
        ]:
            card = ctk.CTkFrame(
                stats, fg_color=PANEL
            )
            card.pack(
                side="left", fill="both",
                expand=True, padx=5
            )

            ctk.CTkLabel(
                card,
                text=severity + " SEVERITY",
                text_color=color,
                font=("Arial", 13, "bold")
            ).pack(pady=(15, 5))

            label = ctk.CTkLabel(
                card, text="0",
                font=("Arial", 35, "bold"),
                text_color=color
            )
            label.pack(pady=(0, 15))
            self.stat_labels[severity] = label

        panel = ctk.CTkFrame(
            self, fg_color=PANEL
        )
        panel.pack(
            fill="both", expand=True,
            padx=25, pady=(5, 20)
        )

        ctk.CTkLabel(
            panel,
            text="LIVE SECURITY EVENTS",
            font=("Arial", 16, "bold"),
            text_color=CYAN
        ).pack(anchor="w", padx=15, pady=12)

        self.logbox = ctk.CTkTextbox(
            panel, fg_color=BG,
            font=("Consolas", 12),
            wrap="word"
        )
        self.logbox.pack(
            fill="both", expand=True,
            padx=15, pady=(0, 15)
        )

        self.write_log(
            "[SYSTEM] FileGuard Phase 4 ready."
        )

    def write_log(self, text):
        self.logbox.insert("end", text + "\n")
        self.logbox.see("end")

    def choose_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder.set(folder)

    def receive_event(self, event_type, path):
        self.events.put((event_type, path))

    def process_events(self):
        try:
            while True:
                event_type, path = self.events.get_nowait()
                severity = EVENTS.get(
                    event_type, "MEDIUM"
                )

                self.counts[severity] += 1
                self.stat_labels[severity].configure(
                    text=str(self.counts[severity])
                )

                now = datetime.now().strftime("%H:%M:%S")
                self.write_log(
                    f"[{now}] [{severity}] "
                    f"{event_type} | {path}"
                )
        except Empty:
            pass

        self.after(150, self.process_events)

    def start_monitor(self):
        if self.monitor is not None:
            return

        folder = self.folder.get().strip()

        if not Path(folder).is_dir():
            messagebox.showerror(
                "Error", "Select a valid folder"
            )
            return

        try:
            monitor = FileGuardMonitor(
                folder, callback=self.receive_event
            )
            monitor.start()
            self.monitor = monitor
        except Exception as error:
            messagebox.showerror(
                "Monitoring Error", str(error)
            )
            return

        self.status.configure(
            text="● MONITORING ACTIVE",
            text_color=GREEN
        )

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.approve_btn.configure(state="normal")
        self.export_btn.configure(state="normal")
        self.entry.configure(state="disabled")
        self.browse.configure(state="disabled")

        self.write_log(
            f"[SYSTEM] Started: {folder}"
        )

    def stop_monitor(self):
        if self.monitor is None:
            return

        self.monitor.stop()

        self.status.configure(
            text="● OFFLINE", text_color=RED
        )

        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.approve_btn.configure(state="normal")
        self.export_btn.configure(state="normal")
        self.entry.configure(state="normal")
        self.browse.configure(state="normal")

        self.write_log("[SYSTEM] Monitoring stopped.")

    def approve(self):
        if self.monitor is None:
            return

        confirm = messagebox.askyesno(
            "Approve Baseline",
            "Trust the current file state?\n"
            "This replaces the original baseline."
        )

        if confirm:
            try:
                self.monitor.approve_baseline()
                self.write_log(
                    "[SYSTEM] New baseline approved."
                )
            except Exception as error:
                messagebox.showerror(
                    "Baseline Error", str(error)
                )

    def export(self):
        if self.monitor is None:
            return

        try:
            filename = self.monitor.export_csv()
            self.write_log(
                f"[SYSTEM] CSV exported: {filename}"
            )
            messagebox.showinfo(
                "Export Complete", filename
            )
        except Exception as error:
            messagebox.showerror(
                "Export Error", str(error)
            )

    def close_app(self):
        if self.monitor and self.monitor.running:
            self.monitor.stop()
        self.destroy()


if __name__ == "__main__":
    app = FileGuardApp()
    app.mainloop()
