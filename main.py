import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from metadata_engine import analyze_file, export_report

COLORS = {"ok": "#1a7f37", "error": "#c62828", "info": "#555555"}


class MetaTraceApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("MetaTrace - File Metadata Extractor")
        root.geometry("950x620")
        root.minsize(700, 450)

        self.results = {}
        self.source_path = ""
        self.msgs: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: threading.Thread | None = None

        self._build_ui()
        self._bind_shortcuts()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        ttk.Label(self.root, text="MetaTrace", font=("Arial", 24, "bold")).pack(pady=(18, 2))
        ttk.Label(self.root, text="Digital Forensics - File Metadata Extractor").pack(pady=(0, 12))

        bar = ttk.Frame(self.root)
        bar.pack(pady=6)
        self.btn_select = ttk.Button(bar, text="Select File", command=self.select_file)
        self.btn_cancel = ttk.Button(bar, text="Cancel", command=self.cancel, state="disabled")
        self.btn_export = ttk.Button(bar, text="Export Report", command=self.export, state="disabled")
        self.btn_clear = ttk.Button(bar, text="Clear Results", command=self.clear_results)
        for b in (self.btn_select, self.btn_cancel, self.btn_export, self.btn_clear):
            b.pack(side="left", padx=5)

        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=20, pady=(8, 0))

        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.table = ttk.Treeview(frame, columns=("Property", "Value"),
                                  show="headings", selectmode="extended")
        self.table.heading("Property", text="Property")
        self.table.heading("Value", text="Value")
        self.table.column("Property", width=230, stretch=False)
        self.table.column("Value", width=650, stretch=True)

        ybar = ttk.Scrollbar(frame, orient="vertical", command=self.table.yview)
        xbar = ttk.Scrollbar(frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        bold = tkfont.nametofont("TkDefaultFont").copy()
        bold.configure(weight="bold")
        self.table.tag_configure("section", font=bold, background="#e3eaf3", foreground="#000000")
        self.table.tag_configure("warn", foreground=COLORS["error"])

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Copy value", command=lambda: self.copy_selected(value_only=True))
        self.menu.add_command(label="Copy row", command=self.copy_selected)

        self.status = ttk.Label(self.root, text="Ready. Select a file to begin.")
        self.status.pack(pady=(0, 10))
        self.set_status("Ready. Select a file to begin.", "ok")

    def _bind_shortcuts(self):
        self.root.bind("<Control-o>", lambda _e: self.select_file())
        self.table.bind("<Control-c>", lambda _e: self.copy_selected())
        self.table.bind("<Button-3>", self._popup)   # Windows / Linux
        self.table.bind("<Button-2>", self._popup)   # macOS

    def _popup(self, event):
        row = self.table.identify_row(event.y)
        if row:
            if row not in self.table.selection():
                self.table.selection_set(row)
            self.menu.tk_popup(event.x_root, event.y_root)

    # ------------------------------------------------------------- helpers
    def set_status(self, text: str, level: str = "info"):
        self.status.config(text=text, foreground=COLORS[level])

    def _set_busy(self, busy: bool):
        self.btn_select.config(state="disabled" if busy else "normal")
        self.btn_cancel.config(state="normal" if busy else "disabled")
        self.btn_clear.config(state="disabled" if busy else "normal")
        if busy:
            self.btn_export.config(state="disabled")

    def _populate(self, results):
        for section, rows in results.items():
            self.table.insert("", "end", values=(section.upper(), ""), tags=("section",))
            for key, value in rows.items():
                tags = ("warn",) if str(value).startswith("MISMATCH") else ()
                self.table.insert("", "end", values=(f"   {key}", value), tags=tags)

    # ------------------------------------------------------------- actions
    def select_file(self):
        if self.worker and self.worker.is_alive():
            return
        path = filedialog.askopenfilename(title="Select a file for analysis")
        if path:
            self.start_analysis(path)

    def start_analysis(self, path: str):
        self.clear_results(quiet=True)
        self.source_path = path
        self.cancel_event.clear()
        self.progress.config(value=0, maximum=100)
        self._set_busy(True)
        self.set_status(f"Analyzing {Path(path).name} ...", "info")

        self.worker = threading.Thread(target=self._work, args=(path,), daemon=True)
        self.worker.start()
        self.root.after(50, self._poll)

    def _work(self, path: str):
        """Runs in a background thread. Never touch Tk widgets here."""
        try:
            results = analyze_file(
                path,
                progress=lambda done, total: self.msgs.put(("progress", done, total)),
                cancel=self.cancel_event,
            )
            self.msgs.put(("done", results))
        except InterruptedError:
            self.msgs.put(("cancelled",))
        except Exception as error:
            self.msgs.put(("error", error))

    def _poll(self):
        finished = False
        try:
            while True:
                kind, *data = self.msgs.get_nowait()
                if kind == "progress":
                    done, total = data
                    self.progress.config(value=(done / total * 100) if total else 100)
                elif kind == "done":
                    self.results = data[0]
                    self._populate(self.results)
                    self.progress.config(value=100)
                    self.btn_export.config(state="normal")
                    warn = any(str(v).startswith("MISMATCH")
                               for v in self.results["Type Analysis"].values())
                    if warn:
                        self.set_status("Analysis complete - WARNING: extension does not match content.", "error")
                    else:
                        self.set_status("Analysis completed successfully.", "ok")
                    finished = True
                elif kind == "cancelled":
                    self.progress.config(value=0)
                    self.set_status("Analysis cancelled.", "info")
                    finished = True
                elif kind == "error":
                    self.progress.config(value=0)
                    messagebox.showerror("Analysis Error", str(data[0]))
                    self.set_status("Analysis failed.", "error")
                    finished = True
        except queue.Empty:
            pass

        if finished:
            self._set_busy(False)
            if self.results:
                self.btn_export.config(state="normal")
        else:
            self.root.after(50, self._poll)

    def cancel(self):
        self.cancel_event.set()
        self.set_status("Cancelling ...", "info")

    def export(self):
        if not self.results:
            return
        dest = filedialog.asksaveasfilename(
            title="Export report",
            defaultextension=".json",
            initialfile=f"{Path(self.source_path).name}_metatrace",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("Text", "*.txt")],
        )
        if not dest:
            return
        try:
            export_report(self.results, dest, source=self.source_path)
            self.set_status(f"Report saved to {dest}", "ok")
        except OSError as error:
            messagebox.showerror("Export Error", str(error))
            self.set_status("Export failed.", "error")

    def copy_selected(self, value_only: bool = False):
        lines = []
        for item in self.table.selection():
            prop, value = self.table.item(item, "values")
            lines.append(str(value) if value_only else f"{prop.strip()}\t{value}")
        if lines:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(lines))
            self.set_status("Copied to clipboard.", "ok")

    def clear_results(self, quiet: bool = False):
        self.table.delete(*self.table.get_children())
        self.results = {}
        self.progress.config(value=0)
        self.btn_export.config(state="disabled")
        if not quiet:
            self.set_status("Results cleared. Select another file.", "ok")


if __name__ == "__main__":
    root = tk.Tk()
    MetaTraceApp(root)
    root.mainloop()