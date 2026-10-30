
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from metadata_engine import extract_metadata


class MetaTraceApp:

    def __init__(self, root):
        self.root = root

        self.root.title("MetaTrace - File Metadata Extractor")
        self.root.geometry("850x550")
        self.root.minsize(650, 400)

        self.create_interface()

    def create_interface(self):

        # Application heading
        heading = ttk.Label(
            self.root,
            text="MetaTrace",
            font=("Arial", 24, "bold")
        )
        heading.pack(pady=(20, 5))

        subtitle = ttk.Label(
            self.root,
            text="Digital Forensics - File Metadata Extractor"
        )
        subtitle.pack(pady=(0, 20))

        # Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)

        ttk.Button(
            button_frame,
            text="Select File",
            command=self.select_file
        ).pack(side="left", padx=5)

        ttk.Button(
            button_frame,
            text="Clear Results",
            command=self.clear_results
        ).pack(side="left", padx=5)

        # Metadata table
        self.table = ttk.Treeview(
            self.root,
            columns=("Property", "Value"),
            show="headings"
        )

        self.table.heading("Property", text="Property")
        self.table.heading("Value", text="Value")

        self.table.column("Property", width=220)
        self.table.column("Value", width=550)

        self.table.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=15
        )

        # Status message
        self.status = ttk.Label(
            self.root,
            text="Ready. Select a file to begin.",
            foreground="green"
        )
        self.status.pack(pady=10)

    def select_file(self):

        file_path = filedialog.askopenfilename(
            title="Select a file for analysis"
        )

        if not file_path:
            return

        try:
            results = extract_metadata(file_path)

            self.clear_results()

            for key, value in results.items():
                self.table.insert(
                    "",
                    "end",
                    values=(key, value)
                )

            self.status.config(
                text="Analysis completed successfully.",
                foreground="green"
            )

        except Exception as error:
            messagebox.showerror(
                "Analysis Error",
                str(error)
            )

            self.status.config(
                text="Analysis failed.",
                foreground="red"
            )

    def clear_results(self):

        for item in self.table.get_children():
            self.table.delete(item)

        self.status.config(
            text="Results cleared. Select another file.",
            foreground="green"
        )


if __name__ == "__main__":

    root = tk.Tk()

    app = MetaTraceApp(root)

    root.mainloop()
