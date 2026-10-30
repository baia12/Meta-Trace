# MetaTrace – File Metadata Extractor

**MetaTrace** is a Python desktop application designed to extract and analyse file metadata for preliminary digital forensic investigations.

The application helps users inspect file properties, calculate cryptographic hashes, detect disguised file types and examine EXIF and GPS metadata from images.

## Project Objectives

- Simplify file metadata examination.
- Support preliminary digital forensic investigations.
- Calculate MD5, SHA-1 and SHA-256 hashes for file integrity checking.
- Detect files whose extension does not match their real content.
- Provide a user-friendly, responsive desktop interface.
- Generate structured metadata reports.

## Features

### Implemented

- [x] File selection
- [x] File name, full path, extension, size, permissions and owner
- [x] Created, modified and accessed timestamps (UTC and local time)
- [x] MIME type estimation from the file extension
- [x] File type detection from magic bytes, with extension mismatch warnings
- [x] MD5, SHA-1 and SHA-256 hashes, calculated in a single pass
- [x] Image EXIF metadata extraction (camera, date taken, exposure and more)
- [x] GPS metadata extraction with decimal coordinates and a map link
- [x] JSON, CSV and plain-text report export
- [x] Background analysis with progress bar and cancel button
- [x] Copy values or rows to the clipboard (Ctrl+C or right-click)
- [x] Desktop interface using Tkinter

### Planned

- [ ] PDF metadata extraction
- [ ] Office document metadata (author, revisions)
- [ ] Batch file analysis
- [ ] Hash verification against an expected value
- [ ] Drag-and-drop file selection
- [ ] Formatted forensic report generation (PDF/HTML)
- [ ] Automated tests

## Technology Stack

| Technology    | Purpose                           |
| ------------- | --------------------------------- |
| Python 3.10+  | Application development           |
| Tkinter       | Desktop interface                 |
| Pillow (9.4+) | Image, EXIF and GPS metadata      |
| hashlib       | MD5, SHA-1 and SHA-256 hashing    |
| PyPDF         | PDF metadata (planned)            |
| GitHub        | Version control and collaboration |

## Project Structure

```text
MetaTrace/
├── main.py                # Tkinter user interface
├── metadata_engine.py     # Metadata extraction, hashing and report export
├── requirements.txt
├── README.md
├── samples/
├── exports/
└── tests/
```

## Installation

1. Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
```

2. Navigate into the project:

```bash
cd MetaTrace
```

3. Create a virtual environment:

```bash
python -m venv .venv
```

4. Activate the environment.

   Windows (PowerShell):

```powershell
.venv\Scripts\Activate.ps1
```

macOS / Linux:

```bash
source .venv/bin/activate
```

5. Install dependencies:

```bash
pip install -r requirements.txt
```

6. Run the application:

```bash
python main.py
```

## Usage

1. Click **Select File** (or press `Ctrl+O`) and choose a file.
2. Wait for the analysis to finish. Large files show a progress bar and can be cancelled.
3. Review the results, which are grouped into sections:
   - **File Information**: name, path, extension, size, permissions, owner
   - **Timestamps**: created, modified, accessed
   - **Type Analysis**: extension-based MIME type, detected type and match check
   - **Hashes**: MD5, SHA-1, SHA-256
   - **Image / EXIF / GPS**: shown for supported images
4. Rows marked in red (`MISMATCH`) indicate the extension does not fit the file's content.
5. Click **Export Report** to save the results as JSON, CSV or text.

## Using the Engine Without the GUI

```python
from metadata_engine import analyze_file, export_report

results = analyze_file("samples/photo.jpg")
print(results["Hashes"]["SHA-256"])
export_report(results, "exports/photo_report.json", source="samples/photo.jpg")
```

## Limitations

- **Creation time** is only available on Windows and macOS. On Linux, MetaTrace reports the inode change time (ctime) separately and marks creation time as unavailable.
- **File type detection** covers common formats only. A file with an unrecognised signature is reported as "Not recognised", not as safe.
- **EXIF and GPS data** can be edited or removed easily and may be absent from images processed by social media or messaging apps.
- MetaTrace is **read-only**: it never modifies the analysed file. Timestamps are read before the file is opened, but opening a file may still update access times on some systems. Use a write blocker or a forensic copy for evidence handling.

## Team Collaboration

Developed collaboratively by two cybersecurity students as a practical learning project in Python development and digital forensics.

## Disclaimer

MetaTrace is an educational project intended for authorised digital forensic examination. Extracted metadata should be treated as investigative information and not automatically as proof of authenticity.

## Project Status

Currently under development.
