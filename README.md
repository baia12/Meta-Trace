# MetaTrace – File Metadata Extractor

**MetaTrace** is a Python desktop application designed to extract and analyse file metadata for preliminary digital forensic investigations.

The application helps users inspect file properties, calculate cryptographic hashes and examine metadata from supported file formats.

## Project Objectives

- Simplify file metadata examination.
- Support preliminary digital forensic investigations.
- Calculate SHA-256 hashes for file integrity checking.
- Provide a user-friendly desktop interface.
- Generate structured metadata reports.

## Features

### Implemented

- [x] File selection
- [x] File name and extension extraction
- [x] File size identification
- [x] File timestamp extraction
- [x] MIME type estimation
- [x] SHA-256 hash calculation
- [x] Desktop interface using Tkinter

### Planned

- [ ] Image EXIF metadata extraction
- [ ] GPS metadata extraction
- [ ] PDF metadata extraction
- [ ] Batch file analysis
- [ ] CSV and JSON export
- [ ] Forensic report generation

## Technology Stack

| Technology | Purpose                           |
| ---------- | --------------------------------- |
| Python     | Application development           |
| Tkinter    | Desktop interface                 |
| Pillow     | Image metadata                    |
| PyPDF      | PDF metadata                      |
| hashlib    | SHA-256 hashing                   |
| GitHub     | Version control and collaboration |

## Project Structure

```text
MetaTrace/
├── main.py
├── metadata_engine.py
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

4. Activate the environment on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

5. Install dependencies:

```bash
pip install -r requirements.txt
```

6. Run the application:

```bash
python main.py
```

## Team Collaboration

Developed collaboratively by two cybersecurity students as a practical learning project in Python development and digital forensics.

## Disclaimer

MetaTrace is an educational project intended for authorised digital forensic examination. Extracted metadata should be treated as investigative information and not automatically as proof of authenticity.

## Project Status

Currently under development.
