import os 
import hashlib
import mimetypes

from pathlib import Path
from datetime import datetime

def calculate_sha256(file_path):
    sha256=hashlib.sha256()
    with open (file_path ,"rb") as file :
        for chunk in iter(lambda :file.read(4096),b""):
            sha256.update(chunk)

    return sha256.hexdigest()

def extract_metadata(file_path):

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError("File does not exist.")

    file_stats = os.stat(file_path)

    mime_type, encoding = mimetypes.guess_type(str(path))

    metadata = {
        "File Name": path.name,

        "File Extension": path.suffix or "No extension",

        "File Size": f"{file_stats.st_size:,} bytes",

        "Creation Time (Windows)": datetime.fromtimestamp(
            file_stats.st_ctime
        ).strftime("%Y-%m-%d %H:%M:%S"),

        "Last Modified": datetime.fromtimestamp(
            file_stats.st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S"),

        "MIME Type (Extension-based)": mime_type or "Unknown",

        "SHA-256": calculate_sha256(file_path)
    }

    return metadata

