"""MetaTrace metadata engine.

analyze_file() returns an ordered dict of sections:
    {"File Information": {"File Name": "...", ...}, "Hashes": {...}, ...}
"""
from __future__ import annotations

import csv
import hashlib
import json
import mimetypes
import os
import stat
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from PIL import Image, UnidentifiedImageError
from PIL.ExifTags import GPSTAGS, TAGS
from PIL.TiffImagePlugin import IFDRational

try:
    import pwd  # POSIX only
except ImportError:  # Windows
    pwd = None

Results = dict[str, dict[str, str]]
ProgressFn = Callable[[int, int], None]

CHUNK_SIZE = 1024 * 1024  # 1 MiB
EXIF_IFD, GPS_IFD = 0x8769, 0x8825
MAX_VALUE_LEN = 300

# --------------------------------------------------------------------------
# File signature ("magic number") detection
# --------------------------------------------------------------------------
_ZIP_EXTS = {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
             ".jar", ".apk", ".epub", ".xpi"}
_OLE_EXTS = {".doc", ".xls", ".ppt", ".msi", ".msg"}

# (offset, magic bytes, label, mime, allowed extensions)
SIGNATURES = [
    (0, b"\x89PNG\r\n\x1a\n", "PNG image", "image/png", {".png"}),
    (0, b"\xff\xd8\xff", "JPEG image", "image/jpeg", {".jpg", ".jpeg", ".jpe", ".jfif"}),
    (0, b"GIF87a", "GIF image", "image/gif", {".gif"}),
    (0, b"GIF89a", "GIF image", "image/gif", {".gif"}),
    (0, b"BM", "BMP image", "image/bmp", {".bmp", ".dib"}),
    (0, b"II*\x00", "TIFF image", "image/tiff", {".tif", ".tiff"}),
    (0, b"MM\x00*", "TIFF image", "image/tiff", {".tif", ".tiff"}),
    (0, b"%PDF-", "PDF document", "application/pdf", {".pdf"}),
    (0, b"PK\x03\x04", "ZIP container (ZIP/Office/JAR/APK)", "application/zip", _ZIP_EXTS),
    (0, b"Rar!\x1a\x07", "RAR archive", "application/vnd.rar", {".rar"}),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "application/x-7z-compressed", {".7z"}),
    (0, b"\x1f\x8b", "GZIP archive", "application/gzip", {".gz", ".tgz"}),
    (0, b"MZ", "Windows executable (PE/DOS)", "application/vnd.microsoft.portable-executable",
     {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}),
    (0, b"\x7fELF", "ELF executable", "application/x-elf", {".elf", ".so", ".o", ".bin", ""}),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound file (legacy Office)",
     "application/x-ole-storage", _OLE_EXTS),
    (0, b"SQLite format 3\x00", "SQLite database", "application/vnd.sqlite3",
     {".sqlite", ".sqlite3", ".db", ".db3"}),
    (4, b"ftyp", "ISO media (MP4/MOV/HEIC)", "video/mp4",
     {".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".heic", ".heif"}),
    (0, b"ID3", "MP3 audio (ID3)", "audio/mpeg", {".mp3"}),
    (0, b"OggS", "Ogg container", "audio/ogg", {".ogg", ".oga", ".ogv", ".opus"}),
    (0, b"fLaC", "FLAC audio", "audio/flac", {".flac"}),
]


def detect_signature(head: bytes) -> tuple[str, str, set[str]] | None:
    """Identify a file type from its first bytes, or None if unrecognised."""
    if head[:4] == b"RIFF" and len(head) >= 12:
        kind = head[8:12]
        riff = {
            b"WEBP": ("WebP image", "image/webp", {".webp"}),
            b"WAVE": ("WAV audio", "audio/wav", {".wav"}),
            b"AVI ": ("AVI video", "video/x-msvideo", {".avi"}),
        }
        if kind in riff:
            return riff[kind]
    for offset, magic, label, mime, exts in SIGNATURES:
        if head[offset:offset + len(magic)] == magic:
            return label, mime, exts
    return None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _human_size(n: int) -> str:
    size = float(n)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{n:,} bytes" if unit == "bytes" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{n:,} bytes"


def _fmt_ts(ts: float) -> str:
    utc = datetime.fromtimestamp(ts, tz=timezone.utc)
    local = utc.astimezone()
    return f"{utc:%Y-%m-%d %H:%M:%S} UTC  ({local:%Y-%m-%d %H:%M:%S %Z})"


def calculate_hashes(
    file_path: str | Path,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
) -> dict[str, str]:
    """MD5, SHA-1 and SHA-256 computed in a single pass over the file."""
    hashers = {
        "MD5": hashlib.md5(usedforsecurity=False),
        "SHA-1": hashlib.sha1(usedforsecurity=False),
        "SHA-256": hashlib.sha256(),
    }
    total = os.path.getsize(file_path)
    done = 0
    with open(file_path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            if cancel is not None and cancel.is_set():
                raise InterruptedError("Analysis cancelled.")
            for h in hashers.values():
                h.update(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)
    if progress and total == 0:
        progress(0, 0)
    return {name: h.hexdigest() for name, h in hashers.items()}


# --------------------------------------------------------------------------
# Section builders
# --------------------------------------------------------------------------
def _file_section(path: Path, st: os.stat_result) -> dict[str, str]:
    info = {
        "File Name": path.name,
        "Full Path": str(path.resolve()),
        "File Extension": path.suffix or "No extension",
        "File Size": f"{_human_size(st.st_size)}  ({st.st_size:,} bytes)"
        if st.st_size >= 1024 else f"{st.st_size:,} bytes",
        "Permissions": stat.filemode(st.st_mode),
    }
    if pwd is not None:
        try:
            info["Owner"] = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            info["Owner"] = f"uid {st.st_uid}"
    if path.is_symlink():
        info["Symlink Target"] = os.readlink(path)
    return info


def _time_section(st: os.stat_result) -> dict[str, str]:
    times: dict[str, str] = {}
    birth = getattr(st, "st_birthtime", None)
    if birth is not None:
        times["Created"] = _fmt_ts(birth)
    elif sys.platform == "win32":
        times["Created"] = _fmt_ts(st.st_ctime)  # ctime == creation time on Windows
    else:
        times["Created"] = "Not available on this filesystem/OS"
        times["Inode Changed (ctime)"] = _fmt_ts(st.st_ctime)
    times["Modified"] = _fmt_ts(st.st_mtime)
    times["Accessed"] = _fmt_ts(st.st_atime)
    return times


def _type_section(path: Path, head: bytes) -> dict[str, str]:
    guessed, _ = mimetypes.guess_type(str(path))
    detected = detect_signature(head)
    ext = path.suffix.lower()

    section = {"MIME Type (extension-based)": guessed or "Unknown"}
    if detected is None:
        section["Detected Type (signature)"] = "Not recognised"
        section["Extension vs. Content"] = "Unknown - no matching signature"
    else:
        label, mime, allowed = detected
        section["Detected Type (signature)"] = f"{label}  [{mime}]"
        if ext in allowed:
            section["Extension vs. Content"] = "Match"
        else:
            section["Extension vs. Content"] = (
                f"MISMATCH - extension '{ext or 'none'}' does not fit content "
                f"(possible renamed or disguised file)"
            )
    return section


def _clean(value) -> str:
    if isinstance(value, bytes):
        if len(value) > 64:
            return f"<{len(value)} bytes>"
        try:
            text = value.decode("utf-8").rstrip("\x00")
            return text if text.isprintable() else value.hex()
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, IFDRational):
        return f"{float(value):.6g}"
    if isinstance(value, (tuple, list)):
        return ", ".join(_clean(v) for v in value)
    text = str(value)
    return text if len(text) <= MAX_VALUE_LEN else text[:MAX_VALUE_LEN] + "..."


def _dms_to_degrees(dms, ref) -> float:
    d, m, s = (float(x) for x in dms)
    deg = d + m / 60 + s / 3600
    return -deg if str(ref).upper() in ("S", "W") else deg


def extract_image_metadata(file_path: str | Path) -> Results:
    """Image / EXIF / GPS sections. Returns {} if the file is not an image."""
    out: Results = {}
    try:
        with Image.open(file_path) as image:
            basic = {
                "Format": image.format or "Unknown",
                "Mode": image.mode,
                "Dimensions": f"{image.width} x {image.height} px",
            }
            if getattr(image, "n_frames", 1) > 1:
                basic["Frames"] = str(image.n_frames)
            if dpi := image.info.get("dpi"):
                basic["DPI"] = ", ".join(f"{float(x):.0f}" for x in dpi)
            out["Image"] = basic

            exif = image.getexif()
            tags: dict[str, str] = {}
            skip = {EXIF_IFD, GPS_IFD}
            # Base IFD, then the Exif sub-IFD (DateTimeOriginal, exposure, lens...)
            for source in (
                {k: v for k, v in exif.items() if k not in skip},
                {k: v for k, v in exif.get_ifd(EXIF_IFD).items() if k != 0xA005},
            ):
                for tag_id, value in source.items():
                    name = TAGS.get(tag_id, f"Unknown (0x{tag_id:04X})")
                    tags[name] = _clean(value)
            if tags:
                out["EXIF"] = tags

            gps_raw = exif.get_ifd(GPS_IFD)
            if gps_raw:
                gps = {GPSTAGS.get(k, f"Unknown ({k})"): v for k, v in gps_raw.items()}
                section = {f"GPS {k}": _clean(v) for k, v in gps.items()}
                try:
                    lat = _dms_to_degrees(gps["GPSLatitude"], gps["GPSLatitudeRef"])
                    lon = _dms_to_degrees(gps["GPSLongitude"], gps["GPSLongitudeRef"])
                    section["Coordinates (decimal)"] = f"{lat:.6f}, {lon:.6f}"
                    section["Map Link"] = (
                        f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}"
                        f"#map=16/{lat:.6f}/{lon:.6f}"
                    )
                except (KeyError, TypeError, ValueError, ZeroDivisionError):
                    pass
                out["GPS"] = section
    except UnidentifiedImageError:
        return {}  # not an image: perfectly normal
    except Exception as error:  # corrupt image, unsupported variant, ...
        out["Image"] = {"Image Metadata Error": f"{type(error).__name__}: {error}"}
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def analyze_file(
    file_path: str | Path,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
) -> Results:
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File does not exist: {path}")

    # stat() BEFORE reading the file so access time reflects the original state
    st = os.stat(path)
    with open(path, "rb") as fh:
        head = fh.read(32)

    results: Results = {
        "File Information": _file_section(path, st),
        "Timestamps": _time_section(st),
        "Type Analysis": _type_section(path, head),
    }
    results["Hashes"] = calculate_hashes(path, progress, cancel)
    results.update(extract_image_metadata(path))
    return results


def extract_metadata(file_path: str | Path) -> dict[str, str]:
    """Backward-compatible flat view of analyze_file()."""
    flat: dict[str, str] = {}
    for section in analyze_file(file_path).values():
        flat.update(section)
    return flat


def export_report(results: Results, dest: str | Path, source: str = "") -> None:
    """Write results as .json, .csv or plain text depending on dest suffix."""
    dest = Path(dest)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    suffix = dest.suffix.lower()

    if suffix == ".json":
        payload = {"tool": "MetaTrace", "generated": stamp, "source": source, "results": results}
        dest.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    elif suffix == ".csv":
        with open(dest, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Section", "Property", "Value"])
            for section, rows in results.items():
                for key, value in rows.items():
                    writer.writerow([section, key, value])
    else:
        lines = ["MetaTrace Report", f"Generated: {stamp}", f"Source: {source}", ""]
        for section, rows in results.items():
            lines += [f"[{section}]"] + [f"  {k}: {v}" for k, v in rows.items()] + [""]
        dest.write_text("\n".join(lines), encoding="utf-8")