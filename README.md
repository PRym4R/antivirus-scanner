# Antivirus Scanner

Simple Python CLI antivirus scanner with heuristic detection and archive support.

## Features
- File signature scanning
- Heuristic analysis (PE anomalies, entropy, base64 patterns)
- Archive scanning (zip, tar, gz)
- Folder monitoring (watch mode)
- Windows notifications + autostart support

## Usage
```bash
python antivirus.py <path> -r
