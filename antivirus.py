#!/usr/bin/env python3
import os
import re
import sys
import struct
import argparse
import math
import zipfile
import tarfile
import time
import ctypes
import ctypes.wintypes
from dataclasses import dataclass
from typing import Optional

@dataclass
class Threat:
    name: str
    signature: str
    signature_type: str
    severity: str

SIGNATURES = [
    Threat("EICAR-Test-File", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "string", "safe"),
]

C2_PATTERNS = [
    (r'https://discord(app)?\.com/api/webhooks/[\w/-]+', "Discord-Webhook"),
    (r'[0-9]{8,10}:[A-Za-z0-9_-]{35}', "Telegram-Token"),
    (r'https?://[\w.-]+:[\d]+', "C2-URL:Port"),
    (r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[\d]+', "IP:Port"),
    (r'Samopal', "Samopal-Malware"),
    (r'SheetRat|SheetRat', "SheetRAT"),
    (r'XWorm\b', "XWorm"),
    (r'stratum\+tcp://[\w.-]+:\d+', "Monero-Mine"),
]

ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'}
THREAT_SEVERITY = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

class Antivirus:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.stats = {"files_scanned": 0, "threats_detected": 0}

    def log(self, msg):
        if self.verbose:
            print(f"[+] {msg}")

    def analyze_file(self, filepath):
        self.stats["files_scanned"] += 1
        threats = []
        
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ARCHIVE_EXTENSIONS:
            threats.extend(self._scan_archive(filepath))
            return threats
        
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception:
            return threats
        
        for threat in SIGNATURES:
            if threat.signature.encode() in data:
                threats.append((threat, "string match"))
        
        threats.extend(self._check_pe_anomalies(filepath, data))
        return threats

    def _scan_archive(self, filepath):
        threats = []
        self.log(f"Scanning archive: {filepath}")
        
        try:
            if filepath.endswith('.zip'):
                with zipfile.ZipFile(filepath, 'r') as zf:
                    for name in zf.namelist():
                        if name.endswith('/'):
                            continue
                        try:
                            data = zf.read(name)
                            threats.extend(self._check_pe_anomalies(name, data))
                        except:
                            pass
            elif filepath.endswith(('.tar', '.gz', '.bz2')):
                with tarfile.open(filepath, 'r:*') as tf:
                    for member in tf:
                        if member.isfile():
                            try:
                                data = tf.extractfile(member).read()
                                threats.extend(self._check_pe_anomalies(member.name, data))
                            except:
                                pass
        except Exception as e:
            self.log(f"Archive error: {e}")
        
        return threats

    def _check_pe_anomalies(self, filepath, data):
        threats = []
        
        try:
            text = data.decode('utf-8', errors='ignore')
            found_c2 = {}
            for pattern, name in C2_PATTERNS:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    found_c2[name] = m.group()[:60]
            for c2_name, c2_val in found_c2.items():
                threats.append((Threat(c2_name, c2_val, "heuristic", "critical"), ""))
        except:
            pass
        
        if not data.startswith(b"MZ") or len(data) < 64:
            return threats
        
        try:
            e_lfanew = struct.unpack("<I", data[60:64])[0]
            if e_lfanew > len(data) - 6:
                return threats
            
            num_sections = struct.unpack("<H", data[e_lfanew + 6:e_lfanew + 8])[0]
            if num_sections > 15:
                threats.append((Threat("SuspiciousSections", "Many PE sections", "heuristic", "high"), ""))
            
            # High entropy
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            n = len(data)
            entropy = sum(-p/n * math.log2(p/n) for p in freq if p > 0)
            if entropy > 8.0:
                threats.append((Threat("HighEntropy", "Packed/encrypted", "heuristic", "high"), ""))
            
            # RAT patterns - network + process + some crypto
            b64 = re.findall(b'[A-Za-z0-9+/]{50,}={0,2}', data)
            has_network = b"NetworkStream" in data or b"TcpClient" in data  
            has_process = b"ProcessStartInfo" in data
            has_socket = b"Socket" in data
            
            # RAT = network + process + socket OR network + process + crypto
            if (has_network and has_process and has_socket) or (has_network and has_process and b64):
                threats.append((Threat("RAT_Indicators", f"b64={len(b64)}", "heuristic", "critical"), ""))
            
            # Encoded strings - high threshold
            if len(b64) > 50:
                threats.append((Threat("EncodedStrings", "Many base64 strings", "heuristic", "medium"), ""))
            
        except:
            pass
        
        return threats

    def scan_path(self, path, recursive=True):
        results = {"clean": [], "infected": [], "errors": []}
        
        if os.path.isfile(path):
            threats = self.analyze_file(path)
            if threats:
                results["infected"].append({"file": path, "threats": threats})
                self.stats["threats_detected"] += len(threats)
            else:
                results["clean"].append(path)
            return results
        
        if recursive:
            for root, _, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    threats = self.analyze_file(filepath)
                    if threats:
                        results["infected"].append({"file": filepath, "threats": threats})
                        self.stats["threats_detected"] += len(threats)
                    else:
                        results["clean"].append(filepath)
        else:
            for entry in os.scandir(path):
                if entry.is_file():
                    threats = self.analyze_file(entry.path)
                    if threats:
                        results["infected"].append({"file": entry.path, "threats": threats})
                    else:
                        results["clean"].append(entry.path)
        
        return results


def notify_windows(title, message):
    if sys.platform == "win32":
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)


def print_results(results, av):
    sys.stdout.reconfigure(encoding='utf-8')
    print(f"\n{'='*50}")
    print(f"Files scanned: {av.stats['files_scanned']}")
    print(f"Threats found: {av.stats['threats_detected']}")
    print(f"Clean files: {len(results['clean'])}")
    print(f"Infected files: {len(results['infected'])}")
    
    if results["infected"]:
        print(f"\n{'!'*50}")
        print("INFECTED FILES:")
        for item in results["infected"]:
            print(f"\n  {item['file']}")
            for threat, details in item["threats"]:
                sev = "!" if THREAT_SEVERITY[threat.severity] >= 3 else "*"
                val = f": {threat.signature}" if threat.signature else ""
                print(f"    {sev} [{threat.severity.upper()}] {threat.name}{val}")


def main():
    parser = argparse.ArgumentParser(prog="antivirus", description="CLI Antivirus")
    parser.add_argument("path", nargs="?", help="Path to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="Scan recursively")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    parser.add_argument("-w", "--watch", metavar="DIR", help="Watch directory")
    parser.add_argument("--autostart", action="store_true", help="Install autostart")
    parser.add_argument("--remove-autostart", action="store_true", help="Remove autostart")
    args = parser.parse_args()
    
    if args.remove_autostart:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "Antivirus")
            winreg.CloseKey(key)
            print("[-] Removed from autostart")
        except:
            print("Not in autostart")
        return 0
    
    if args.autostart:
        import winreg
        script = os.path.abspath(__file__)
        exe_dir = os.path.dirname(sys.executable)
        pythonw = os.path.join(exe_dir, "pythonw.exe")
        exe_path = pythonw if os.path.exists(pythonw) else sys.executable
        
        bat_path = os.path.join(os.path.dirname(script), "antivirus.bat")
        with open(bat_path, "w") as f:
            f.write(f'@echo off\nstart "" /b "{exe_path}" "{script}" -w "{os.path.expanduser("~")}\\Downloads"\n')
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "Antivirus", 0, winreg.REG_SZ, f'"{bat_path}"')
            winreg.CloseKey(key)
            print("[+] Added to autostart")
        except Exception as e:
            print(f"Error: {e}")
        return 0
    
    if args.watch:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        
        av = Antivirus(verbose=args.verbose)
        
        class Handler(FileSystemEventHandler):
            def on_created(self, event):
                if event.is_directory:
                    return
                filepath = event.src_path
                if filepath.endswith('.part'):
                    return
                if any(filepath.endswith(ext) for ext in ['.tmp', '.crdownload', '.partial']):
                    return
                
                print(f"\n[NEW FILE] {filepath}")
                
                last_size = -1
                for _ in range(60):
                    time.sleep(1)
                    try:
                        with open(filepath, 'rb') as f:
                            f.seek(0, 2)
                            size = f.tell()
                        if size == last_size and size > 512:
                            break
                        last_size = size
                    except:
                        pass
                
                threats = av.analyze_file(filepath)
                if threats:
                    msg = f"[!] SUSPICIOUS: {os.path.basename(filepath)}\n"
                    for threat, _ in threats:
                        msg += f"  {threat.name}\n"
                    print(msg)
                    notify_windows("[ANTIVIRUS] SUSPICIOUS!", os.path.basename(filepath))
                else:
                    print(f"[+] CLEAN: {filepath}")
                    notify_windows("[ANTIVIRUS] Clean", "File OK")
        
        print(f"Watching: {args.watch}")
        print("Press Ctrl+C to stop")
        
        observer = Observer()
        observer.schedule(Handler(), args.watch, recursive=False)
        observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
        return 0
    
    if args.path is None:
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        if os.path.isdir(downloads):
            args.watch = downloads
            args.path = None
        else:
            print("Usage: antivirus <path> [-r] [-v] [-w DIR]")
            return 0
    
    if args.path:
        av = Antivirus(verbose=args.verbose)
        print(f"Starting scan: {args.path}")
        results = av.scan_path(args.path, recursive=args.recursive)
        print_results(results, av)
        return 1 if results["infected"] else 0
    
    return 0


if __name__ == "__main__":
    sys.exit(main())