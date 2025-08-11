"""
Steganography helpers: basic file extraction checks and strings scan for images/archives.
"""
import os
from pathlib import Path
import subprocess

def scan_file_for_strings(file_path):
    results = []
    try:
        with open(file_path, 'rb') as fh:
            data = fh.read()
            # basic strings extraction
            current = []
            for b in data:
                if 32 <= b < 127:
                    current.append(b)
                else:
                    if len(current) >= 6:
                        s = bytes(current).decode('latin-1', errors='ignore')
                        if any(k in s for k in ['flag', 'CTF', 'picoCTF', 'FLAG']):
                            results.append(s)
                    current = []
            # tail
            if len(current) >= 6:
                s = bytes(current).decode('latin-1', errors='ignore')
                if any(k in s for k in ['flag', 'CTF', 'picoCTF', 'FLAG']):
                    results.append(s)
    except Exception:
        pass
    return results

def try_extract_image_bytes(payload_bytes, out_dir):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    out_paths = []
    try:
        # JPEG
        jpos = payload_bytes.find(b'\xff\xd8')
        if jpos != -1:
            eps = payload_bytes.find(b'\xff\xd9', jpos)
            if eps != -1:
                imgb = payload_bytes[jpos:eps+2]
                out = os.path.join(out_dir, f'extracted_{jpos}.jpg')
                with open(out, 'wb') as fh:
                    fh.write(imgb)
                out_paths.append(out)
        # PNG
        ppos = payload_bytes.find(b'\x89PNG')
        if ppos != -1:
            eps = payload_bytes.find(b'IEND', ppos)
            if eps != -1:
                imgb = payload_bytes[ppos:eps+8]
                out = os.path.join(out_dir, f'extracted_{ppos}.png')
                with open(out, 'wb') as fh:
                    fh.write(imgb)
                out_paths.append(out)
    except Exception:
        pass
    return out_paths

def scan_for_steganography(file_path):
    try:
        binwalk_cmd = ["binwalk", file_path]
        zsteg_cmd = ["zsteg", file_path]
        subprocess.run(binwalk_cmd, check=True)
        subprocess.run(zsteg_cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Steganography scan failed: {e}")
