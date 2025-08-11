# utils/tshark_utils.py
import shutil
import subprocess
from typing import Optional
import json

def is_tshark_available() -> bool:
    return shutil.which('tshark') is not None

def run_tshark_extract_text(pcap_file: str, display_filter: str = "") -> Optional[str]:
    """
    Returns big text blob extracted by tshark (if available).
    This is optional helper — base code doesn't require tshark.
    """
    if not is_tshark_available():
        return None
    cmd = ['tshark', '-r', pcap_file, '-V']
    if display_filter:
        cmd.extend(['-Y', display_filter])
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=60)
        return out.decode('utf-8', errors='ignore')
    except Exception:
        return None

def extract_raw_data(pcap_file, output_file):
    try:
        cmd = ["tshark", "-r", pcap_file, "-w", output_file]
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"tshark failed: {e}")

def run_tshark(pcap_file, protocol_filter=None):
    """
    Run tshark to parse PCAP files with optional protocol filtering.
    """
    cmd = ['tshark', '-r', pcap_file, '-T', 'json', '-x']
    
    if protocol_filter:  # Add filter only if provided
        cmd += ['-Y', f"frame.protocols contains {protocol_filter}"]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"tshark parsing failed: {result.stderr}")
    
    return json.loads(result.stdout)
