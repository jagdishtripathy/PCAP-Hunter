"""
Obfuscation helpers: entropy checks and XOR single-byte brute force.
"""
import math

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for v in freq.values():
        p = v / length
        ent -= p * math.log2(p)
    return ent

def single_byte_xor_bruteforce(data: bytes, min_printable=0.6):
    """
    Try XORing with single byte keys and return candidates that look printable.
    Returns list of (key_int, decoded_text).
    """
    candidates = []
    if not data:
        return candidates
    for key in range(1, 256):
        out = bytes([b ^ key for b in data])
        printable = sum(1 for c in out if 32 <= c < 127)
        ratio = printable / max(1, len(out))
        if ratio >= min_printable:
            try:
                txt = out.decode('utf-8', errors='ignore')
                candidates.append((key, txt))
            except Exception:
                continue
    return candidates
