"""
Recursive decoding chains (multi-pass decoders).
"""
from core.decoder import try_decodings
from core.search import search_for_flags
import base64
import json
import re

def recursive_decode(payload, max_depth=3):
    """
    Recursively decode nested payloads.
    """
    decoded = payload
    for _ in range(max_depth):
        try:
            # Attempt Base64 decoding
            decoded = base64.b64decode(decoded).decode("utf-8")
        except:
            pass
        try:
            # Attempt JSON parsing
            decoded = json.loads(decoded)
        except:
            pass
    return decoded

def recursive_decode_and_search(s, max_depth=3, patterns=None):
    """
    Recursively decode nested payloads and search for patterns.
    """
    decoded = recursive_decode(s, max_depth)
    matches = []
    if patterns:
        for pattern in patterns:
            matches.extend(re.findall(pattern, decoded))
    return matches

def recursive_decode_and_search_old(s, max_depth=3):
    found = []
    seen = set()
    queue = [(s, 0)]
    while queue:
        cur, depth = queue.pop(0)
        if cur in seen or depth > max_depth:
            continue
        seen.add(cur)
        # check flags
        if search_for_flags(cur):
            found.append((cur, depth))
        # try decodings
        decs = try_decodings(cur)
        for d in decs:
            if d not in seen:
                queue.append((d, depth+1))
    return found
