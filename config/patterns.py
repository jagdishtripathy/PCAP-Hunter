# config/patterns.py
import re

# Standard CTF flag patterns
FLAG_PATTERNS = [
    r"flag\{.*?\}",
    r"FLAG\[\S+\]",
    r"CTF\{.*?\}",
    r"picoCTF\{.*?\}",
    r"flag\[.*?\]",
    r"FLAG\{.*?\}",
    r"ctf\{.*?\}",
    r"PICOCTF\{.*?\}",
    r"flag\(.*?\)",
    r"FLAG\(.*?\)",
    r"flag:.*?",
    r"FLAG:.*?",
    r"key\{.*?\}",
    r"KEY\{.*?\}",
    r"secret\{.*?\}",
    r"SECRET\{.*?\}",
    r"hack\{.*?\}",
    r"HACK\{.*?\}",
    r"root\{.*?\}",
    r"ROOT\{.*?\}"
]

# Extended CTF patterns
EXTENDED_FLAG_PATTERNS = [
    r"flag_[a-zA-Z0-9_]+",
    r"FLAG_[a-zA-Z0-9_]+",
    r"ctf_[a-zA-Z0-9_]+",
    r"CTF_[a-zA-Z0-9_]+",
    r"key_[a-zA-Z0-9_]+",
    r"KEY_[a-zA-Z0-9_]+",
    r"secret_[a-zA-Z0-9_]+",
    r"SECRET_[a-zA-Z0-9_]+",
    r"hint_[a-zA-Z0-9_]+",
    r"HINT_[a-zA-Z0-9_]+"
]

# Crypto hash patterns (MD5, SHA1, SHA256)
CRYPTO_PATTERNS = [
    r"[a-fA-F0-9]{32}",  # MD5
    r"[a-fA-F0-9]{40}",  # SHA1
    r"[a-fA-F0-9]{64}",  # SHA256
    r"[a-fA-F0-9]{128}", # SHA512
    r"[a-fA-F0-9]{96}",  # SHA384
    r"[a-fA-F0-9]{56}",  # SHA224
    r"[a-fA-F0-9]{48}",  # SHA224 (truncated)
    r"[a-fA-F0-9]{24}",  # MD5 (truncated)
    r"[a-fA-F0-9]{16}",  # MD5 (truncated)
    r"[a-fA-F0-9]{8}"    # Short hash
]

# Base64 encoded patterns
BASE64_PATTERNS = [
    r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64 (20+ chars)
    r"[A-Za-z0-9+/]{16,}={0,2}",  # Base64 (16+ chars)
    r"[A-Za-z0-9+/]{12,}={0,2}"   # Base64 (12+ chars)
]

# Hex encoded patterns
HEX_PATTERNS = [
    r"0x[a-fA-F0-9]{8,}",         # Hex with 0x prefix
    r"\\x[a-fA-F0-9]{2}",          # Hex escape sequences
    r"[a-fA-F0-9]{8,}",            # Raw hex (8+ chars)
    r"[a-fA-F0-9]{6,}"             # Raw hex (6+ chars)
]

# URL encoded patterns
URL_ENCODED_PATTERNS = [
    r"%[0-9A-Fa-f]{2}",            # URL encoded characters
    r"\\u[0-9A-Fa-f]{4}",          # Unicode escape sequences
    r"\\x[0-9A-Fa-f]{2}"           # Hex escape sequences
]

# Common keywords that might indicate hidden data
KEYWORD_PATTERNS = [
    r"secret",
    r"hidden",
    r"password",
    r"key",
    r"token",
    r"auth",
    r"private",
    r"confidential",
    r"encrypted",
    r"encoded",
    r"decoded",
    r"cipher",
    r"plaintext",
    r"hint",
    r"clue",
    r"solution",
    r"answer",
    r"flag",
    r"ctf",
    r"challenge",
    r"mission",
    r"objective",
    r"target",
    r"goal",
    r"win",
    r"success",
    r"complete",
    r"finished",
    r"done",
    r"found",
    r"discovered",
    r"revealed",
    r"exposed",
    r"leaked",
    r"stolen",
    r"captured",
    r"obtained",
    r"acquired",
    r"retrieved",
    r"extracted",
    r"recovered",
    r"restored",
    r"repaired",
    r"fixed",
    r"solved",
    r"cracked",
    r"hacked",
    r"breached",
    r"compromised",
    r"infiltrated",
    r"penetrated",
    r"bypassed",
    r"overridden",
    r"overwhelmed",
    r"defeated",
    r"conquered",
    r"dominated",
    r"controlled",
    r"owned",
    r"pwned"
]

# Suspicious patterns that might indicate steganography or hidden data
SUSPICIOUS_PATTERNS = [
    r"stego",
    r"steganography",
    r"lsb",
    r"least significant bit",
    r"hidden message",
    r"concealed",
    r"embedded",
    r"injected",
    r"invisible",
    r"covert",
    r"stealth",
    r"silent",
    r"quiet",
    r"whisper",
    r"murmur",
    r"echo",
    r"shadow",
    r"ghost",
    r"phantom",
    r"specter",
    r"wraith",
    r"spirit",
    r"soul",
    r"essence",
    r"core",
    r"heart",
    r"center",
    r"middle",
    r"inside",
    r"internal",
    r"inner",
    r"deep",
    r"depth",
    r"layer",
    r"level",
    r"tier",
    r"stratum",
    r"plane",
    r"dimension",
    r"realm",
    r"world",
    r"universe",
    r"cosmos",
    r"space",
    r"void",
    r"abyss",
    r"chasm",
    r"gap",
    r"hole",
    r"tunnel",
    r"passage",
    r"corridor",
    r"hallway",
    r"path",
    r"way",
    r"route",
    r"trail",
    r"track",
    r"footprint",
    r"mark",
    r"sign",
    r"symbol",
    r"icon",
    r"emblem",
    r"badge",
    r"medal",
    r"trophy",
    r"prize",
    r"reward",
    r"gift",
    r"present",
    r"treasure",
    r"loot",
    r"booty",
    r"spoils",
    r"riches",
    r"wealth",
    r"fortune",
    r"luck",
    r"chance",
    r"opportunity",
    r"moment",
    r"instant",
    r"second",
    r"minute",
    r"hour",
    r"day",
    r"night",
    r"dawn",
    r"dusk",
    r"sunrise",
    r"sunset",
    r"morning",
    r"evening",
    r"afternoon",
    r"midnight",
    r"noon",
    r"twilight",
    r"gloaming",
    r"daybreak",
    r"nightfall"
]

# Combine all patterns
ALL_PATTERNS = (FLAG_PATTERNS + EXTENDED_FLAG_PATTERNS + CRYPTO_PATTERNS + 
                BASE64_PATTERNS + HEX_PATTERNS + URL_ENCODED_PATTERNS + 
                KEYWORD_PATTERNS + SUSPICIOUS_PATTERNS)

# Compile patterns for better performance
COMPILED_PATTERNS = {
    "flags": [re.compile(pattern, re.IGNORECASE) for pattern in FLAG_PATTERNS],
    "extended_flags": [re.compile(pattern, re.IGNORECASE) for pattern in EXTENDED_FLAG_PATTERNS],
    "crypto": [re.compile(pattern) for pattern in CRYPTO_PATTERNS],
    "base64": [re.compile(pattern) for pattern in BASE64_PATTERNS],
    "hex": [re.compile(pattern) for pattern in HEX_PATTERNS],
    "url_encoded": [re.compile(pattern) for pattern in URL_ENCODED_PATTERNS],
    "keywords": [re.compile(pattern, re.IGNORECASE) for pattern in KEYWORD_PATTERNS],
    "suspicious": [re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS],
    "all": [re.compile(pattern, re.IGNORECASE) for pattern in ALL_PATTERNS]
}

# Pattern categories for organized searching
PATTERN_CATEGORIES = {
    "ctf_flags": FLAG_PATTERNS + EXTENDED_FLAG_PATTERNS,
    "crypto_hashes": CRYPTO_PATTERNS,
    "encoded_data": BASE64_PATTERNS + HEX_PATTERNS + URL_ENCODED_PATTERNS,
    "keywords": KEYWORD_PATTERNS,
    "suspicious": SUSPICIOUS_PATTERNS
}
