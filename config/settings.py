# config/settings.py

# PCAP Processing Settings
PCAP_READ_TIMEOUT = 60
PCAP_CHUNK_SIZE = 1024 * 1024  # 1MB chunks
MAX_PACKET_SIZE = 65535
MIN_PAYLOAD_SIZE = 10

# Protocol Settings
DEFAULT_PROTOCOLS = ["http", "ftp", "dns", "smtp", "ssh", "telnet"]
PRIORITY_PROTOCOLS = ["http", "https", "ftp", "dns"]
IGNORED_PROTOCOLS = ["arp", "stp", "cdp"]

# Analysis Settings
DEFAULT_DECODE_PASSES = 3
MAX_DECODE_PASSES = 10
ENTROPY_THRESHOLD = 7.5
TIMING_ANALYSIS_WINDOW = 1000  # milliseconds
MAX_PACKETS_FOR_ANALYSIS = 10000

# File Extraction Settings
MAX_EXTRACTED_FILE_SIZE = 100 * 1024 * 1024  # 100MB
SUPPORTED_ARCHIVES = [".zip", ".rar", ".tar", ".gz", ".bz2", ".7z"]
SUPPORTED_IMAGES = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"]
SUPPORTED_DOCUMENTS = [".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt"]
SUPPORTED_SPREADSHEETS = [".xls", ".xlsx", ".csv", ".ods"]

# Steganography Settings
STEGO_SCAN_DEPTH = 3
STEGO_MIN_STRING_LENGTH = 6
STEGO_ENTROPY_THRESHOLD = 6.0

# Covert Channel Settings
DNS_TXT_MIN_LENGTH = 10
ICMP_PAYLOAD_MIN_SIZE = 8
ICMP_PAYLOAD_MAX_SIZE = 1024

# Obfuscation Analysis Settings
XOR_BRUTEFORCE_KEYS = list(range(1, 256))  # 1-255
XOR_MIN_PAYLOAD_SIZE = 20
XOR_MAX_KEYS_TO_TEST = 50

# Output Settings
DEFAULT_OUTPUT_DIR = "output"
LOG_FILE = "pcap_hunter.log"
REPORT_FORMATS = ["json", "txt", "csv", "html"]
MAX_FINDINGS_PER_REPORT = 1000

# Performance Settings
DEFAULT_THREAD_COUNT = 1
MAX_THREAD_COUNT = 8
BATCH_SIZE = 100
PROGRESS_UPDATE_INTERVAL = 100

# Logging Settings
LOG_LEVELS = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "error": 40,
    "critical": 50
}
DEFAULT_LOG_LEVEL = "info"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Search Settings
SEARCH_TIMEOUT = 30
MAX_SEARCH_RESULTS = 10000
FUZZY_MATCH_THRESHOLD = 0.8

# Network Settings
DEFAULT_TIMEOUT = 5
MAX_RETRIES = 3
BUFFER_SIZE = 8192

# Security Settings
MAX_FILE_DEPTH = 10
BLOCKED_EXTENSIONS = [".exe", ".bat", ".cmd", ".com", ".scr", ".pif"]
ALLOWED_IP_RANGES = ["0.0.0.0/0"]  # All IPs allowed by default
BLOCKED_IP_RANGES = []  # No IPs blocked by default

# Advanced Analysis Settings
TIMING_ANALYSIS_ENABLED = True
ENTROPY_ANALYSIS_ENABLED = True
STEGANOGRAPHY_ANALYSIS_ENABLED = True
COVERT_CHANNEL_ANALYSIS_ENABLED = True
OBFUSCATION_ANALYSIS_ENABLED = True
NESTED_PARSER_ENABLED = True

# Memory Management
MAX_MEMORY_USAGE = 1024 * 1024 * 1024  # 1GB
GARBAGE_COLLECTION_INTERVAL = 1000
CACHE_SIZE = 1000