# 🎯 PCAP Hunter - Advanced Network Traffic Analysis Tool

**PCAP Hunter** is a comprehensive tool for cybersecurity professionals and CTF participants to discover hidden data, flags, and embedded files within PCAP (Packet Capture) files.

---

## ✨ Features

### 🔍 **Core Analysis Capabilities**
- **Flag Detection**: Automatically identifies CTF flags, crypto hashes, and hidden patterns.
- **File Extraction**: Extracts embedded files, executables, and compressed archives.
- **Protocol Analysis**: Deep inspection of HTTP, HTTPS, DNS, FTP, and other protocols.
- **Payload Analysis**: Comprehensive payload examination with multiple decoding passes.

### 🧠 **Advanced Analysis Modes**
- **Steganography Detection**: Identifies hidden data in packet timing and payloads.
- **Covert Channel Analysis**: Detects DNS tunneling, ICMP payload manipulation.
- **Entropy Analysis**: Identifies encrypted/compressed data through statistical analysis.
- **Timing Analysis**: Uncovers timing-based covert channels and anomalies.
- **Obfuscation Detection**: Brute-force XOR and other encoding schemes.

### 🚀 **Performance & Usability**
- **Multi-threaded Processing**: Configurable threading for large PCAP files.
- **Smart Filtering**: Protocol-specific analysis and customizable search patterns.
- **Comprehensive Reporting**: JSON, text, and structured output formats.
- **Progress Tracking**: Real-time analysis progress and status updates.

---

## 📋 Feature Overview

| Feature                  | Status        | Implementation                     |
|--------------------------|---------------|-------------------------------------|
| **Multi-Protocol Scan**  | ✅ Available  | `--protocols http,ftp,dns`         |
| **Flag Pattern Detection** | ✅ Available | Preloaded regex patterns + `--pattern` |
| **Packet & Stream Tracing** | ✅ Available | Packet number, timestamp, src/dst IP saved |
| **Text & File Extraction** | ✅ Available | HTTP downloads, transferred files auto-save |
| **Keyword Search Mode**  | ✅ Available  | `--keyword "secret"`               |
| **Auto-Encoding Detection** | ✅ Available | Base64, Hex, URL encoding detection |
| **Multi-pass Decoding**  | ✅ Available  | `--decode-passes` for nested encodings |
| **Crypto Pattern Hints** | ✅ Available  | MD5, SHA1, SHA256 detection        |
| **TShark Integration**   | ✅ Available  | Wireshark CLI integration          |
| **Multi-threaded Parsing** | ✅ Available | `--threads` option                 |
| **Quick Summary Mode**   | ✅ Available  | Protocol distribution, packet count |
| **Advanced Mode**        | ✅ Available  | `--mode advanced`                  |
| **Steganography Detection** | ✅ Available | Basic stego scan with binwalk/zsteg |
| **Entropy Analysis**     | ✅ Available  | Statistical randomness detection   |
| **Timing Analysis**      | ✅ Available  | Packet timing pattern detection    |
| **Export & Report**      | ✅ Available  | JSON, TXT, structured output       |

---

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone <your-repo-url>
cd pcap-hunter

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
```bash
# Quick flag hunting
python main.py -f capture.pcap

# Advanced analysis
python main.py -f capture.pcap --mode advanced

# Search for specific keywords
python main.py -f capture.pcap --keyword "secret"

# Custom pattern search
python main.py -f capture.pcap --pattern "flag{.*}"
```

---

## 🔧 Command Line Options

| Option                  | Description                              | Default       |
|-------------------------|------------------------------------------|---------------|
| `-f, --file`            | PCAP file to analyze                    | Required      |
| `-m, --mode`            | Analysis mode: normal/advanced           | normal        |
| `-p, --protocols`       | Comma-separated protocols to analyze     | all           |
| `-k, --keyword`         | Additional keyword to search for         | None          |
| `--pattern`             | Custom regex pattern                    | None          |
| `--decode-passes`       | Maximum decoding attempts               | 3             |
| `--max-packets`         | Limit packets to analyze (0 = all)      | 0             |
| `--min-payload-size`    | Minimum payload size to analyze         | 10            |
| `--save-payloads`       | Save payload data to separate files     | False         |
| `--threads`             | Number of threads for analysis          | 1             |
| `--out`                 | Output directory                        | output        |
| `--no-tshark`           | Disable tshark integration (use scapy only) | False     |
| `-v, --verbose`         | Enable verbose logging                  | False         |
| `--quiet`               | Suppress console output (only log to file) | False     |

---

## 📊 Output

Results are saved to the output directory:
- **`findings.json`**: Detailed flag and pattern matches.
- **`analysis_results.json`**: Statistical analysis summary.
- **`extracted_files.json`**: Information about extracted files.
- **`final_report.txt`**: Human-readable summary report.

### Advanced Analysis Reports
- **`timing_analysis_report.txt`**: Timing-based anomaly detection.
- **`entropy_analysis_report.txt`**: Entropy analysis results.
- **`stego_analysis_report.txt`**: Steganography detection results.

---

## 🧪 Examples

### CTF Challenge Analysis
```bash
# Quick flag hunt in a CTF PCAP
python main.py -f ctf_challenge.pcap --mode advanced

# Look for specific flag format
python main.py -f ctf_challenge.pcap --pattern "picoCTF{.*}"
```

### Network Forensics
```bash
# Comprehensive network analysis
python main.py -f incident.pcap --mode advanced --save-payloads

# Focus on specific protocols
python main.py -f incident.pcap --protocols http,https,dns --keyword "malware"
```

### Performance Tuning
```bash
# Large file analysis with threading
python main.py -f large_capture.pcap --threads 4 --max-packets 10000

# Quick sample analysis
python main.py -f large_capture.pcap --max-packets 1000 --min-payload-size 50
```

---

## 🏗️ Architecture

```
PCAP Hunter/
├── core/                 # Core analysis modules
│   ├── parser.py        # PCAP parsing and packet extraction
│   ├── search.py        # Pattern matching and flag detection
│   ├── decoder.py       # Multi-layer decoding
│   ├── extractor.py     # File extraction
│   └── exporter.py      # Results export
├── advanced/            # Advanced analysis modules
│   ├── stego.py        # Steganography detection
│   ├── entropy_analysis.py # Entropy analysis
│   ├── timing_analysis.py  # Timing analysis
│   └── covert_channels.py  # Covert channel detection
├── config/              # Configuration files
├── utils/               # Utility functions
└── tests/               # Test suite
```

---

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_search.py -v

# Run with coverage
python -m pytest tests/ --cov=core --cov=advanced
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ for the cybersecurity community**

*PCAP Hunter - Uncover the hidden, decode the encoded, find the flags.*
