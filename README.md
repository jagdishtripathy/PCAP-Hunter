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
##### Clone the repository
```bash
git clone https://github.com/jagdishtripathy/PCAP-Hunter.git
cd PCAP-Hunter
```
##### Install dependencies
```bash
pip install -r requirements.txt
```

### Basic Usage
##### Quick flag hunting
```bash
python main.py -f <your pcap file>
```
##### Advanced analysis
```bash
python main.py -f <your pcap file> --mode advanced
```
##### Search for specific keywords
```bash
python main.py -f <your pcap file> --keyword "secret"
```
##### Custom pattern search
```bash
python main.py -f <your pcap file> --pattern "flag{.*}"
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
##### Quick flag hunt in a CTF PCAP
```bash
python main.py -f ctf_challenge.pcap --mode advanced
```
##### Look for specific flag format
```bash
python main.py -f ctf_challenge.pcap --pattern "picoCTF{.*}"
```

### Network Forensics
##### Comprehensive network analysis
```bash
python main.py -f incident.pcap --mode advanced --save-payloads
```
##### Focus on specific protocols
```bash
python main.py -f incident.pcap --protocols http,https,dns --keyword "malware"
```

### Performance Tuning
##### Large file analysis with threading
```bash
python main.py -f large_capture.pcap --threads 4 --max-packets 10000
```
##### Quick sample analysis
```bash
python main.py -f large_capture.pcap --max-packets 1000 --min-payload-size 50
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ for the cybersecurity community**

*PCAP Hunter - Uncover the hidden, decode the encoded, find the flags.*
