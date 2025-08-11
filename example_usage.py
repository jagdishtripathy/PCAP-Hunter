#!/usr/bin/env python3
"""
Example usage of PCAP Hunter
Demonstrates how to use the tool programmatically
"""

from core.parser import parse_pcap
from core.search import search_for_flags
from core.decoder import try_decodings
from core.extractor import extract_files_from_pcap

def analyze_pcap_example(pcap_file: str):
    """Example of analyzing a PCAP file"""
    
    print(f"🔍 Analyzing {pcap_file}...")
    
    # Parse PCAP file
    packets = parse_pcap(pcap_file, use_tshark=False)
    print(f"📦 Found {len(packets)} packets")
    
    # Search for flags in each packet
    findings = []
    for i, packet in enumerate(packets):
        payload = packet.get("payload", "")
        if payload:
            flags = search_for_flags(payload)
            if flags["all"]:
                findings.append({
                    "packet": i,
                    "flags": flags["all"],
                    "payload_preview": payload[:100]
                })
    
    print(f"🎯 Found {len(findings)} packets with flags")
    
    # Extract files
    extracted = extract_files_from_pcap(packets, "output")
    print(f"📁 Extracted {len(extracted)} files")
    
    return findings, extracted

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python example_usage.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    findings, extracted = analyze_pcap_example(pcap_file)
    
    print("\n--- Results ---")
    for finding in findings[:5]:  # Show first 5
        print(f"Packet {finding['packet']}: {finding['flags']}")
        print(f"  Preview: {finding['payload_preview']}")
        print()
