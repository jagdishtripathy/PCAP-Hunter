#!/usr/bin/env python3
"""
Automated PCAP Flag Hunter - Main CLI Entry Point
A comprehensive tool for finding flags and hidden data in PCAP files
"""
import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Optional

# Core modules
from core.parser import parse_pcap
from core.search import search_for_flags, search_for_keyword, search_for_custom_pattern
from core.decoder import try_decodings
from core.extractor import extract_files_from_pcap
from core.exporter import save_findings, export_flagged_packets
from core import summary as pcap_summary
from core.streams import reassemble_streams
from core.plugin_system import load_plugin

# Advanced modules
from advanced.stego import scan_for_steganography
from advanced.timing_analysis import analyze_packet_timing
from advanced.entropy_analysis import analyze_payload_entropy
from advanced.covert_channels import extract_dns_txt, extract_icmp_payloads
from advanced.obfuscation import single_byte_xor_bruteforce
from advanced.nested_parser import recursive_decode, recursive_decode_and_search

# Utils
from utils import logging_utils as log
from concurrent.futures import ThreadPoolExecutor

class PCAPHunter:
    """Main PCAP Hunter class"""
    
    def __init__(self, args):
        self.args = args
        self.output_dir = Path(args.out)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        log.setup_logging(level=args.verbose)
        self.logger = log.get_logger(__name__)
        
        # Results storage
        self.findings = []
        self.extracted_files = []
        self.analysis_results = {}
        
    def run(self):
        """Main execution flow"""
        start_time = time.time()
        
        self.logger.info("🚀 PCAP Hunter Starting...")
        self.logger.info(f"📁 Target: {self.args.file}")
        self.logger.info(f"🎯 Mode: {self.args.mode}")
        self.logger.info(f"📊 Protocols: {self.args.protocols or 'all'}")
        
        try:
            # Step 1: Generate PCAP summary
            self._generate_summary()
            
            # Step 2: Parse PCAP file
            self._parse_pcap()
            
            # Step 3: Search for flags and patterns
            self._search_patterns()
            
            # Step 4: Extract files
            self._extract_files()
            
            # Step 5: Advanced analysis (if enabled)
            if self.args.mode == "advanced":
                self._run_advanced_analysis()
            
            # Step 6: Save results
            self._save_results()
            
            # Step 7: Generate final report
            self._generate_final_report()
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            # Try to save partial results
            try:
                if self.findings or self.extracted_files:
                    self.logger.info("Saving partial results...")
                    self._save_results()
            except Exception as save_error:
                self.logger.error(f"Failed to save partial results: {save_error}")
            raise
        
        elapsed_time = time.time() - start_time
        self.logger.info(f"Analysis complete in {elapsed_time:.2f} seconds")
        
        # Print summary to console
        self._print_summary()
        
    def _generate_summary(self):
        """Generate PCAP summary"""
        try:
            self.logger.info("Generating PCAP summary...")
            summary = pcap_summary.summarize(self.args.file)
            self.analysis_results["summary"] = summary
            self.logger.info(f"PCAP Summary: {summary}")
        except Exception as e:
            self.logger.warning(f"⚠️Summary generation failed: {e}")
    
    def _parse_pcap(self):
        """Parse PCAP file"""
        self.logger.info("🔍 Parsing PCAP file...")
        
        # Parse protocols
        protocols = None
        if self.args.protocols:
            protocols = [p.strip() for p in self.args.protocols.split(",")]
            self.logger.info(f"🎯 Filtering protocols: {protocols}")
        
        try:
            # Parse PCAP
            self.packets = parse_pcap(
                self.args.file, 
                protocols=protocols,
                use_tshark=not self.args.no_tshark
            )
            
            if not self.packets:
                self.logger.warning("⚠️ No packets found in PCAP file")
                self.packets = []
            else:
                self.logger.info(f"📦 Parsed {len(self.packets)} packets")
                
        except Exception as e:
            self.logger.error(f"Failed to parse PCAP: {e}")
            self.logger.info("Falling back to basic parsing...")
            # Fallback to basic parsing
            try:
                from scapy.all import rdpcap
                raw_packets = rdpcap(self.args.file)
                self.packets = []
                for i, pkt in enumerate(raw_packets):
                    packet = {
                        "index": i,
                        "time": 0.0,
                        "src": str(pkt.getlayer('IP').src) if pkt.haslayer('IP') else "-",
                        "dst": str(pkt.getlayer('IP').dst) if pkt.haslayer('IP') else "-",
                        "protocol": "Unknown",
                        "payload": "",
                        "payload_bytes": b"",
                        "port_src": 0,
                        "port_dst": 0
                    }
                    
                    # Try to get payload
                    if pkt.haslayer('Raw'):
                        packet["payload_bytes"] = bytes(pkt['Raw'].load)
                        packet["payload"] = packet["payload_bytes"].decode("utf-8", errors="ignore")
                    
                    self.packets.append(packet)
                
                self.logger.info(f"📦 Basic parsing completed: {len(self.packets)} packets")
                
            except Exception as fallback_error:
                self.logger.error(f"Basic parsing also failed: {fallback_error}")
                self.packets = []
    
    def _search_patterns(self):
        """Search for flags and patterns"""
        if not self.packets:
            self.logger.warning("⚠️ No packets to search")
            return
            
        self.logger.info("🔍 Searching for flags and patterns...")
        
        # Prepare custom patterns
        custom_patterns = []
        if self.args.pattern:
            custom_patterns.append(self.args.pattern)
        
        # Search each packet with progress indication
        total_packets = len(self.packets)
        for i, packet in enumerate(self.packets):
            if i % 100 == 0:  # Progress indicator every 100 packets
                self.logger.info(f"🔍 Searching packet {i+1}/{total_packets}")
            
            payload = packet.get("payload", "")
            if not payload:
                continue
            
            try:
                # Search for flags
                flag_results = search_for_flags(payload, search_type="all")
                
                # Search for keywords if specified
                keyword_results = []
                if self.args.keyword:
                    keyword_results = search_for_keyword(payload, self.args.keyword)
                
                # Search for custom patterns
                custom_results = []
                for pattern in custom_patterns:
                    custom_results.extend(search_for_custom_pattern(payload, pattern))
                
                # Check if we found anything
                if (flag_results["all"] or keyword_results or custom_results):
                    finding = {
                        "packet_info": {
                            "index": packet.get("index"),
                            "time": packet.get("time"),
                            "src": packet.get("src"),
                            "dst": packet.get("dst"),
                            "protocol": packet.get("protocol"),
                            "port_src": packet.get("port_src"),
                            "port_dst": packet.get("port_dst")
                        },
                        "flags": flag_results,
                        "keywords": keyword_results,
                        "custom_patterns": custom_results,
                        "payload_preview": payload[:200] + "..." if len(payload) > 200 else payload
                    }
                    
                    # Try decoding
                    if flag_results["all"] or custom_results:
                        try:
                            decoded_data = [item.get("keyword", "") for item in keyword_results]
                            decoded_data.extend(flag_results["all"])
                            decoded_data.extend(custom_results)
                            
                            decode_results = try_decodings(
                                decoded_data, 
                                max_passes=self.args.decode_passes,
                                custom_patterns=custom_patterns
                            )
                            finding["decoded"] = decode_results
                        except Exception as decode_error:
                            self.logger.debug(f"Decoding failed for packet {i}: {decode_error}")
                            finding["decoded"] = {"error": str(decode_error)}
                    
                    self.findings.append(finding)
                    
            except Exception as search_error:
                self.logger.debug(f"Search failed for packet {i}: {search_error}")
                continue
        
        self.logger.info(f"🎯 Found {len(self.findings)} packets with potential flags/patterns")
    
    def _extract_files(self):
        """Extract files from PCAP"""
        if not self.packets:
            self.logger.warning("⚠️ No packets to extract files from")
            return
            
        self.logger.info("📁 Extracting files...")
        
        try:
            self.extracted_files = extract_files_from_pcap(self.packets, str(self.output_dir))
            self.logger.info(f"📁 Extracted {len(self.extracted_files)} files")
        except Exception as e:
            self.logger.warning(f"⚠️ File extraction failed: {e}")
            self.extracted_files = []
    
    def _run_advanced_analysis(self):
        """Run advanced analysis modules"""
        if not self.packets:
            self.logger.warning("⚠️ No packets for advanced analysis")
            return
            
        self.logger.info("🧠 Running advanced analysis...")
        
        # Apply packet limits if specified
        if self.args.max_packets > 0 and len(self.packets) > self.args.max_packets:
            self.logger.info(f"📊 Limiting analysis to {self.args.max_packets} packets")
            self.packets = self.packets[:self.args.max_packets]
        
        # Filter packets by payload size
        if self.args.min_payload_size > 0:
            original_count = len(self.packets)
            self.packets = [p for p in self.packets if len(p.get("payload_bytes", b"")) >= self.args.min_payload_size]
            self.logger.info(f"📊 Filtered to {len(self.packets)} packets with payload >= {self.args.min_payload_size} bytes")
        
        # Save payloads if requested
        if self.args.save_payloads:
            self._save_payloads()
        
        # Timing analysis
        try:
            self.logger.info("⏱️ Analyzing packet timing...")
            timing_results = analyze_packet_timing(self.packets, str(self.output_dir))
            self.analysis_results["timing"] = timing_results
        except Exception as e:
            self.logger.warning(f"⚠️ Timing analysis failed: {e}")
            self.analysis_results["timing"] = {"error": str(e)}
        
        # Entropy analysis
        try:
            self.logger.info("📊 Analyzing payload entropy...")
            entropy_results = analyze_payload_entropy(self.packets, str(self.output_dir))
            self.analysis_results["entropy"] = entropy_results
        except Exception as e:
            self.logger.warning(f"⚠️ Entropy analysis failed: {e}")
            self.analysis_results["entropy"] = {"error": str(e)}
        
        # Steganography analysis on extracted files
        try:
            self.logger.info("🕵️ Scanning for steganography...")
            for file_info in self.extracted_files:
                if "saved_path" in file_info:
                    try:
                        scan_for_steganography(file_info["saved_path"])
                    except Exception as e:
                        self.logger.debug(f"Steganography scan failed for {file_info['saved_path']}: {e}")
        except Exception as e:
            self.logger.warning(f"⚠️ Steganography analysis failed: {e}")
        
        # Covert channels analysis
        try:
            self.logger.info("🔍 Analyzing covert channels...")
            dns_txts = extract_dns_txt(self.args.file)
            icmp_payloads = extract_icmp_payloads(self.args.file)
            
            if dns_txts or icmp_payloads:
                self.analysis_results["covert_channels"] = {
                    "dns_txt": dns_txts,
                    "icmp_payloads": [str(p) for p in icmp_payloads[:10]]  # Limit output
                }
                self.logger.info(f"🔍 Found {len(dns_txts)} DNS TXT records and {len(icmp_payloads)} ICMP payloads")
        except Exception as e:
            self.logger.warning(f"⚠️ Covert channels analysis failed: {e}")
            self.analysis_results["covert_channels"] = {"error": str(e)}
        
        # Obfuscation analysis
        try:
            self.logger.info("🔐 Analyzing obfuscation...")
            obfuscation_results = []
            
            for packet in self.packets[:100]:  # Limit to first 100 packets for performance
                payload = packet.get("payload_bytes", b"")
                if payload and len(payload) > 10:
                    xor_candidates = single_byte_xor_bruteforce(payload)
                    if xor_candidates:
                        obfuscation_results.append({
                            "packet_index": packet.get("index"),
                            "xor_candidates": xor_candidates[:3]  # Limit to top 3
                        })
            
            if obfuscation_results:
                self.analysis_results["obfuscation"] = obfuscation_results
                self.logger.info(f"🔐 Found {len(obfuscation_results)} packets with potential XOR obfuscation")
        except Exception as e:
            self.logger.warning(f"⚠️ Obfuscation analysis failed: {e}")
            self.analysis_results["obfuscation"] = {"error": str(e)}
        
        # Nested parser analysis
        try:
            self.logger.info("🔄 Running nested parser analysis...")
            nested_results = []
            
            for finding in self.findings[:20]:  # Limit to first 20 findings
                if finding.get("flags", {}).get("all"):
                    for flag in finding["flags"]["all"][:3]:  # Limit to first 3 flags
                        nested_found = recursive_decode_and_search(flag, max_depth=2)
                        if nested_found:
                            nested_results.append({
                                "original_flag": flag,
                                "nested_findings": nested_found
                            })
            
            if nested_results:
                self.analysis_results["nested_parser"] = nested_results
                self.logger.info(f"🔄 Found {len(nested_results)} nested decoding chains")
        except Exception as e:
            self.logger.warning(f"⚠️ Nested parser analysis failed: {e}")
            self.analysis_results["nested_parser"] = {"error": str(e)}
    
    def _save_payloads(self):
        """Save individual packet payloads to files"""
        if not self.args.save_payloads:
            return
            
        self.logger.info("💾 Saving packet payloads...")
        payloads_dir = self.output_dir / "payloads"
        payloads_dir.mkdir(exist_ok=True)
        
        saved_count = 0
        for i, packet in enumerate(self.packets):
            payload = packet.get("payload_bytes", b"")
            if payload and len(payload) >= self.args.min_payload_size:
                try:
                    # Create filename
                    filename = f"packet_{packet.get('index', i)}_payload.bin"
                    filepath = payloads_dir / filename
                    
                    with open(filepath, 'wb') as f:
                        f.write(payload)
                    
                    saved_count += 1
                except Exception as e:
                    self.logger.debug(f"Failed to save payload {i}: {e}")
        
        self.logger.info(f"💾 Saved {saved_count} payload files to {payloads_dir}")
    
    def _save_results(self):
        """Save analysis results"""
        self.logger.info("💾 Saving results...")
        
        try:
            # Save findings
            if self.findings:
                save_findings(self.findings, str(self.output_dir))
                self.logger.info(f"💾 Saved {len(self.findings)} findings")
            else:
                self.logger.info("💾 No findings to save")
            
            # Save analysis results
            if self.analysis_results:
                import json
                analysis_file = self.output_dir / "analysis_results.json"
                with open(analysis_file, 'w') as f:
                    json.dump(self.analysis_results, f, indent=2, default=str)
                self.logger.info(f"💾 Saved analysis results to {analysis_file}")
            
            # Save extracted files info
            if self.extracted_files:
                import json
                files_file = self.output_dir / "extracted_files.json"
                with open(files_file, 'w') as f:
                    json.dump(self.extracted_files, f, indent=2, default=str)
                self.logger.info(f"💾 Saved extracted files info to {files_file}")
            
            self.logger.info(f"💾 Results saved to {self.output_dir}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            # Try to save at least some results
            try:
                if self.findings:
                    save_findings(self.findings, str(self.output_dir))
            except Exception:
                pass
    
    def _generate_final_report(self):
        """Generate final analysis report"""
        self.logger.info("📋 Generating final report...")
        
        try:
            report_path = self.output_dir / "final_report.txt"
            
            with open(report_path, 'w') as f:
                f.write("PCAP Hunter - Final Analysis Report\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Target File: {self.args.file}\n")
                f.write(f"Analysis Mode: {self.args.mode}\n")
                f.write(f"Protocols: {self.args.protocols or 'all'}\n")
                f.write(f"Analysis Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Summary
                if "summary" in self.analysis_results:
                    f.write("PCAP Summary:\n")
                    summary = self.analysis_results["summary"]
                    for key, value in summary.items():
                        f.write(f"  {key}: {value}\n")
                    f.write("\n")
                
                # Findings
                f.write(f"Flag/Pattern Findings: {len(self.findings)}\n")
                for i, finding in enumerate(self.findings[:10], 1):  # Show first 10
                    packet = finding["packet_info"]
                    f.write(f"  {i}. Packet {packet['index']} ({packet['protocol']}): "
                           f"{packet['src']} -> {packet['dst']}\n")
                    if finding["flags"]["all"]:
                        f.write(f"     Flags: {finding['flags']['all'][:3]}\n")
                    if finding["keywords"]:
                        f.write(f"     Keywords: {len(finding['keywords'])} matches\n")
                f.write("\n")
                
                # Extracted files
                f.write(f"Extracted Files: {len(self.extracted_files)}\n")
                for file_info in self.extracted_files[:5]:  # Show first 5
                    f.write(f"  - {file_info.get('filename', 'unknown')} "
                           f"({file_info.get('type', 'unknown')})\n")
                f.write("\n")
                
                # Advanced analysis results
                if self.args.mode == "advanced":
                    f.write("Advanced Analysis Results:\n")
                    if "timing" in self.analysis_results:
                        timing = self.analysis_results["timing"]
                        if "error" not in timing:
                            f.write(f"  Timing Analysis: {len(timing.get('suspicious_intervals', []))} suspicious intervals\n")
                        else:
                            f.write(f"  Timing Analysis: Error - {timing['error']}\n")
                    
                    if "entropy" in self.analysis_results:
                        entropy = self.analysis_results["entropy"]
                        if "error" not in entropy:
                            f.write(f"  Entropy Analysis: {len(entropy.get('suspicious_packets', []))} suspicious packets\n")
                        else:
                            f.write(f"  Entropy Analysis: Error - {entropy['error']}\n")
                    
                    # Covert channels
                    if "covert_channels" in self.analysis_results:
                        covert = self.analysis_results["covert_channels"]
                        if "error" not in covert:
                            f.write(f"  Covert Channels: {len(covert.get('dns_txt', []))} DNS TXT, {len(covert.get('icmp_payloads', []))} ICMP payloads\n")
                        else:
                            f.write(f"  Covert Channels: Error - {covert['error']}\n")
                    
                    # Obfuscation
                    if "obfuscation" in self.analysis_results:
                        obfusc = self.analysis_results["obfuscation"]
                        if "error" not in obfusc:
                            f.write(f"  Obfuscation: {len(obfusc)} packets with XOR candidates\n")
                        else:
                            f.write(f"  Obfuscation: Error - {obfusc['error']}\n")
                    
                    # Nested parser
                    if "nested_parser" in self.analysis_results:
                        nested = self.analysis_results["nested_parser"]
                        if "error" not in nested:
                            f.write(f"  Nested Parser: {len(nested)} decoding chains found\n")
                        else:
                            f.write(f"  Nested Parser: Error - {nested['error']}\n")
                
                f.write("\nAnalysis Complete!\n")
            
            self.logger.info(f"📋 Final report saved to {report_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate final report: {e}")
            # Try to create a minimal report
            try:
                report_path = self.output_dir / "error_report.txt"
                with open(report_path, 'w') as f:
                    f.write(f"PCAP Hunter - Error Report\n")
                    f.write(f"Analysis failed: {e}\n")
                    f.write(f"Findings found: {len(self.findings)}\n")
                    f.write(f"Files extracted: {len(self.extracted_files)}\n")
                self.logger.info(f"📋 Error report saved to {report_path}")
            except Exception:
                pass

    def _print_summary(self):
        """Print a summary of the analysis results to the console."""
        print("\n--- Analysis Summary ---")
        if "summary" in self.analysis_results:
            print("PCAP Summary:")
            summary = self.analysis_results["summary"]
            for key, value in summary.items():
                print(f"  {key}: {value}")
            print()

        print(f"Total Flag/Pattern Findings: {len(self.findings)}")
        print(f"Total Extracted Files: {len(self.extracted_files)}")

        if self.args.mode == "advanced":
            print("\nAdvanced Analysis Results:")
            if "timing" in self.analysis_results:
                timing = self.analysis_results["timing"]
                if "error" not in timing:
                    print(f"  Timing Analysis: {len(timing.get('suspicious_intervals', []))} suspicious intervals")
            if "entropy" in self.analysis_results:
                entropy = self.analysis_results["entropy"]
                if "error" not in entropy:
                    print(f"  Entropy Analysis: {len(entropy.get('suspicious_packets', []))} suspicious packets")
            if "covert_channels" in self.analysis_results:
                covert = self.analysis_results["covert_channels"]
                print(f"  Covert Channels: {len(covert.get('dns_txt', []))} DNS TXT, {len(covert.get('icmp_payloads', []))} ICMP payloads")
            if "obfuscation" in self.analysis_results:
                obfusc = self.analysis_results["obfuscation"]
                print(f"  Obfuscation: {len(obfusc)} packets with XOR candidates")
            if "nested_parser" in self.analysis_results:
                nested = self.analysis_results["nested_parser"]
                print(f"  Nested Parser: {len(nested)} decoding chains found")
        print("-------------------------\n")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Automated PCAP Flag Hunter - Find flags and hidden data in PCAP files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Normal mode - quick flag hunting
  python main.py -f capture.pcap --protocols http,ftp,dns
  
  # Advanced mode - comprehensive analysis
  python main.py -f capture.pcap --mode advanced --keyword "secret"
  
  # Custom pattern search
  python main.py -f capture.pcap --pattern "myflag{.*}" --decode-passes 5
  
  # Keyword search only
  python main.py -f capture.pcap --keyword "password" --no-tshark
  
  # Performance tuning
  python main.py -f capture.pcap --max-packets 1000 --threads 4
  
  # Save payloads for further analysis
  python main.py -f capture.pcap --save-payloads --min-payload-size 50
  
  # Quiet mode (log to file only)
  python main.py -f capture.pcap --quiet --out detailed_analysis
        """
    )
    
    # Required arguments
    parser.add_argument("-f", "--file", required=True, 
                       help="Path to PCAP file")
    
    # Mode and analysis options
    parser.add_argument("-m", "--mode", choices=["normal", "advanced"], 
                       default="normal", help="Analysis mode (default: normal)")
    parser.add_argument("-p", "--protocols", default="", 
                       help="Comma-separated protocols to prioritize (e.g., http,ftp,dns)")
    parser.add_argument("-k", "--keyword", default=None, 
                       help="Keyword to search for in addition to flags")
    parser.add_argument("--pattern", default=None, 
                       help="Custom regex pattern to search for")
    parser.add_argument("--decode-passes", type=int, default=3, 
                       help="Maximum number of decoding passes (default: 3)")
    
    # Advanced analysis options
    parser.add_argument("--max-packets", type=int, default=0,
                       help="Maximum number of packets to analyze (0 = all)")
    parser.add_argument("--min-payload-size", type=int, default=10,
                       help="Minimum payload size to analyze (default: 10)")
    parser.add_argument("--save-payloads", action="store_true",
                       help="Save payload data to separate files")
    parser.add_argument("--threads", type=int, default=1,
                       help="Number of threads for analysis (default: 1)")
    
    # Output and performance options
    parser.add_argument("--out", default="output", 
                       help="Output directory (default: output)")
    parser.add_argument("--no-tshark", action="store_true", 
                       help="Disable tshark integration (use scapy only)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose logging")
    parser.add_argument("--quiet", action="store_true",
                       help="Suppress console output (only log to file)")
    
    # Plugin argument
    parser.add_argument("--plugin", help="Path to custom plugin script")
    parser.add_argument("--export-pcap", action="store_true", help="Export flagged packets as a new PCAP file")
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.file):
        print(f"Error: PCAP file '{args.file}' not found")
        sys.exit(1)
    
    # Create and run PCAP Hunter
    hunter = PCAPHunter(args)
    
    try:
        hunter.run()
        print(f"\n🎉 Analysis complete! Check the '{args.out}' directory for results.")
    except KeyboardInterrupt:
        print("\n⏹️ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n Analysis failed: {e}")
        sys.exit(1)

    from core.parser import parse_pcap

    packets = parse_pcap(args.file, protocols=args.protocols.split(","))
    # Process packets as needed

    if args.plugin:
        plugin = load_plugin(args.plugin)
        packets = parse_pcap(args.file, protocols=args.protocols.split(","))
        for pkt in packets:
            payload = pkt.get("payload", "")
            plugin_results = plugin.process(payload)
            log.info(f"Plugin results: {plugin_results}")

    flagged_packets = []
    packets = parse_pcap(args.file, protocols=args.protocols.split(","))
    for pkt in packets:
        payload = pkt.get("payload", "")
        flags = search_for_flags(payload)
        if flags:
            flagged_packets.append(pkt)

    if flagged_packets:
        export_flagged_packets(flagged_packets, os.path.join(args.out, "flagged_packets.pcap"))
        log.success(f"Flagged packets saved to flagged_packets.pcap")

    packets = parse_pcap(args.file, protocols=args.protocols.split(","))
    streams = reassemble_streams(args.file)

    for stream_id, stream_data in streams.items():
        flags = search_for_flags(stream_data.decode(errors="ignore"))
        if flags:
            log.success(f"Flags found in stream {stream_id}: {flags}")

if __name__ == "__main__":
    main()