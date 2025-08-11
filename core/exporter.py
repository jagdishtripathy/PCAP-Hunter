# core/exporter.py
import json
import os
import csv
from pathlib import Path
from typing import List, Dict, Any
import logging
from scapy.all import wrpcap

logger = logging.getLogger(__name__)

def save_findings(findings: List[Dict[str, Any]], out_dir: str) -> str:
    """Save findings to JSON file"""
    output_file = os.path.join(out_dir, "findings.json")
    try:
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(findings, f, indent=4, ensure_ascii=False, default=str)
        logger.info(f"Findings saved to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Failed to save findings: {e}")
        raise

def save_findings_csv(findings: List[Dict[str, Any]], out_dir: str) -> str:
    """Save findings to CSV file for easy analysis"""
    output_file = os.path.join(out_dir, "findings.csv")
    try:
        if not findings:
            logger.warning("No findings to export to CSV")
            return ""
        
        # Flatten findings for CSV export
        csv_rows = []
        for finding in findings:
            packet_info = finding.get("packet_info", {})
            flags = finding.get("flags", {})
            keywords = finding.get("keywords", [])
            custom_patterns = finding.get("custom_patterns", [])
            
            row = {
                "packet_index": packet_info.get("index", ""),
                "timestamp": packet_info.get("time", ""),
                "source_ip": packet_info.get("src", ""),
                "dest_ip": packet_info.get("dst", ""),
                "protocol": packet_info.get("protocol", ""),
                "source_port": packet_info.get("port_src", ""),
                "dest_port": packet_info.get("port_dst", ""),
                "flags_found": "; ".join(flags.get("all", [])),
                "keywords_found": "; ".join([k.get("keyword", "") for k in keywords]),
                "custom_patterns": "; ".join(custom_patterns),
                "payload_preview": finding.get("payload_preview", "")
            }
            csv_rows.append(row)
        
        if csv_rows:
            fieldnames = csv_rows[0].keys()
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_rows)
            
            logger.info(f"Findings exported to CSV: {output_file}")
            return output_file
        
    except Exception as e:
        logger.error(f"Failed to export findings to CSV: {e}")
        raise
    
    return ""

def save_analysis_results(results: Dict[str, Any], out_dir: str) -> str:
    """Save analysis results to JSON file"""
    output_file = os.path.join(out_dir, "analysis_results.json")
    try:
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False, default=str)
        logger.info(f"Analysis results saved to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Failed to save analysis results: {e}")
        raise

def save_extracted_files_info(files: List[Dict[str, Any]], out_dir: str) -> str:
    """Save extracted files information to JSON file"""
    output_file = os.path.join(out_dir, "extracted_files.json")
    try:
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(files, f, indent=4, ensure_ascii=False, default=str)
        logger.info(f"Extracted files info saved to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Failed to save extracted files info: {e}")
        raise

def export_summary_report(summary_data: Dict[str, Any], out_dir: str) -> str:
    """Export a human-readable summary report"""
    output_file = os.path.join(out_dir, "summary_report.txt")
    try:
        with open(output_file, "w", encoding='utf-8') as f:
            f.write("PCAP Hunter - Analysis Summary Report\n")
            f.write("=" * 50 + "\n\n")
            
            # Basic summary
            if "summary" in summary_data:
                f.write("PCAP File Summary:\n")
                summary = summary_data["summary"]
                for key, value in summary.items():
                    f.write(f"  {key.title()}: {value}\n")
                f.write("\n")
            
            # Findings summary
            if "findings_count" in summary_data:
                f.write(f"Total Findings: {summary_data['findings_count']}\n")
            
            if "extracted_files_count" in summary_data:
                f.write(f"Files Extracted: {summary_data['extracted_files_count']}\n")
            
            # Analysis results summary
            if "analysis_results" in summary_data:
                f.write("\nAdvanced Analysis Results:\n")
                analysis = summary_data["analysis_results"]
                
                for analysis_type, result in analysis.items():
                    if isinstance(result, dict) and "error" not in result:
                        if analysis_type == "timing":
                            suspicious_count = len(result.get("suspicious_intervals", []))
                            f.write(f"  Timing Analysis: {suspicious_count} suspicious intervals\n")
                        elif analysis_type == "entropy":
                            suspicious_count = len(result.get("suspicious_packets", []))
                            f.write(f"  Entropy Analysis: {suspicious_count} suspicious packets\n")
                        elif analysis_type == "covert_channels":
                            dns_count = len(result.get("dns_txt", []))
                            icmp_count = len(result.get("icmp_payloads", []))
                            f.write(f"  Covert Channels: {dns_count} DNS TXT, {icmp_count} ICMP payloads\n")
                        elif analysis_type == "obfuscation":
                            f.write(f"  Obfuscation: {len(result)} packets with XOR candidates\n")
                        elif analysis_type == "nested_parser":
                            f.write(f"  Nested Parser: {len(result)} decoding chains found\n")
                    else:
                        f.write(f"  {analysis_type.title()}: Error occurred\n")
            
            f.write("\nReport generated by PCAP Hunter\n")
        
        logger.info(f"Summary report saved to {output_file}")
        return output_file
        
    except Exception as e:
        logger.error(f"Failed to export summary report: {e}")
        raise

def export_all_results(findings: List[Dict[str, Any]], 
                      analysis_results: Dict[str, Any], 
                      extracted_files: List[Dict[str, Any]], 
                      out_dir: str) -> Dict[str, str]:
    """Export all results in multiple formats"""
    exported_files = {}
    
    try:
        # Create output directory if it doesn't exist
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        
        # Export findings
        if findings:
            exported_files["findings_json"] = save_findings(findings, out_dir)
            exported_files["findings_csv"] = save_findings_csv(findings, out_dir)
        
        # Export analysis results
        if analysis_results:
            exported_files["analysis_results"] = save_analysis_results(analysis_results, out_dir)
        
        # Export extracted files info
        if extracted_files:
            exported_files["extracted_files"] = save_extracted_files_info(extracted_files, out_dir)
        
        # Export summary report
        summary_data = {
            "findings_count": len(findings),
            "extracted_files_count": len(extracted_files),
            "analysis_results": analysis_results
        }
        exported_files["summary_report"] = export_summary_report(summary_data, out_dir)
        
        logger.info(f"All results exported to {out_dir}")
        return exported_files
        
    except Exception as e:
        logger.error(f"Failed to export all results: {e}")
        raise

def export_flagged_packets(packets, output_file):
    """
    Save flagged packets to a new PCAP file.
    """
    wrpcap(output_file, packets)
