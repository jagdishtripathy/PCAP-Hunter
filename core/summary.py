# core/summary.py
from scapy.all import PcapReader, TCP, UDP, ICMP, IP
import json
import time
from collections import defaultdict, Counter
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

def summarize(pcap_file: str) -> Dict[str, Any]:
    """Generate comprehensive PCAP summary"""
    counts = {
        "total": 0, 
        "tcp": 0, 
        "udp": 0, 
        "icmp": 0, 
        "other": 0,
        "ipv4": 0,
        "ipv6": 0,
        "non_ip": 0
    }
    
    # Protocol-specific counters
    protocols = defaultdict(int)
    ports = defaultdict(int)
    ip_addresses = defaultdict(int)
    packet_sizes = []
    timestamps = []
    
    # Application layer protocols
    app_protocols = defaultdict(int)
    
    try:
        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                counts['total'] += 1
                packet_sizes.append(len(pkt))
                
                try:
                    # IP layer analysis
                    if IP in pkt:
                        counts['ipv4'] += 1
                        ip_src = pkt[IP].src
                        ip_dst = pkt[IP].dst
                        ip_addresses[ip_src] += 1
                        ip_addresses[ip_dst] += 1
                        
                        # Transport layer analysis
                        if TCP in pkt:
                            counts['tcp'] += 1
                            tcp = pkt[TCP]
                            ports[f"TCP:{tcp.sport}"] += 1
                            ports[f"TCP:{tcp.dport}"] += 1
                            
                            # Application layer detection
                            if tcp.sport == 80 or tcp.dport == 80:
                                app_protocols["HTTP"] += 1
                            elif tcp.sport == 443 or tcp.dport == 443:
                                app_protocols["HTTPS"] += 1
                            elif tcp.sport == 21 or tcp.dport == 21:
                                app_protocols["FTP"] += 1
                            elif tcp.sport == 22 or tcp.dport == 22:
                                app_protocols["SSH"] += 1
                            elif tcp.sport == 23 or tcp.dport == 23:
                                app_protocols["Telnet"] += 1
                            elif tcp.sport == 25 or tcp.dport == 25:
                                app_protocols["SMTP"] += 1
                            elif tcp.sport == 110 or tcp.dport == 110:
                                app_protocols["POP3"] += 1
                            elif tcp.sport == 143 or tcp.dport == 143:
                                app_protocols["IMAP"] += 1
                            
                        elif UDP in pkt:
                            counts['udp'] += 1
                            udp = pkt[UDP]
                            ports[f"UDP:{udp.sport}"] += 1
                            ports[f"UDP:{udp.dport}"] += 1
                            
                            # DNS detection
                            if udp.sport == 53 or udp.dport == 53:
                                app_protocols["DNS"] += 1
                            elif udp.sport == 67 or udp.dport == 67:
                                app_protocols["DHCP"] += 1
                            elif udp.sport == 123 or udp.dport == 123:
                                app_protocols["NTP"] += 1
                            
                        elif ICMP in pkt:
                            counts['icmp'] += 1
                            app_protocols["ICMP"] += 1
                        else:
                            counts['other'] += 1
                            
                    else:
                        counts['non_ip'] += 1
                    
                    # Store timestamp if available
                    if hasattr(pkt, 'time'):
                        timestamps.append(pkt.time)
                        
                except Exception as e:
                    logger.debug(f"Error processing packet: {e}")
                    counts['other'] += 1
                    continue
        
        # Calculate statistics
        summary = {
            "file": pcap_file,
            "total_packets": counts['total'],
            "protocols": dict(app_protocols),
            "transport": {
                "tcp": counts['tcp'],
                "udp": counts['udp'],
                "icmp": counts['icmp'],
                "other": counts['other']
            },
            "network": {
                "ipv4": counts['ipv4'],
                "non_ip": counts['non_ip']
            },
            "top_ports": dict(Counter(ports).most_common(10)),
            "top_ips": dict(Counter(ip_addresses).most_common(10)),
            "packet_stats": {
                "min_size": min(packet_sizes) if packet_sizes else 0,
                "max_size": max(packet_sizes) if packet_sizes else 0,
                "avg_size": sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
            }
        }
        
        if timestamps:
            summary["time_range"] = {
                "start": min(timestamps),
                "end": max(timestamps),
                "duration": max(timestamps) - min(timestamps)
            }
        
        return summary
        
    except Exception as e:
        logger.error(f"Failed to summarize PCAP: {e}")
        return {
            "file": pcap_file,
            "error": str(e),
            "total_packets": 0
        }

def get_protocol_summary(pcap_file: str) -> Dict[str, Any]:
    """Get protocol-specific summary"""
    try:
        summary = summarize(pcap_file)
        if "error" in summary:
            return summary
            
        return {
            "file": summary["file"],
            "total_packets": summary["total_packets"],
            "protocols": summary["protocols"],
            "transport": summary["transport"]
        }
    except Exception as e:
        logger.error(f"Failed to get protocol summary: {e}")
        return {"error": str(e)}

def get_traffic_patterns(pcap_file: str) -> Dict[str, Any]:
    """Analyze traffic patterns"""
    try:
        summary = summarize(pcap_file)
        if "error" in summary:
            return summary
            
        return {
            "file": summary["file"],
            "top_ports": summary["top_ports"],
            "top_ips": summary["top_ips"],
            "packet_stats": summary["packet_stats"]
        }
    except Exception as e:
        logger.error(f"Failed to get traffic patterns: {e}")
        return {"error": str(e)}
