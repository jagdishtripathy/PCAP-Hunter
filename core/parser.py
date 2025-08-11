# core/parser.py
import os
import subprocess
import tempfile
from scapy.all import PcapReader, Raw, TCP, UDP, IP, rdpcap
from typing import Dict, List, Generator, Optional
from utils.tshark_utils import run_tshark
import logging
import json

log = logging.getLogger(__name__)

class PCAPParser:
    def __init__(self, use_tshark=True):
        self.use_tshark = use_tshark
        self.temp_dir = tempfile.mkdtemp()
        
    def parse_pcap(self, pcap_file: str, protocols: Optional[List[str]] = None) -> List[Dict]:
        """Parse PCAP file and return list of packet dictionaries"""
        if self.use_tshark and self._check_tshark():
            return self._parse_with_tshark(pcap_file, protocols)
        else:
            return self._parse_with_scapy(pcap_file, protocols)
    
    def _check_tshark(self) -> bool:
        """Check if tshark is available"""
        # Common tshark installation paths
        tshark_paths = [
            "tshark",  # In PATH
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"C:\Windows\System32\tshark.exe",
        ]
        
        for tshark_path in tshark_paths:
            try:
                subprocess.run([tshark_path, "--version"], 
                             capture_output=True, check=True)
                # Store the working path for later use
                self.tshark_path = tshark_path
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        log.warning("tshark not found, falling back to scapy")
        return False
    
    def _parse_with_tshark(self, pcap_file: str, protocols: Optional[List[str]]) -> List[Dict]:
        """Parse PCAP using tshark for better protocol detection"""
        packets = []
        
        # Build tshark command
        cmd = ["tshark", "-r", pcap_file, "-T", "json", "-x"]
        
        if protocols and len(protocols) > 0 and any(protocols):
            # Filter out empty strings and add protocol filters
            valid_protocols = [proto for proto in protocols if proto and proto.strip()]
            if valid_protocols:
                proto_filter = " or ".join([f"frame.protocols contains '{proto.strip()}'" for proto in valid_protocols])
                cmd.extend(["-Y", proto_filter])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            tshark_data = json.loads(result.stdout)
            
            for packet_data in tshark_data:
                packet = self._parse_tshark_packet(packet_data)
                if packet:
                    packets.append(packet)
                    
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            log.error(f"tshark parsing failed: {e}")
            return self._parse_with_scapy(pcap_file, protocols)
            
        return packets
    
    def _parse_tshark_packet(self, packet_data: Dict) -> Optional[Dict]:
        """Parse individual tshark packet data"""
        try:
            layers = packet_data.get("_source", {}).get("layers", {})
            
            packet = {
                "index": int(packet_data.get("_index", 0)),
                "time": float(packet_data.get("_source", {}).get("frame", {}).get("frame_time_epoch", 0)),
                "src": "-",
                "dst": "-",
                "protocol": "unknown",
                "payload": "",
                "payload_bytes": b"",
                "port_src": 0,
                "port_dst": 0
            }
            
            # Extract IP addresses
            if "ip" in layers:
                packet["src"] = layers["ip"].get("ip_src", "-")
                packet["dst"] = layers["ip"].get("ip_dst", "-")
            
            # Extract ports and protocol info
            if "tcp" in layers:
                packet["protocol"] = "TCP"
                packet["port_src"] = int(layers["tcp"].get("tcp_srcport", 0))
                packet["port_dst"] = int(layers["tcp"].get("tcp_dstport", 0))
            elif "udp" in layers:
                packet["protocol"] = "UDP"
                packet["port_src"] = int(layers["udp"].get("udp_srcport", 0))
                packet["port_dst"] = int(layers["udp"].get("udp_dstport", 0))
            
            # Extract payload
            if "data" in layers:
                hex_data = layers["data"].get("data_data", "")
                try:
                    packet["payload_bytes"] = bytes.fromhex(hex_data.replace(":", ""))
                    packet["payload"] = packet["payload_bytes"].decode("utf-8", errors="ignore")
                except ValueError:
                    pass
            
            # Try to detect application layer protocol
            packet = self._parse_protocol_specific(layers, packet)
            
            return packet
            
        except Exception as e:
            log.debug(f"Failed to parse tshark packet: {e}")
            return None
    
    def _parse_protocol_specific(self, layers: Dict, packet: Dict) -> Dict:
        """Parse protocol-specific information"""
        # HTTP detection
        if "http" in layers:
            packet["protocol"] = "HTTP"
        elif "ftp" in layers:
            packet["protocol"] = "FTP"
        elif "dns" in layers:
            packet["protocol"] = "DNS"
        elif "smtp" in layers:
            packet["protocol"] = "SMTP"
        elif "tls" in layers:
            packet["protocol"] = "TLS"
        elif "ssh" in layers:
            packet["protocol"] = "SSH"
        
        return packet
    
    def _parse_with_scapy(self, pcap_file: str, protocols: Optional[List[str]]) -> List[Dict]:
        """Parse PCAP using scapy as fallback"""
        packets = []
        
        try:
            raw_packets = rdpcap(pcap_file)
            
            for idx, pkt in enumerate(raw_packets):
                packet = self._parse_scapy_packet(pkt, idx)
                if packet and self._should_include_packet(packet, protocols or []):
                    packets.append(packet)
                    
        except Exception as e:
            log.error(f"Scapy parsing failed: {e}")
            
        return packets
    
    def _parse_scapy_packet(self, pkt, idx: int) -> Optional[Dict]:
        """Parse individual scapy packet"""
        try:
            packet = {
                "index": idx,
                "time": float(getattr(pkt, 'time', 0)),
                "src": "-",
                "dst": "-",
                "protocol": "unknown",
                "payload": "",
                "payload_bytes": b"",
                "port_src": 0,
                "port_dst": 0
            }
            
            # Extract IP layer info
            if IP in pkt:
                packet["src"] = pkt[IP].src
                packet["dst"] = pkt[IP].dst
            
            # Extract TCP/UDP layer info
            if TCP in pkt:
                packet["protocol"] = "TCP"
                packet["port_src"] = pkt[TCP].sport
                packet["port_dst"] = pkt[TCP].dport
            elif UDP in pkt:
                packet["protocol"] = "UDP"
                packet["port_src"] = pkt[UDP].sport
                packet["port_dst"] = pkt[UDP].dport
            
            # Extract payload
            if Raw in pkt:
                packet["payload_bytes"] = bytes(pkt[Raw].load)
                packet["payload"] = packet["payload_bytes"].decode("utf-8", errors="ignore")
            
            # Try to detect application protocol
            if packet["port_dst"] == 80 or packet["port_dst"] == 443:
                packet["protocol"] = "HTTP/HTTPS"
            elif packet["port_dst"] == 21:
                packet["protocol"] = "FTP"
            elif packet["port_dst"] == 53:
                packet["protocol"] = "DNS"
            elif packet["port_dst"] == 25:
                packet["protocol"] = "SMTP"
            elif packet["port_dst"] == 22:
                packet["protocol"] = "SSH"
            
            return packet
            
        except Exception as e:
            log.debug(f"Failed to parse scapy packet {idx}: {e}")
            return None
    
    def _should_include_packet(self, packet: Dict, protocols: List[str]) -> bool:
        """Check if packet should be included based on protocol filter"""
        if not protocols:
            return True
        return packet["protocol"].lower() in [p.lower() for p in protocols]
    
    def __del__(self):
        """Cleanup temporary directory"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass

def parse_pcap(pcap_file: str, protocols: Optional[List[str]] = None, use_tshark: bool = True) -> List[Dict]:
    """Convenience function to parse PCAP file"""
    parser = PCAPParser(use_tshark=use_tshark)
    return parser.parse_pcap(pcap_file, protocols)

def parse_with_scapy(pcap_file, protocols=None):
    """
    Fallback parsing using scapy.
    """
    from scapy.all import rdpcap
    packets = rdpcap(pcap_file)
    # Add protocol filtering logic for scapy here
    return packets
