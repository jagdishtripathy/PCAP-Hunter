# core/streams.py
from scapy.all import PcapReader, TCP, IP, UDP, Raw
from collections import defaultdict
import logging
from typing import Dict, List, Tuple, Optional, Any
import re
import pyshark

logger = logging.getLogger(__name__)

def reassemble_tcp_streams(pcap_file: str) -> Dict[Tuple[str, int, str, int], str]:
    """
    Return dict keyed by (src, sport, dst, dport) -> assembled payload (utf-8 or empty string).
    Best-effort reassembly using seq order; not a full TCP stack.
    """
    streams = {}
    try:
        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                try:
                    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                        continue
                    ip = pkt[IP]
                    tcp = pkt[TCP]
                    key = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
                    seq = int(getattr(tcp, 'seq', 0))
                    raw = b""
                    if tcp.payload:
                        raw = bytes(tcp.payload)
                    streams.setdefault(key, []).append((seq, raw))
                except Exception as e:
                    logger.debug(f"Error processing TCP packet: {e}")
                    continue
    except Exception as e:
        logger.error(f"Failed to read PCAP file: {e}")
        return {}

    out = {}
    for k, segments in streams.items():
        try:
            segments.sort(key=lambda x: x[0])
            combined = b"".join(s for _, s in segments)
            try:
                out[k] = combined.decode('utf-8', errors='ignore')
            except Exception:
                out[k] = ''
        except Exception as e:
            logger.debug(f"Error reassembling stream {k}: {e}")
            out[k] = ''
    
    return out

def extract_http_streams(pcap_file: str) -> List[Dict[str, Any]]:
    """Extract HTTP requests and responses from PCAP"""
    http_streams = []
    current_stream = None
    
    try:
        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                try:
                    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                        continue
                    
                    ip = pkt[IP]
                    tcp = pkt[TCP]
                    
                    # Check if this is HTTP traffic (port 80 or 8080)
                    if tcp.sport not in [80, 8080] and tcp.dport not in [80, 8080]:
                        continue
                    
                    # Get payload
                    payload = b""
                    if pkt.haslayer(Raw):
                        payload = bytes(pkt[Raw].load)
                    
                    if not payload:
                        continue
                    
                    # Try to decode as text
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                    except:
                        continue
                    
                    # Detect HTTP request
                    if text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                        if current_stream:
                            http_streams.append(current_stream)
                        
                        current_stream = {
                            'src_ip': ip.src,
                            'src_port': tcp.sport,
                            'dst_ip': ip.dst,
                            'dst_port': tcp.dport,
                            'method': text.split()[0],
                            'path': text.split()[1] if len(text.split()) > 1 else '',
                            'request_headers': {},
                            'response_headers': {},
                            'request_body': '',
                            'response_body': '',
                            'status_code': None,
                            'packets': []
                        }
                        
                        # Parse headers
                        lines = text.split('\r\n')
                        for line in lines[1:]:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                current_stream['request_headers'][key.strip()] = value.strip()
                    
                    # Detect HTTP response
                    elif text.startswith('HTTP/'):
                        if current_stream:
                            # Parse status line
                            lines = text.split('\r\n')
                            if len(lines) > 0:
                                status_parts = lines[0].split()
                                if len(status_parts) >= 3:
                                    current_stream['status_code'] = int(status_parts[1])
                            
                            # Parse response headers
                            for line in lines[1:]:
                                if ':' in line:
                                    key, value = line.split(':', 1)
                                    current_stream['response_headers'][key.strip()] = value.strip()
                    
                    # Add packet info
                    if current_stream:
                        current_stream['packets'].append({
                            'seq': tcp.seq,
                            'ack': tcp.ack,
                            'flags': tcp.flags,
                            'payload_size': len(payload),
                            'timestamp': pkt.time if hasattr(pkt, 'time') else None
                        })
                        
                        # Try to extract body content
                        if '\r\n\r\n' in text:
                            body_start = text.find('\r\n\r\n') + 4
                            if body_start < len(text):
                                body = text[body_start:]
                                if current_stream['status_code']:
                                    current_stream['response_body'] = body
                                else:
                                    current_stream['request_body'] = body
                
                except Exception as e:
                    logger.debug(f"Error processing HTTP packet: {e}")
                    continue
        
        # Add the last stream if exists
        if current_stream:
            http_streams.append(current_stream)
        
        return http_streams
        
    except Exception as e:
        logger.error(f"Failed to extract HTTP streams: {e}")
        return []

def extract_dns_queries(pcap_file: str) -> List[Dict[str, Any]]:
    """Extract DNS queries and responses from PCAP"""
    dns_queries = []
    
    try:
        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                try:
                    if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
                        continue
                    
                    udp = pkt[UDP]
                    ip = pkt[IP]
                    
                    # Check if this is DNS traffic (port 53)
                    if udp.sport != 53 and udp.dport != 53:
                        continue
                    
                    # Get payload
                    payload = b""
                    if pkt.haslayer(Raw):
                        payload = bytes(pkt[Raw].load)
                    
                    if not payload:
                        continue
                    
                    # Basic DNS parsing (simplified)
                    if len(payload) > 12:  # Minimum DNS header size
                        # Check if it's a query or response
                        flags = payload[2:4]
                        is_query = (flags[0] & 0x80) == 0
                        
                        query_info = {
                            'src_ip': ip.src,
                            'src_port': udp.sport,
                            'dst_ip': ip.dst,
                            'dst_port': udp.dport,
                            'is_query': is_query,
                            'timestamp': pkt.time if hasattr(pkt, 'time') else None,
                            'payload_size': len(payload)
                        }
                        
                        dns_queries.append(query_info)
                
                except Exception as e:
                    logger.debug(f"Error processing DNS packet: {e}")
                    continue
        
        return dns_queries
        
    except Exception as e:
        logger.error(f"Failed to extract DNS queries: {e}")
        return []

def extract_ftp_streams(pcap_file: str) -> List[Dict[str, Any]]:
    """Extract FTP commands and responses from PCAP"""
    ftp_streams = []
    current_stream = None
    
    try:
        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                try:
                    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                        continue
                    
                    ip = pkt[IP]
                    tcp = pkt[TCP]
                    
                    # Check if this is FTP traffic (port 21)
                    if tcp.sport != 21 and tcp.dport != 21:
                        continue
                    
                    # Get payload
                    payload = b""
                    if pkt.haslayer(Raw):
                        payload = bytes(pkt[Raw].load)
                    
                    if not payload:
                        continue
                    
                    # Try to decode as text
                    try:
                        text = payload.decode('utf-8', errors='ignore').strip()
                    except:
                        continue
                    
                    if not text:
                        continue
                    
                    # Detect FTP command or response
                    if text.startswith(('USER ', 'PASS ', 'LIST ', 'RETR ', 'STOR ', 'CWD ', 'PWD ')):
                        if current_stream:
                            ftp_streams.append(current_stream)
                        
                        current_stream = {
                            'src_ip': ip.src,
                            'src_port': tcp.sport,
                            'dst_ip': ip.dst,
                            'dst_port': tcp.dport,
                            'command': text.split()[0],
                            'arguments': ' '.join(text.split()[1:]) if len(text.split()) > 1 else '',
                            'responses': [],
                            'packets': []
                        }
                    
                    elif text.startswith(('220', '230', '331', '250', '200', '150', '226')):
                        if current_stream:
                            current_stream['responses'].append(text)
                    
                    # Add packet info
                    if current_stream:
                        current_stream['packets'].append({
                            'seq': tcp.seq,
                            'ack': tcp.ack,
                            'flags': tcp.flags,
                            'payload': text,
                            'timestamp': pkt.time if hasattr(pkt, 'time') else None
                        })
                
                except Exception as e:
                    logger.debug(f"Error processing FTP packet: {e}")
                    continue
        
        # Add the last stream if exists
        if current_stream:
            ftp_streams.append(current_stream)
        
        return ftp_streams
        
    except Exception as e:
        logger.error(f"Failed to extract FTP streams: {e}")
        return []

def reassemble_streams(pcap_file):
    """
    Reassemble TCP/UDP streams from fragmented packets.
    """
    streams = {}
    with PcapReader(pcap_file) as packets:
        for pkt in packets:
            if pkt.haslayer(TCP):
                stream_id = (pkt[TCP].sport, pkt[TCP].dport, pkt[IP].src, pkt[IP].dst)
                if stream_id not in streams:
                    streams[stream_id] = b""
                if pkt.haslayer(Raw):
                    streams[stream_id] += bytes(pkt[Raw].load)
            elif pkt.haslayer(UDP):
                stream_id = (pkt[UDP].sport, pkt[UDP].dport, pkt[IP].src, pkt[IP].dst)
                if stream_id not in streams:
                    streams[stream_id] = b""
                if pkt.haslayer(Raw):
                    streams[stream_id] += bytes(pkt[Raw].load)
    return streams

def get_stream_statistics(pcap_file: str) -> Dict[str, Any]:
    """Get comprehensive stream statistics"""
    stats = {
        'tcp_streams': 0,
        'http_streams': 0,
        'dns_queries': 0,
        'ftp_streams': 0,
        'total_packets': 0,
        'protocols': defaultdict(int)
    }
    
    try:
        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                stats['total_packets'] += 1
                
                try:
                    if pkt.haslayer(TCP):
                        stats['protocols']['TCP'] += 1
                    elif pkt.haslayer(UDP):
                        stats['protocols']['UDP'] += 1
                    elif pkt.haslayer(IP):
                        stats['protocols']['IP'] += 1
                    else:
                        stats['protocols']['Other'] += 1
                except:
                    stats['protocols']['Unknown'] += 1
        
        # Extract streams
        tcp_streams = reassemble_tcp_streams(pcap_file)
        http_streams = extract_http_streams(pcap_file)
        dns_queries = extract_dns_queries(pcap_file)
        ftp_streams = extract_ftp_streams(pcap_file)
        
        stats['tcp_streams'] = len(tcp_streams)
        stats['http_streams'] = len(http_streams)
        stats['dns_queries'] = len(dns_queries)
        stats['ftp_streams'] = len(ftp_streams)
        stats['protocols'] = dict(stats['protocols'])
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get stream statistics: {e}")
        return {'error': str(e)}

def parse_http_streams(pcap_file):
    """
    Parse HTTP streams using pyshark.
    """
    streams = {}
    capture = pyshark.FileCapture(pcap_file, display_filter="http")
    for packet in capture:
        try:
            stream_id = (packet.tcp.srcport, packet.tcp.dstport, packet.ip.src, packet.ip.dst)
            if stream_id not in streams:
                streams[stream_id] = ""
            streams[stream_id] += packet.http.file_data
        except AttributeError:
            pass
    capture.close()
    return streams
