"""
Helpers to extract DNS TXT and ICMP payloads from pcap via scapy parsing.
"""
from scapy.all import PcapReader, DNS, Raw, ICMP

def extract_dns_txt(pcap_file):
    txts = []
    with PcapReader(pcap_file) as pcap:
        for pkt in pcap:
            try:
                if pkt.haslayer(DNS) and int(getattr(pkt[DNS], 'ancount', 0)) > 0:
                    # iterate answers
                    for i in range(int(pkt[DNS].ancount)):
                        try:
                            rr = pkt[DNS].an[i]
                            if hasattr(rr, 'rdata'):
                                txts.append(str(rr.rdata))
                        except Exception:
                            continue
            except Exception:
                continue
    return txts

def extract_icmp_payloads(pcap_file):
    outs = []
    with PcapReader(pcap_file) as pcap:
        for pkt in pcap:
            try:
                if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
                    outs.append(bytes(pkt[Raw].load))
            except Exception:
                continue
    return outs
