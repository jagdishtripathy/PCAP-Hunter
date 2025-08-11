"""
Entropy Analysis Module for PCAP Hunter
Detects suspicious randomness and hidden data in packet payloads
"""
import math
import numpy as np
from typing import List, Dict, Tuple, Optional
import logging
from collections import Counter
import matplotlib.pyplot as plt
from pathlib import Path

log = logging.getLogger(__name__)

class EntropyAnalyzer:
    """Analyzes entropy of packet payloads for hidden data detection"""
    
    def __init__(self):
        self.entropy_thresholds = {
            "low": 3.0,      # Very structured data
            "medium": 4.5,    # Normal data
            "high": 6.0,      # Random data
            "very_high": 7.0  # Highly random (suspicious)
        }
    
    def analyze_entropy(self, packets: List[Dict]) -> Dict:
        """
        Analyze entropy of packet payloads
        
        Args:
            packets: List of parsed packets
            
        Returns:
            Dictionary with entropy analysis results
        """
        if not packets:
            return {"error": "No packets to analyze"}
        
        analysis = {
            "total_packets": len(packets),
            "payload_entropy": [],
            "suspicious_packets": [],
            "entropy_distribution": {},
            "overall_statistics": {},
            "entropy_patterns": []
        }
        
        # Calculate entropy for each packet
        for packet in packets:
            payload = packet.get("payload_bytes", b"")
            if payload:
                entropy_info = self._calculate_payload_entropy(payload, packet)
                analysis["payload_entropy"].append(entropy_info)
                
                # Check if suspicious
                if entropy_info["suspicious"]:
                    analysis["suspicious_packets"].append(entropy_info)
        
        # Calculate overall statistics
        if analysis["payload_entropy"]:
            analysis["overall_statistics"] = self._calculate_overall_statistics(
                analysis["payload_entropy"]
            )
            analysis["entropy_distribution"] = self._categorize_entropy(
                analysis["payload_entropy"]
            )
            analysis["entropy_patterns"] = self._detect_entropy_patterns(
                analysis["payload_entropy"]
            )
        
        return analysis
    
    def _calculate_payload_entropy(self, payload: bytes, packet: Dict) -> Dict:
        """Calculate entropy for a single payload"""
        if not payload:
            return {
                "packet_index": packet.get("index", 0),
                "entropy": 0.0,
                "length": 0,
                "category": "empty",
                "suspicious": False,
                "analysis": "No payload data"
            }
        
        # Calculate byte frequency
        byte_counts = Counter(payload)
        total_bytes = len(payload)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        
        # Categorize entropy
        category = self._categorize_entropy_value(entropy)
        
        # Determine if suspicious
        suspicious = self._is_suspicious_entropy(entropy, payload)
        
        # Additional analysis
        analysis = self._analyze_payload_characteristics(payload, entropy)
        
        return {
            "packet_index": packet.get("index", 0),
            "src": packet.get("src", ""),
            "dst": packet.get("dst", ""),
            "protocol": packet.get("protocol", ""),
            "entropy": entropy,
            "length": total_bytes,
            "category": category,
            "suspicious": suspicious,
            "analysis": analysis,
            "byte_distribution": dict(byte_counts.most_common(10))  # Top 10 bytes
        }
    
    def _categorize_entropy_value(self, entropy: float) -> str:
        """Categorize entropy value"""
        if entropy < self.entropy_thresholds["low"]:
            return "very_low"
        elif entropy < self.entropy_thresholds["medium"]:
            return "low"
        elif entropy < self.entropy_thresholds["high"]:
            return "medium"
        elif entropy < self.entropy_thresholds["very_high"]:
            return "high"
        else:
            return "very_high"
    
    def _is_suspicious_entropy(self, entropy: float, payload: bytes) -> bool:
        """Determine if entropy is suspicious"""
        # Very high entropy (encrypted/compressed data)
        if entropy > self.entropy_thresholds["very_high"]:
            return True
        
        # Very low entropy (possible steganography or encoding)
        if entropy < self.entropy_thresholds["low"]:
            return True
        
        # Check for patterns that suggest hidden data
        if self._has_hidden_data_patterns(payload):
            return True
        
        return False
    
    def _has_hidden_data_patterns(self, payload: bytes) -> bool:
        """Check for patterns that suggest hidden data"""
        if len(payload) < 16:
            return False
        
        # Check for repeated patterns
        pattern_lengths = [2, 4, 8, 16]
        for length in pattern_lengths:
            if len(payload) >= length * 2:
                patterns = {}
                for i in range(len(payload) - length + 1):
                    pattern = payload[i:i+length]
                    patterns[pattern] = patterns.get(pattern, 0) + 1
                
                # If any pattern appears too frequently
                for pattern, count in patterns.items():
                    if count > len(payload) / (length * 2):
                        return True
        
        # Check for alternating patterns (XOR steganography)
        if len(payload) >= 4:
            alternating_count = 0
            for i in range(1, len(payload)):
                if payload[i] == payload[i-1]:
                    alternating_count += 1
            
            if alternating_count > len(payload) * 0.8:
                return True
        
        return False
    
    def _analyze_payload_characteristics(self, payload: bytes, entropy: float) -> str:
        """Analyze payload characteristics"""
        analysis = []
        
        # Check for null bytes
        null_count = payload.count(b'\x00')
        if null_count > len(payload) * 0.1:
            analysis.append(f"High null byte count: {null_count}")
        
        # Check for printable characters
        printable_count = sum(1 for b in payload if 32 <= b <= 126)
        printable_ratio = printable_count / len(payload)
        
        if printable_ratio > 0.9:
            analysis.append("Highly printable content")
        elif printable_ratio < 0.1:
            analysis.append("Mostly non-printable content")
        
        # Check for repeated bytes
        byte_counts = Counter(payload)
        most_common = byte_counts.most_common(1)[0]
        if most_common[1] > len(payload) * 0.3:
            analysis.append(f"Repeated byte {hex(most_common[0])} appears {most_common[1]} times")
        
        # Entropy interpretation
        if entropy < 2.0:
            analysis.append("Very structured data - possible encoding or steganography")
        elif entropy > 7.5:
            analysis.append("Extremely random - possible encryption or compression")
        
        return "; ".join(analysis) if analysis else "Normal payload characteristics"
    
    def _calculate_overall_statistics(self, entropy_data: List[Dict]) -> Dict:
        """Calculate overall entropy statistics"""
        entropies = [item["entropy"] for item in entropy_data]
        lengths = [item["length"] for item in entropy_data]
        
        return {
            "mean_entropy": float(np.mean(entropies)),
            "median_entropy": float(np.median(entropies)),
            "std_entropy": float(np.std(entropies)),
            "min_entropy": float(np.min(entropies)),
            "max_entropy": float(np.max(entropies)),
            "total_payload_size": sum(lengths),
            "mean_payload_size": float(np.mean(lengths))
        }
    
    def _categorize_entropy(self, entropy_data: List[Dict]) -> Dict:
        """Categorize packets by entropy level"""
        categories = {}
        for item in entropy_data:
            category = item["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(item["packet_index"])
        
        return categories
    
    def _detect_entropy_patterns(self, entropy_data: List[Dict]) -> List[Dict]:
        """Detect patterns in entropy values"""
        patterns = []
        
        if len(entropy_data) < 3:
            return patterns
        
        # Sort by packet index
        sorted_data = sorted(entropy_data, key=lambda x: x["packet_index"])
        entropies = [item["entropy"] for item in sorted_data]
        
        # Check for entropy trends
        if len(entropies) >= 5:
            # Linear trend
            x = np.arange(len(entropies))
            slope = np.polyfit(x, entropies, 1)[0]
            
            if abs(slope) > 0.1:  # Significant trend
                patterns.append({
                    "type": "entropy_trend",
                    "slope": slope,
                    "description": "Increasing" if slope > 0 else "Decreasing",
                    "significance": "high" if abs(slope) > 0.5 else "medium"
                })
        
        # Check for entropy cycles
        if len(entropies) >= 10:
            # Simple cycle detection
            for cycle_length in range(2, min(10, len(entropies) // 2)):
                cycle_correlation = self._calculate_cycle_correlation(entropies, cycle_length)
                if cycle_correlation > 0.7:
                    patterns.append({
                        "type": "entropy_cycle",
                        "cycle_length": cycle_length,
                        "correlation": cycle_correlation,
                        "description": f"Cyclic pattern every {cycle_length} packets"
                    })
        
        # Check for entropy clusters
        entropy_clusters = self._find_entropy_clusters(entropies)
        for cluster in entropy_clusters:
            if len(cluster["indices"]) > 2:
                patterns.append({
                    "type": "entropy_cluster",
                    "cluster_size": len(cluster["indices"]),
                    "mean_entropy": cluster["mean_entropy"],
                    "description": f"Cluster of {len(cluster['indices'])} packets with similar entropy"
                })
        
        return patterns
    
    def _calculate_cycle_correlation(self, values: List[float], cycle_length: int) -> float:
        """Calculate correlation for cyclic patterns"""
        if len(values) < cycle_length * 2:
            return 0.0
        
        # Compare first cycle with second cycle
        first_cycle = values[:cycle_length]
        second_cycle = values[cycle_length:cycle_length*2]
        
        if len(second_cycle) < cycle_length:
            return 0.0
        
        # Calculate correlation
        correlation = np.corrcoef(first_cycle, second_cycle)[0, 1]
        return correlation if not np.isnan(correlation) else 0.0
    
    def _find_entropy_clusters(self, entropies: List[float]) -> List[Dict]:
        """Find clusters of similar entropy values"""
        clusters = []
        threshold = 0.5  # Entropy difference threshold
        
        current_cluster = {
            "indices": [0],
            "mean_entropy": entropies[0]
        }
        
        for i in range(1, len(entropies)):
            if abs(entropies[i] - current_cluster["mean_entropy"]) <= threshold:
                # Add to current cluster
                current_cluster["indices"].append(i)
                # Update mean
                current_cluster["mean_entropy"] = np.mean([
                    entropies[j] for j in current_cluster["indices"]
                ])
            else:
                # Start new cluster
                if len(current_cluster["indices"]) > 1:
                    clusters.append(current_cluster)
                
                current_cluster = {
                    "indices": [i],
                    "mean_entropy": entropies[i]
                }
        
        # Add last cluster
        if len(current_cluster["indices"]) > 1:
            clusters.append(current_cluster)
        
        return clusters
    
    def generate_entropy_report(self, analysis: Dict, output_dir: str) -> str:
        """Generate a detailed entropy analysis report"""
        report_path = Path(output_dir) / "entropy_analysis_report.txt"
        
        with open(report_path, 'w') as f:
            f.write("PCAP Entropy Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Total Packets Analyzed: {analysis['total_packets']}\n\n")
            
            # Overall statistics
            stats = analysis.get('overall_statistics', {})
            if stats:
                f.write("Overall Entropy Statistics:\n")
                f.write(f"  Mean Entropy: {stats['mean_entropy']:.3f}\n")
                f.write(f"  Median Entropy: {stats['median_entropy']:.3f}\n")
                f.write(f"  Standard Deviation: {stats['std_entropy']:.3f}\n")
                f.write(f"  Entropy Range: {stats['min_entropy']:.3f} - {stats['max_entropy']:.3f}\n")
                f.write(f"  Total Payload Size: {stats['total_payload_size']:,} bytes\n")
                f.write(f"  Mean Payload Size: {stats['mean_payload_size']:.1f} bytes\n\n")
            
            # Entropy distribution
            distribution = analysis.get('entropy_distribution', {})
            if distribution:
                f.write("Entropy Distribution:\n")
                for category, packet_indices in distribution.items():
                    f.write(f"  {category}: {len(packet_indices)} packets\n")
                f.write("\n")
            
            # Suspicious packets
            suspicious = analysis.get('suspicious_packets', [])
            if suspicious:
                f.write(f"Suspicious Packets ({len(suspicious)}):\n")
                for packet in suspicious[:20]:  # Show first 20
                    f.write(f"  Packet {packet['packet_index']}: "
                           f"Entropy={packet['entropy']:.3f} "
                           f"({packet['category']}) - {packet['analysis']}\n")
                f.write("\n")
            
            # Entropy patterns
            patterns = analysis.get('entropy_patterns', [])
            if patterns:
                f.write("Detected Entropy Patterns:\n")
                for pattern in patterns:
                    f.write(f"  - {pattern['type']}: {pattern['description']}\n")
                f.write("\n")
            
            f.write("Analysis Complete\n")
        
        log.info(f"Entropy analysis report saved to: {report_path}")
        return str(report_path)

def analyze_payload_entropy(packets: List[Dict], output_dir: str) -> Dict:
    """Main function to analyze payload entropy"""
    analyzer = EntropyAnalyzer()
    analysis = analyzer.analyze_entropy(packets)
    
    # Generate report
    if "error" not in analysis:
        analyzer.generate_entropy_report(analysis, output_dir)
    
    return analysis
