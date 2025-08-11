"""
Timing Analysis Module for PCAP Hunter
Detects covert channels and timing-based steganography
"""
import numpy as np
from typing import List, Dict, Tuple, Optional
import logging
from collections import defaultdict
import matplotlib.pyplot as plt
from pathlib import Path

log = logging.getLogger(__name__)

class TimingAnalyzer:
    """Analyzes packet timing for covert channels"""
    
    def __init__(self):
        self.suspicious_patterns = []
    
    def analyze_timing(self, packets: List[Dict]) -> Dict:
        """
        Analyze packet timing for suspicious patterns
        
        Args:
            packets: List of parsed packets
            
        Returns:
            Dictionary with timing analysis results
        """
        if not packets or len(packets) < 2:
            return {"error": "Insufficient packets for timing analysis"}
        
        # Sort packets by time
        sorted_packets = sorted(packets, key=lambda x: x.get("time", 0))
        
        # Calculate inter-packet delays
        delays = self._calculate_delays(sorted_packets)
        
        # Analyze patterns
        analysis = {
            "total_packets": len(packets),
            "time_span": sorted_packets[-1]["time"] - sorted_packets[0]["time"],
            "delays": delays,
            "patterns": self._detect_timing_patterns(delays),
            "statistics": self._calculate_statistics(delays),
            "suspicious_intervals": self._find_suspicious_intervals(delays),
            "covert_channel_indicators": self._detect_covert_channels(delays)
        }
        
        return analysis
    
    def _calculate_delays(self, sorted_packets: List[Dict]) -> List[float]:
        """Calculate inter-packet delays"""
        delays = []
        for i in range(1, len(sorted_packets)):
            delay = sorted_packets[i]["time"] - sorted_packets[i-1]["time"]
            delays.append(delay)
        return delays
    
    def _calculate_statistics(self, delays: List[float]) -> Dict:
        """Calculate statistical measures of delays"""
        if not delays:
            return {}
        
        delays_array = np.array(delays)
        
        return {
            "mean": float(np.mean(delays_array)),
            "median": float(np.median(delays_array)),
            "std": float(np.std(delays_array)),
            "min": float(np.min(delays_array)),
            "max": float(np.max(delays_array)),
            "percentiles": {
                "25": float(np.percentile(delays_array, 25)),
                "75": float(np.percentile(delays_array, 75)),
                "90": float(np.percentile(delays_array, 90)),
                "95": float(np.percentile(delays_array, 95))
            }
        }
    
    def _detect_timing_patterns(self, delays: List[float]) -> List[Dict]:
        """Detect recurring timing patterns"""
        patterns = []
        
        # Look for repeated delays
        delay_counts = defaultdict(int)
        for delay in delays:
            delay_counts[round(delay, 6)] += 1
        
        # Find frequently occurring delays
        for delay, count in delay_counts.items():
            if count > 3:  # More than 3 occurrences
                patterns.append({
                    "type": "repeated_delay",
                    "delay": delay,
                    "count": count,
                    "suspicious": count > 10
                })
        
        # Look for arithmetic sequences
        if len(delays) >= 3:
            for i in range(len(delays) - 2):
                d1, d2, d3 = delays[i], delays[i+1], delays[i+2]
                if abs((d2 - d1) - (d3 - d2)) < 0.001:  # Tolerance for floating point
                    patterns.append({
                        "type": "arithmetic_sequence",
                        "start_index": i,
                        "common_difference": d2 - d1,
                        "suspicious": True
                    })
        
        return patterns
    
    def _find_suspicious_intervals(self, delays: List[float]) -> List[Dict]:
        """Find suspicious timing intervals"""
        suspicious = []
        
        if not delays:
            return suspicious
        
        delays_array = np.array(delays)
        mean = np.mean(delays_array)
        std = np.std(delays_array)
        
        # Find delays that are significantly different from the mean
        threshold = 3 * std  # 3-sigma rule
        
        for i, delay in enumerate(delays):
            if abs(delay - mean) > threshold:
                suspicious.append({
                    "index": i,
                    "delay": delay,
                    "deviation": abs(delay - mean),
                    "z_score": abs(delay - mean) / std if std > 0 else 0
                })
        
        return suspicious
    
    def _detect_covert_channels(self, delays: List[float]) -> List[Dict]:
        """Detect potential covert channel indicators"""
        indicators = []
        
        if len(delays) < 10:
            return indicators
        
        # Check for binary encoding patterns
        binary_pattern = self._check_binary_encoding(delays)
        if binary_pattern:
            indicators.append(binary_pattern)
        
        # Check for Morse code patterns
        morse_pattern = self._check_morse_patterns(delays)
        if morse_pattern:
            indicators.append(morse_pattern)
        
        # Check for steganographic timing
        stego_pattern = self._check_stego_timing(delays)
        if stego_pattern:
            indicators.append(stego_pattern)
        
        return indicators
    
    def _check_binary_encoding(self, delays: List[float]) -> Optional[Dict]:
        """Check if delays encode binary data"""
        if len(delays) < 8:
            return None
        
        # Calculate mean delay
        mean_delay = np.mean(delays)
        
        # Convert to binary (short delays = 0, long delays = 1)
        binary_data = []
        for delay in delays:
            if delay > mean_delay:
                binary_data.append(1)
            else:
                binary_data.append(0)
        
        # Look for patterns that could be ASCII or other encodings
        if len(binary_data) >= 8:
            # Try to decode as ASCII
            try:
                # Group into bytes
                bytes_data = []
                for i in range(0, len(binary_data), 8):
                    if i + 8 <= len(binary_data):
                        byte = binary_data[i:i+8]
                        byte_val = int(''.join(map(str, byte)), 2)
                        bytes_data.append(byte_val)
                
                # Check if bytes are printable ASCII
                printable_count = sum(1 for b in bytes_data if 32 <= b <= 126)
                if printable_count > len(bytes_data) * 0.7:  # 70% printable
                    return {
                        "type": "binary_encoding",
                        "method": "timing_based",
                        "confidence": printable_count / len(bytes_data),
                        "binary_data": binary_data[:32],  # First 32 bits
                        "decoded_bytes": bytes_data[:4]  # First 4 bytes
                    }
            except Exception:
                pass
        
        return None
    
    def _check_morse_patterns(self, delays: List[float]) -> Optional[Dict]:
        """Check for Morse code timing patterns"""
        if len(delays) < 10:
            return None
        
        # Morse code uses short and long intervals
        mean_delay = np.mean(delays)
        
        # Classify delays as short (dot) or long (dash)
        morse_sequence = []
        for delay in delays:
            if delay < mean_delay * 0.7:
                morse_sequence.append(".")
            elif delay > mean_delay * 1.3:
                morse_sequence.append("-")
            else:
                morse_sequence.append("?")  # Uncertain
        
        # Look for common Morse patterns
        morse_str = "".join(morse_sequence)
        
        # Check for SOS pattern
        if "---...---" in morse_str:
            return {
                "type": "morse_code",
                "pattern": "SOS",
                "sequence": morse_str,
                "confidence": 0.9
            }
        
        # Check for other common patterns
        common_patterns = ["...", "---", ".-", "-."]
        pattern_count = sum(1 for pattern in common_patterns if pattern in morse_str)
        
        if pattern_count >= 2:
            return {
                "type": "morse_code",
                "pattern": "common_patterns",
                "sequence": morse_str,
                "confidence": pattern_count / len(common_patterns)
            }
        
        return None
    
    def _check_stego_timing(self, delays: List[float]) -> Optional[Dict]:
        """Check for steganographic timing patterns"""
        if len(delays) < 20:
            return None
        
        # Check for LSB steganography in timing
        delays_array = np.array(delays)
        
        # Round delays to common precision and check LSB patterns
        rounded_delays = np.round(delays_array, 6)
        lsb_patterns = []
        
        for delay in rounded_delays:
            # Extract last few digits
            delay_str = f"{delay:.6f}"
            if '.' in delay_str:
                decimal_part = delay_str.split('.')[1]
                if len(decimal_part) >= 6:
                    lsb = decimal_part[-1]
                    lsb_patterns.append(int(lsb))
        
        # Check if LSBs form a pattern
        if len(lsb_patterns) >= 8:
            # Check for binary patterns in LSBs
            binary_lsb = [b % 2 for b in lsb_patterns]
            
            # Count transitions
            transitions = sum(1 for i in range(1, len(binary_lsb)) 
                           if binary_lsb[i] != binary_lsb[i-1])
            
            # Random data should have ~50% transitions
            transition_ratio = transitions / (len(binary_lsb) - 1)
            
            if abs(transition_ratio - 0.5) > 0.3:  # Significantly different from random
                return {
                    "type": "lsb_steganography",
                    "method": "timing_precision",
                    "transition_ratio": transition_ratio,
                    "expected_random": 0.5,
                    "confidence": 1 - abs(transition_ratio - 0.5)
                }
        
        return None
    
    def generate_timing_report(self, analysis: Dict, output_dir: str) -> str:
        """Generate a detailed timing analysis report"""
        report_path = Path(output_dir) / "timing_analysis_report.txt"
        
        with open(report_path, 'w') as f:
            f.write("PCAP Timing Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Total Packets: {analysis['total_packets']}\n")
            f.write(f"Time Span: {analysis['time_span']:.6f} seconds\n\n")
            
            # Statistics
            stats = analysis.get('statistics', {})
            if stats:
                f.write("Timing Statistics:\n")
                f.write(f"  Mean Delay: {stats['mean']:.6f}s\n")
                f.write(f"  Median Delay: {stats['median']:.6f}s\n")
                f.write(f"  Standard Deviation: {stats['std']:.6f}s\n")
                f.write(f"  Min Delay: {stats['min']:.6f}s\n")
                f.write(f"  Max Delay: {stats['max']:.6f}s\n\n")
            
            # Patterns
            patterns = analysis.get('patterns', [])
            if patterns:
                f.write("Detected Patterns:\n")
                for pattern in patterns:
                    f.write(f"  - {pattern['type']}: {pattern}\n")
                f.write("\n")
            
            # Suspicious intervals
            suspicious = analysis.get('suspicious_intervals', [])
            if suspicious:
                f.write(f"Suspicious Timing Intervals: {len(suspicious)}\n")
                for item in suspicious[:10]:  # Show first 10
                    f.write(f"  Packet {item['index']}: {item['delay']:.6f}s (z-score: {item['z_score']:.2f})\n")
                f.write("\n")
            
            # Covert channel indicators
            indicators = analysis.get('covert_channel_indicators', [])
            if indicators:
                f.write("Covert Channel Indicators:\n")
                for indicator in indicators:
                    f.write(f"  - {indicator['type']}: {indicator}\n")
                f.write("\n")
            
            f.write("Analysis Complete\n")
        
        log.info(f"Timing analysis report saved to: {report_path}")
        return str(report_path)

def analyze_packet_timing(packets: List[Dict], output_dir: str) -> Dict:
    """Main function to analyze packet timing"""
    analyzer = TimingAnalyzer()
    analysis = analyzer.analyze_timing(packets)
    
    # Generate report
    if "error" not in analysis:
        analyzer.generate_timing_report(analysis, output_dir)
    
    return analysis
