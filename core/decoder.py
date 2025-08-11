import base64
import codecs
import urllib.parse
import binascii
import logging
from typing import List, Dict, Tuple, Optional
import re

log = logging.getLogger(__name__)

class MultiPassDecoder:
    """Handles multi-pass decoding of various encodings"""
    
    def __init__(self, max_passes: int = 3):
        self.max_passes = max_passes
        self.decoding_methods = [
            ("base64", self._try_base64),
            ("hex", self._try_hex),
            ("url", self._try_url_decode),
            ("rot13", self._try_rot13),
            ("reverse", self._try_reverse),
            ("binary", self._try_binary_decode),
            ("ascii85", self._try_ascii85),
            ("base32", self._try_base32),
            ("base16", self._try_base16)
        ]
    
    def decode_data(self, data: str, custom_patterns: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Attempt to decode data using multiple passes and methods
        
        Args:
            data: Data to decode
            custom_patterns: Custom regex patterns to check after each decode
        
        Returns:
            Dictionary with decoded results by method
        """
        results = {
            "original": [data],
            "decoded": [],
            "final_results": []
        }
        
        current_data = [data]
        
        for pass_num in range(self.max_passes):
            log.debug(f"Starting decode pass {pass_num + 1}")
            new_data = []
            
            for item in current_data:
                for method_name, method_func in self.decoding_methods:
                    try:
                        decoded = method_func(item)
                        if decoded and decoded != item:
                            new_data.append(decoded)
                            results["decoded"].append({
                                "pass": pass_num + 1,
                                "method": method_name,
                                "original": item,
                                "decoded": decoded
                            })
                    except Exception as e:
                        log.debug(f"Method {method_name} failed: {e}")
                        continue
            
            if not new_data:
                log.debug(f"No new decodings found in pass {pass_num + 1}")
                break
            
            current_data = new_data
            
            # Check for patterns in decoded data
            if custom_patterns:
                for item in current_data:
                    for pattern in custom_patterns:
                        if re.search(pattern, item, re.IGNORECASE):
                            results["final_results"].append({
                                "pattern": pattern,
                                "data": item,
                                "pass": pass_num + 1
                            })
        
        # Add all decoded data to results
        results["decoded"].extend(current_data)
        
        return results
    
    def _try_base64(self, data: str) -> Optional[str]:
        """Try base64 decoding"""
        try:
            # Remove padding if present
            data = data.strip()
            if len(data) % 4 != 0:
                data += "=" * (4 - len(data) % 4)
            
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            if self._is_printable(decoded):
                return decoded
        except Exception:
            pass
        return None
    
    def _try_hex(self, data: str) -> Optional[str]:
        """Try hex decoding"""
        try:
            # Remove common hex prefixes
            clean_data = re.sub(r'^0x', '', data.strip())
            if len(clean_data) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', clean_data):
                decoded = bytes.fromhex(clean_data).decode('utf-8', errors='ignore')
                if self._is_printable(decoded):
                    return decoded
        except Exception:
            pass
        return None
    
    def _try_url_decode(self, data: str) -> Optional[str]:
        """Try URL decoding"""
        try:
            decoded = urllib.parse.unquote(data)
            if decoded != data and self._is_printable(decoded):
                return decoded
        except Exception:
            pass
        return None
    
    def _try_rot13(self, data: str) -> Optional[str]:
        """Try ROT13 decoding"""
        try:
            decoded = codecs.decode(data, 'rot_13')
            if decoded != data and self._is_printable(decoded):
                return decoded
        except Exception:
            pass
        return None
    
    def _try_reverse(self, data: str) -> Optional[str]:
        """Try reversing the string"""
        try:
            reversed_data = data[::-1]
            if reversed_data != data and self._is_printable(reversed_data):
                return reversed_data
        except Exception:
            pass
        return None
    
    def _try_binary_decode(self, data: str) -> Optional[str]:
        """Try binary string decoding"""
        try:
            # Check if it looks like binary
            if re.match(r'^[01\s]+$', data):
                # Remove spaces and convert to bytes
                binary_str = data.replace(' ', '')
                if len(binary_str) % 8 == 0:
                    bytes_data = bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))
                    decoded = bytes_data.decode('utf-8', errors='ignore')
                    if self._is_printable(decoded):
                        return decoded
        except Exception:
            pass
        return None
    
    def _try_ascii85(self, data: str) -> Optional[str]:
        """Try ASCII85 decoding"""
        try:
            decoded = base64.a85decode(data).decode('utf-8', errors='ignore')
            if self._is_printable(decoded):
                return decoded
        except Exception:
            pass
        return None
    
    def _try_base32(self, data: str) -> Optional[str]:
        """Try base32 decoding"""
        try:
            decoded = base64.b32decode(data).decode('utf-8', errors='ignore')
            if self._is_printable(decoded):
                return decoded
        except Exception:
            pass
        return None
    
    def _try_base16(self, data: str) -> Optional[str]:
        """Try base16 decoding"""
        try:
            decoded = base64.b16decode(data).decode('utf-8', errors='ignore')
            if self._is_printable(decoded):
                return decoded
        except Exception:
            pass
        return None
    
    def _is_printable(self, text: str) -> bool:
        """Check if text is mostly printable"""
        if not text:
            return False
        
        printable_chars = sum(1 for c in text if c.isprintable() or c.isspace())
        return printable_chars / len(text) > 0.8

def try_decodings(data_list: List[str], max_passes: int = 3, custom_patterns: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """
    Main function to decode a list of data items
    
    Args:
        data_list: List of strings to decode
        max_passes: Maximum number of decoding passes
        custom_patterns: Custom patterns to search for after each decode
    
    Returns:
        Dictionary with all decoding results
    """
    decoder = MultiPassDecoder(max_passes=max_passes)
    all_results = {
        "original": [],
        "decoded": [],
        "final_results": []
    }
    
    for data in data_list:
        if not data or not isinstance(data, str):
            continue
            
        results = decoder.decode_data(data, custom_patterns)
        
        # Merge results
        all_results["original"].extend(results["original"])
        all_results["decoded"].extend(results["decoded"])
        all_results["final_results"].extend(results["final_results"])
    
    # Remove duplicates
    for key in all_results:
        seen = set()
        unique_results = []
        for item in all_results[key]:
            if isinstance(item, dict):
                item_str = str(item)
            else:
                item_str = str(item)
            if item_str not in seen:
                seen.add(item_str)
                unique_results.append(item)
        all_results[key] = unique_results
    
    log.info(f"Decoding complete. Found {len(all_results['final_results'])} pattern matches")
    return all_results

def try_simple_decodings(data_list: List[str]) -> List[str]:
    """
    Simple decoding for backward compatibility
    
    Args:
        data_list: List of strings to decode
    
    Returns:
        List of decoded strings
    """
    results = try_decodings(data_list, max_passes=1)
    return results["decoded"]