"""
File extraction module for PCAP Hunter
Handles extraction of files from HTTP/FTP transfers and embedded data
"""
import os
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import logging
from advanced.stego import try_extract_image_bytes

log = logging.getLogger(__name__)

class FileExtractor:
    """Extracts files from PCAP data"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.extracted_files_dir = self.output_dir / "extracted_files"
        self.extracted_files_dir.mkdir(parents=True, exist_ok=True)
        
        # File signatures for common file types
        self.file_signatures = {
            b'\xff\xd8\xff': '.jpg',
            b'\x89PNG\r\n\x1a\n': '.png',
            b'GIF87a': '.gif',
            b'GIF89a': '.gif',
            b'%PDF': '.pdf',
            b'PK\x03\x04': '.zip',
            b'PK\x05\x06': '.zip',
            b'PK\x07\x08': '.zip',
            b'\x1f\x8b\x08': '.gz',
            b'BZ': '.bz2',
            b'Rar!': '.rar',
            b'\x7fELF': '.elf',
            b'MZ': '.exe',
            b'#!/': '.sh',
            b'<?php': '.php',
            b'<!DOCTYPE': '.html',
            b'<html': '.html',
            b'HTTP/': '.http',
            b'GET ': '.http',
            b'POST ': '.http'
        }
    
    def extract_from_packets(self, packets: List[Dict]) -> List[Dict]:
        """
        Extract files from packet data
        
        Args:
            packets: List of parsed packets
            
        Returns:
            List of extracted file information
        """
        extracted_files = []
        
        for packet in packets:
            if not packet.get("payload_bytes"):
                continue
            
            # Extract files from payload
            files = self._extract_from_payload(packet["payload_bytes"], packet)
            extracted_files.extend(files)
            
            # Extract from protocol-specific data
            if packet.get("protocol") == "HTTP":
                http_files = self._extract_http_files(packet)
                extracted_files.extend(http_files)
            elif packet.get("protocol") == "FTP":
                ftp_files = self._extract_ftp_files(packet)
                extracted_files.extend(ftp_files)
        
        # Remove duplicates and save files
        unique_files = self._deduplicate_files(extracted_files)
        saved_files = self._save_extracted_files(unique_files)
        
        return saved_files
    
    def _extract_from_payload(self, payload_bytes: bytes, packet: Dict) -> List[Dict]:
        """Extract embedded files from payload"""
        files = []
        
        # Try to extract images
        image_files = try_extract_image_bytes(payload_bytes, str(self.extracted_files_dir))
        for img_path in image_files:
            files.append({
                "type": "embedded_image",
                "path": img_path,
                "size": os.path.getsize(img_path),
                "packet_index": packet.get("index"),
                "protocol": packet.get("protocol"),
                "src": packet.get("src"),
                "dst": packet.get("dst")
            })
        
        # Look for other file signatures
        for signature, extension in self.file_signatures.items():
            pos = payload_bytes.find(signature)
            if pos != -1:
                # Try to find the end of the file
                file_data = self._extract_file_by_signature(payload_bytes, pos, signature, extension)
                if file_data:
                    files.append({
                        "type": "embedded_file",
                        "data": file_data,
                        "extension": extension,
                        "size": len(file_data),
                        "packet_index": packet.get("index"),
                        "protocol": packet.get("protocol"),
                        "src": packet.get("src"),
                        "dst": packet.get("dst")
                    })
        
        return files
    
    def _extract_file_by_signature(self, payload: bytes, start_pos: int, signature: bytes, extension: str) -> Optional[bytes]:
        """Extract file data based on signature"""
        try:
            if extension in ['.jpg', '.png', '.gif']:
                # For images, try to find end markers
                if extension == '.jpg':
                    end_marker = b'\xff\xd9'
                elif extension == '.png':
                    end_marker = b'IEND\xaeB`\x82'
                elif extension == '.gif':
                    end_marker = b'\x00;'
                
                end_pos = payload.find(end_marker, start_pos)
                if end_pos != -1:
                    return payload[start_pos:end_pos + len(end_marker)]
            
            elif extension == '.zip':
                # For ZIP files, try to find the central directory
                # This is a simplified approach
                end_pos = start_pos + 1024  # Assume reasonable size
                return payload[start_pos:end_pos]
            
            elif extension in ['.http', '.html']:
                # For HTTP/HTML, try to find end of headers/content
                end_pos = payload.find(b'\r\n\r\n', start_pos)
                if end_pos != -1:
                    return payload[start_pos:end_pos + 4]
            
            # Default: take next 1KB
            end_pos = min(start_pos + 1024, len(payload))
            return payload[start_pos:end_pos]
            
        except Exception as e:
            log.debug(f"Failed to extract file by signature: {e}")
            return None
    
    def _extract_http_files(self, packet: Dict) -> List[Dict]:
        """Extract files from HTTP packets"""
        files = []
        
        # Check if this is an HTTP response with file content
        if packet.get("http_code") == "200" and packet.get("payload_bytes"):
            content_type = packet.get("http_headers", {}).get("content_type", "")
            
            if "image/" in content_type:
                extension = self._get_extension_from_content_type(content_type)
                file_data = packet["payload_bytes"]
                
                files.append({
                    "type": "http_file",
                    "data": file_data,
                    "extension": extension,
                    "size": len(file_data),
                    "packet_index": packet.get("index"),
                    "protocol": "HTTP",
                    "src": packet.get("src"),
                    "dst": packet.get("dst"),
                    "content_type": content_type
                })
        
        return files
    
    def _extract_ftp_files(self, packet: Dict) -> List[Dict]:
        """Extract files from FTP packets"""
        files = []
        
        # Check for FTP data packets (usually on port 20)
        if packet.get("port_dst") == 20 and packet.get("payload_bytes"):
            file_data = packet["payload_bytes"]
            
            # Try to determine file type from content
            extension = self._detect_file_extension(file_data)
            
            files.append({
                "type": "ftp_file",
                "data": file_data,
                "extension": extension,
                "size": len(file_data),
                "packet_index": packet.get("index"),
                "protocol": "FTP",
                "src": packet.get("src"),
                "dst": packet.get("dst")
            })
        
        return files
    
    def _get_extension_from_content_type(self, content_type: str) -> str:
        """Get file extension from HTTP content-type header"""
        content_type = content_type.lower()
        
        if "jpeg" in content_type or "jpg" in content_type:
            return ".jpg"
        elif "png" in content_type:
            return ".png"
        elif "gif" in content_type:
            return ".gif"
        elif "pdf" in content_type:
            return ".pdf"
        elif "zip" in content_type:
            return ".zip"
        elif "text/html" in content_type:
            return ".html"
        elif "text/plain" in content_type:
            return ".txt"
        else:
            return ".bin"
    
    def _detect_file_extension(self, data: bytes) -> str:
        """Detect file extension from file signature"""
        for signature, extension in self.file_signatures.items():
            if data.startswith(signature):
                return extension
        return ".bin"
    
    def _deduplicate_files(self, files: List[Dict]) -> List[Dict]:
        """Remove duplicate files based on content hash"""
        unique_files = []
        seen_hashes = set()
        
        for file_info in files:
            if "data" in file_info:
                file_hash = hashlib.md5(file_info["data"]).hexdigest()
                if file_hash not in seen_hashes:
                    seen_hashes.add(file_hash)
                    unique_files.append(file_info)
            else:
                # For files already saved to disk
                unique_files.append(file_info)
        
        return unique_files
    
    def _save_extracted_files(self, files: List[Dict]) -> List[Dict]:
        """Save extracted files to disk"""
        saved_files = []
        
        for file_info in files:
            if "data" in file_info:
                # Generate filename
                timestamp = file_info.get("packet_index", "unknown")
                extension = file_info.get("extension", ".bin")
                filename = f"extracted_{timestamp}_{file_info['type']}{extension}"
                filepath = self.extracted_files_dir / filename
                
                try:
                    with open(filepath, 'wb') as f:
                        f.write(file_info["data"])
                    
                    # Update file info
                    file_info["saved_path"] = str(filepath)
                    file_info["filename"] = filename
                    del file_info["data"]  # Remove data from memory
                    
                    log.info(f"Saved extracted file: {filename}")
                    saved_files.append(file_info)
                    
                except Exception as e:
                    log.error(f"Failed to save file {filename}: {e}")
            else:
                # File already saved
                saved_files.append(file_info)
        
        return saved_files

def extract_files_from_pcap(packets: List[Dict], output_dir: str) -> List[Dict]:
    """Main function to extract files from PCAP packets"""
    extractor = FileExtractor(output_dir)
    return extractor.extract_from_packets(packets)
