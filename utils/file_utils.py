import os
import hashlib
import mimetypes
import magic
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import zipfile
import tarfile
import gzip
import bz2
import lzma
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime

def ensure_dir(path):
    """Ensure that a directory exists."""
    os.makedirs(path, exist_ok=True)

def save_text_file(path, data):
    """Save string data to a text file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

def copy_file(src, dest):
    """Copy file from src to dest."""
    shutil.copy2(src, dest)

def get_file_info(file_path: str) -> Dict:
    """Get comprehensive file information"""
    try:
        path = Path(file_path)
        if not path.exists():
            return {"error": "File does not exist"}
        
        stat = path.stat()
        
        # Basic file info
        info = {
            "filename": path.name,
            "path": str(path.absolute()),
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "is_file": path.is_file(),
            "is_dir": path.is_dir(),
            "extension": path.suffix.lower(),
            "parent": str(path.parent)
        }
        
        # File type detection
        if path.is_file():
            try:
                # Use python-magic for better file type detection
                mime_type = magic.from_file(str(path), mime=True)
                info["mime_type"] = mime_type
                info["file_type"] = magic.from_file(str(path))
            except ImportError:
                # Fallback to mimetypes
                mime_type, _ = mimetypes.guess_type(str(path))
                info["mime_type"] = mime_type or "unknown"
                info["file_type"] = "unknown"
            
            # Hash calculation
            try:
                info["md5"] = calculate_file_hash(str(path), "md5")
                info["sha1"] = calculate_file_hash(str(path), "sha1")
                info["sha256"] = calculate_file_hash(str(path), "sha256")
            except Exception:
                info["md5"] = "error"
                info["sha1"] = "error"
                info["sha256"] = "error"
        
        return info
    
    except Exception as e:
        return {"error": str(e)}

def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Calculate file hash using specified algorithm"""
    hash_funcs = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    
    if algorithm not in hash_funcs:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hash_func = hash_funcs[algorithm]()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def is_safe_file(file_path: str, blocked_extensions: List[str] = None) -> bool:
    """Check if file is safe to process"""
    if blocked_extensions is None:
        blocked_extensions = [".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".js"]
    
    path = Path(file_path)
    extension = path.suffix.lower()
    
    # Check blocked extensions
    if extension in blocked_extensions:
        return False
    
    # Check file size (max 100MB)
    try:
        if path.stat().st_size > 100 * 1024 * 1024:
            return False
    except:
        return False
    
    return True

def extract_archive(archive_path: str, extract_dir: str) -> List[str]:
    """Extract various archive formats"""
    extracted_files = []
    path = Path(archive_path)
    
    try:
        if path.suffix.lower() == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                extracted_files = zip_ref.namelist()
        
        elif path.suffix.lower() in ['.tar', '.tar.gz', '.tgz']:
            if path.suffix.lower() in ['.tar.gz', '.tgz']:
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_dir)
                    extracted_files = tar_ref.getnames()
            else:
                with tarfile.open(archive_path, 'r') as tar_ref:
                    tar_ref.extractall(extract_dir)
                    extracted_files = tar_ref.getnames()
        
        elif path.suffix.lower() == '.gz':
            output_path = Path(extract_dir) / path.stem
            with gzip.open(archive_path, 'rb') as gz_ref:
                with open(output_path, 'wb') as out_ref:
                    out_ref.write(gz_ref.read())
            extracted_files = [str(output_path)]
        
        elif path.suffix.lower() == '.bz2':
            output_path = Path(extract_dir) / path.stem
            with bz2.open(archive_path, 'rb') as bz2_ref:
                with open(output_path, 'wb') as out_ref:
                    out_ref.write(bz2_ref.read())
            extracted_files = [str(output_path)]
        
        elif path.suffix.lower() == '.xz':
            output_path = Path(extract_dir) / path.stem
            with lzma.open(archive_path, 'rb') as xz_ref:
                with open(output_path, 'wb') as out_ref:
                    out_ref.write(xz_ref.read())
            extracted_files = [str(output_path)]
        
        return extracted_files
    
    except Exception as e:
        raise RuntimeError(f"Failed to extract archive {archive_path}: {e}")

def read_text_file(file_path: str, encoding: str = 'utf-8') -> str:
    """Read text file with encoding fallback"""
    encodings = [encoding, 'utf-8', 'latin-1', 'cp1252']
    
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
        except Exception as e:
            raise RuntimeError(f"Failed to read file {file_path}: {e}")
    
    raise RuntimeError(f"Failed to read file {file_path} with any encoding")

def read_binary_file(file_path: str, chunk_size: int = 8192) -> bytes:
    """Read binary file in chunks"""
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        raise RuntimeError(f"Failed to read binary file {file_path}: {e}")

def write_text_file(file_path: str, content: str, encoding: str = 'utf-8') -> None:
    """Write text to file"""
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w', encoding=encoding) as f:
            f.write(content)
    except Exception as e:
        raise RuntimeError(f"Failed to write file {file_path}: {e}")

def write_binary_file(file_path: str, content: bytes) -> None:
    """Write binary content to file"""
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'wb') as f:
            f.write(content)
    except Exception as e:
        raise RuntimeError(f"Failed to write binary file {file_path}: {e}")

def find_files_by_pattern(directory: str, pattern: str, recursive: bool = True) -> List[str]:
    """Find files matching pattern in directory"""
    path = Path(directory)
    if not path.exists():
        return []
    
    if recursive:
        files = list(path.rglob(pattern))
    else:
        files = list(path.glob(pattern))
    
    return [str(f) for f in files if f.is_file()]

def get_file_extension(file_path: str) -> str:
    """Get file extension"""
    return Path(file_path).suffix.lower()

def is_image_file(file_path: str) -> bool:
    """Check if file is an image"""
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}
    return get_file_extension(file_path) in image_extensions

def is_archive_file(file_path: str) -> bool:
    """Check if file is an archive"""
    archive_extensions = {'.zip', '.rar', '.tar', '.gz', '.bz2', '.xz', '.7z'}
    return get_file_extension(file_path) in archive_extensions

def is_document_file(file_path: str) -> bool:
    """Check if file is a document"""
    doc_extensions = {'.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.md'}
    return get_file_extension(file_path) in doc_extensions

def create_backup(file_path: str, backup_suffix: str = ".backup") -> str:
    """Create a backup of a file"""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    backup_path = str(path) + backup_suffix
    backup_counter = 1
    
    while Path(backup_path).exists():
        backup_path = f"{str(path)}{backup_suffix}.{backup_counter}"
        backup_counter += 1
    
    import shutil
    shutil.copy2(file_path, backup_path)
    return backup_path

def cleanup_temp_files(temp_dir: str, max_age_hours: int = 24) -> int:
    """Clean up temporary files older than specified age"""
    temp_path = Path(temp_dir)
    if not temp_path.exists():
        return 0
    
    current_time = datetime.now()
    deleted_count = 0
    
    for file_path in temp_path.rglob("*"):
        if file_path.is_file():
            try:
                file_age = current_time - datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_age.total_seconds() > max_age_hours * 3600:
                    file_path.unlink()
                    deleted_count += 1
            except Exception:
                continue
    
    return deleted_count

def get_directory_size(directory: str) -> int:
    """Calculate total size of directory"""
    total_size = 0
    path = Path(directory)
    
    if not path.exists():
        return 0
    
    for file_path in path.rglob("*"):
        if file_path.is_file():
            try:
                total_size += file_path.stat().st_size
            except Exception:
                continue
    
    return total_size

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f}{size_names[i]}"
