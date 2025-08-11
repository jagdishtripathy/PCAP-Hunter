import logging
import sys
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
import colorama
from colorama import Fore, Back, Style

# Initialize colorama for cross-platform colored output
colorama.init()

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT,
    }
    
    def format(self, record):
        # Add color to the level name
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{Style.RESET_ALL}"
        
        # Add color to specific keywords
        message = record.getMessage()
        if 'flag' in message.lower() or 'ctf' in message.lower():
            message = f"{Fore.MAGENTA}{message}{Style.RESET_ALL}"
        elif 'error' in message.lower() or 'failed' in message.lower():
            message = f"{Fore.RED}{message}{Style.RESET_ALL}"
        elif 'success' in message.lower() or 'found' in message.lower():
            message = f"{Fore.GREEN}{message}{Style.RESET_ALL}"
        elif 'warning' in message.lower():
            message = f"{Fore.YELLOW}{message}{Style.RESET_ALL}"
        
        record.msg = message
        return super().format(record)

def setup_logging(level=False, log_file=None, max_size=10*1024*1024, backup_count=5):
    """Setup logging configuration with file rotation and colored output"""
    
    # Determine log level
    if level:
        log_level = logging.DEBUG
        format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    else:
        log_level = logging.INFO
        format_str = "%(levelname)s - %(message)s"
    
    # Create formatters
    console_formatter = ColoredFormatter(format_str)
    file_formatter = logging.Formatter(format_str)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with colored output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler with rotation
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=max_size, 
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    else:
        # Default log file
        default_log = 'pcap_hunter.log'
        file_handler = RotatingFileHandler(
            default_log, 
            maxBytes=max_size, 
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

def get_logger(name):
    """Get a logger instance"""
    return logging.getLogger(name)

def set_log_level(level_name):
    """Set the logging level by name"""
    level_map = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    
    if level_name.lower() in level_map:
        logging.getLogger().setLevel(level_map[level_name.lower()])
    else:
        logging.getLogger().setLevel(logging.INFO)

def add_file_handler(log_file, level=logging.INFO, max_size=10*1024*1024, backup_count=5):
    """Add a file handler to existing logging configuration"""
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=max_size, 
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    
    logging.getLogger().addHandler(file_handler)

def remove_file_handler(log_file):
    """Remove a specific file handler"""
    logger = logging.getLogger()
    for handler in logger.handlers[:]:
        if isinstance(handler, RotatingFileHandler) and handler.baseFilename == str(Path(log_file).absolute()):
            logger.removeHandler(handler)
            handler.close()

# Convenience functions with colored output
def info(message):
    """Log info message with green color"""
    logging.info(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

def success(message):
    """Log success message with bright green color"""
    logging.info(f"{Fore.GREEN}{Style.BRIGHT}SUCCESS: {message}{Style.RESET_ALL}")

def warning(message):
    """Log warning message with yellow color"""
    logging.warning(f"{Fore.YELLOW}WARNING: {message}{Style.RESET_ALL}")

def error(message):
    """Log error message with red color"""
    logging.error(f"{Fore.RED}ERROR: {message}{Style.RESET_ALL}")

def critical(message):
    """Log critical message with bright red color"""
    logging.critical(f"{Fore.RED}{Style.BRIGHT}CRITICAL: {message}{Style.RESET_ALL}")

def debug(message):
    """Log debug message with cyan color"""
    logging.debug(f"{Fore.CYAN}DEBUG: {message}{Style.RESET_ALL}")

def flag_found(message):
    """Log flag found message with magenta color"""
    logging.info(f"{Fore.MAGENTA}{Style.BRIGHT}🎯 FLAG FOUND: {message}{Style.RESET_ALL}")

def analysis_start(message):
    """Log analysis start message with blue color"""
    logging.info(f"{Fore.BLUE}{Style.BRIGHT}🚀 {message}{Style.RESET_ALL}")

def analysis_complete(message):
    """Log analysis complete message with green color"""
    logging.info(f"{Fore.GREEN}{Style.BRIGHT}✅ {message}{Style.RESET_ALL}")

def progress(current, total, description="Progress"):
    """Log progress with percentage"""
    percentage = (current / total) * 100 if total > 0 else 0
    bar_length = 30
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    
    progress_msg = f"{description}: [{bar}] {current}/{total} ({percentage:.1f}%)"
    logging.info(f"{Fore.BLUE}{progress_msg}{Style.RESET_ALL}")

# Cleanup function
def cleanup():
    """Cleanup colorama"""
    colorama.deinit()
