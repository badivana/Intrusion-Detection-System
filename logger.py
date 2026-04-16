"""
Logging Module for Intrusion Detection System
==============================================
Handles all logging operations - file and console output
with different severity levels and formatted output.
"""

import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
import colorama

# Initialize colorama for colored console output
colorama.init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels"""
    
    COLORS = {
        'DEBUG': colorama.Fore.CYAN,
        'INFO': colorama.Fore.GREEN,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Style.BRIGHT,
        'ALERT': colorama.Fore.MAGENTA + colorama.Style.BRIGHT
    }
    
    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}[{record.levelname}]"
        return super().format(record)


class IDSLogger:
    """
    Custom logger for the Intrusion Detection System
    Provides both file and console logging with rotation support
    """
    
    def __init__(self, log_file="alerts.log", console_output=True, max_bytes=10485760, backup_count=5):
        """
        Initialize the IDS logger
        
        Args:
            log_file: Path to the log file
            console_output: Enable/disable console output
            max_bytes: Maximum log file size before rotation
            backup_count: Number of backup files to keep
        """
        self.log_file = log_file
        self.console_output = console_output
        self.logger = logging.getLogger("IDSLogger")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler with colors
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_formatter = ColoredFormatter(
                '%(asctime)s | %(levelname)-8s | %(message)s',
                datefmt='%H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def alert(self, message, threat_level="HIGH"):
        """
        Log security alert with threat level
        
        Args:
            message: Alert message
            threat_level: Threat level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        alert_msg = f"[{threat_level}] {message}"
        
        # Use appropriate log level based on threat
        if threat_level == "CRITICAL":
            self.logger.critical(alert_msg)
        elif threat_level == "HIGH":
            self.logger.error(alert_msg)
        elif threat_level == "MEDIUM":
            self.logger.warning(alert_msg)
        else:
            self.logger.info(alert_msg)
        
        return alert_msg
    
    def log_packet(self, packet_info):
        """Log packet information"""
        self.debug(f"Packet: {packet_info}")
    
    def get_logs(self, lines=100):
        """Read last N lines from log file"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    all_lines = f.readlines()
                    return all_lines[-lines:]
            return []
        except Exception as e:
            return [f"Error reading logs: {str(e)}"]
    
    def clear_logs(self):
        """Clear the log file"""
        try:
            if os.path.exists(self.log_file):
                open(self.log_file, 'w').close()
            return True
        except Exception:
            return False


def create_logger(config):
    """Factory function to create logger from config"""
    return IDSLogger(
        log_file=config.LOG_FILE,
        console_output=config.LOG_CONSOLE,
        max_bytes=config.MAX_LOG_SIZE,
        backup_count=config.LOG_BACKUP_COUNT
    )