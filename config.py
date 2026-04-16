"""
Configuration Module for Intrusion Detection System
=====================================================
This module contains all configurable thresholds and settings
that can be adjusted to customize the IDS behavior.
"""

import os

class Config:
    """Configuration class for IDS parameters"""
    
    # ============== NETWORK SETTINGS ==============
    INTERFACE = None  # None = auto-detect (use 'eth0' on Linux, 'Wi-Fi' on Windows)
    PROMISCUOUS_MODE = True
    BPF_FILTER = ""  # BPF filter string (e.g., "tcp or icmp")
    
    # ============== SYN FLOOD DETECTION ==============
    SYN_THRESHOLD = 50           # Max SYN packets per window to consider suspicious
    SYN_WINDOW_SECONDS = 10     # Time window in seconds for SYN flood detection
    SYN_BLOCK_ENABLED = False    # Enable blocking IPs (requires root)
    
    # ============== PORT SCANNING DETECTION ==============
    PORT_SCAN_THRESHOLD = 15     # Different ports scanned within window
    PORT_SCAN_WINDOW_SECONDS = 30 # Time window for port scan detection
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443]
    
    # ============== ICMP FLOOD DETECTION ==============
    ICMP_THRESHOLD = 100         # Max ICMP packets per window
    ICMP_WINDOW_SECONDS = 5     # Time window for ICMP flood detection
    ICMP_PACKET_SIZE_MIN = 64   # Minimum packet size to consider as attack
    
    # ============== LOGGING SETTINGS ==============
    LOG_FILE = "alerts.log"
    LOG_CONSOLE = True
    LOG_LEVEL = "INFO"
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
    LOG_BACKUP_COUNT = 5
    
    # ============== DISPLAY SETTINGS ==============
    SHOW_PACKET_SUMMARY = True
    CLEAR_SCREEN_ON_START = True
    BANNER_WIDTH = 60
    
    # ============== THREAT LEVELS ==============
    THREAT_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    
    @classmethod
    def get_threshold(cls, attack_type):
        """Get threshold for specific attack type"""
        thresholds = {
            "syn_flood": cls.SYN_THRESHOLD,
            "port_scan": cls.PORT_SCAN_THRESHOLD,
            "icmp_flood": cls.ICMP_THRESHOLD
        }
        return thresholds.get(attack_type, 0)
    
    @classmethod
    def get_window(cls, attack_type):
        """Get time window for specific attack type"""
        windows = {
            "syn_flood": cls.SYN_WINDOW_SECONDS,
            "port_scan": cls.PORT_SCAN_WINDOW_SECONDS,
            "icmp_flood": cls.ICMP_WINDOW_SECONDS
        }
        return windows.get(attack_type, 10)
    
    @classmethod
    def to_dict(cls):
        """Return configuration as dictionary"""
        return {
            "interface": cls.INTERFACE,
            "syn_threshold": cls.SYN_THRESHOLD,
            "syn_window": cls.SYN_WINDOW_SECONDS,
            "port_scan_threshold": cls.PORT_SCAN_THRESHOLD,
            "port_scan_window": cls.PORT_SCAN_WINDOW_SECONDS,
            "icmp_threshold": cls.ICMP_THRESHOLD,
            "icmp_window": cls.ICMP_WINDOW_SECONDS,
            "log_file": cls.LOG_FILE
        }