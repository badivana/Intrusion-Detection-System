"""
Utility Functions Module for Intrusion Detection System
========================================================
Contains helper functions for network operations, formatting,
and display utilities.
"""

import os
import sys
import socket
import struct
from datetime import datetime
import colorama

# Initialize colorama
colorama.init(autoreset=True)


def get_current_timestamp():
    """Get current timestamp as string"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_short_timestamp():
    """Get short timestamp for display"""
    return datetime.now().strftime("%H:%M:%S")


def get_ip_address(packet):
    """
    Extract source and destination IP from packet
    
    Args:
        packet: Scapy packet object
        
    Returns:
        tuple: (src_ip, dst_ip)
    """
    try:
        if hasattr(packet, 'src'):
            src_ip = packet.src
        else:
            src_ip = "Unknown"
            
        if hasattr(packet, 'dst'):
            dst_ip = packet.dst
        else:
            dst_ip = "Unknown"
            
        return src_ip, dst_ip
    except:
        return "Unknown", "Unknown"


def get_protocol_name(packet):
    """Get protocol name from packet"""
    try:
        if hasattr(packet, 'proto'):
            proto_map = {
                1: "ICMP",
                6: "TCP",
                17: "UDP"
            }
            return proto_map.get(packet.proto, str(packet.proto))
        return "UNKNOWN"
    except:
        return "UNKNOWN"


def get_port_info(packet):
    """Extract port information from packet"""
    try:
        if hasattr(packet, 'sport'):
            return packet.sport, packet.dport
        return None, None
    except:
        return None, None


def resolve_hostname(ip_address):
    """Resolve IP address to hostname"""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def format_packet_summary(packet):
    """
    Create a formatted summary of the packet
    
    Args:
        packet: Scapy packet object
        
    Returns:
        str: Formatted packet summary
    """
    try:
        summary = packet.summary()
        return summary if summary else "No summary available"
    except:
        return "Unknown packet"


def get_packet_size(packet):
    """Get packet size in bytes"""
    try:
        return len(packet)
    except:
        return 0


def is_valid_ip(ip_address):
    """Check if string is a valid IP address"""
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False


def calculate_attack_severity(attack_type, packet_count):
    """
    Calculate attack severity based on packet count
    
    Args:
        attack_type: Type of attack
        packet_count: Number of packets detected
        
    Returns:
        str: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
    """
    severity_thresholds = {
        "syn_flood": {
            "low": 50,
            "medium": 100,
            "high": 200,
            "critical": 500
        },
        "port_scan": {
            "low": 10,
            "medium": 25,
            "high": 50,
            "critical": 100
        },
        "icmp_flood": {
            "low": 100,
            "medium": 250,
            "high": 500,
            "critical": 1000
        }
    }
    
    thresholds = severity_thresholds.get(attack_type, {})
    
    if packet_count >= thresholds.get("critical", 1000):
        return "CRITICAL"
    elif packet_count >= thresholds.get("high", 200):
        return "HIGH"
    elif packet_count >= thresholds.get("medium", 50):
        return "MEDIUM"
    else:
        return "LOW"


def print_banner(width=60):
    """Print ASCII art banner"""
    banner = f"""
{colorama.Fore.CYAN}+{'=' * (width-2)}+
|  INTRUSION DETECTION SYSTEM  {' ' * (width-31)}|
|  Network Security Monitor     {' ' * (width-32)}|
+{'=' * (width-2)}+{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}
    """
    print(banner)


def print_menu():
    """Print main menu options"""
    menu = f"""
{colorama.Fore.CYAN}┌─────────────────────────────────────────┐
│            MAIN MENU                      │
├─────────────────────────────────────────┤
│  1. Start IDS                           │
│  2. View Logs                           │
│  3. View Configuration                  │
│  4. Clear Logs                          │
│  5. Network Info                        │
│  6. Exit                                │
└─────────────────────────────────────────┘{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}
    """
    print(menu)


def clear_screen():
    """Clear the screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_network_interfaces():
    """Get list of available network interfaces"""
    try:
        import scapy.all as scapy
        return scapy.get_if_list()
    except:
        return ["Default Interface"]


def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"


def print_statistics(stats):
    """Print statistics in formatted table"""
    print(f"\n{colorama.Fore.CYAN}{'='*50}")
    print(f"{colorama.Fore.CYAN}  DETECTION STATISTICS")
    print(f"{colorama.Fore.CYAN}{'='*50}{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
    
    for key, value in stats.items():
        print(f"  {key}: {colorama.Fore.GREEN}{value}{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
    
    print(f"{colorama.Fore.CYAN}{'='*50}{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}\n")


def create_threat_report(alerts):
    """Create a threat report from alerts"""
    report = []
    report.append("\n" + "="*60)
    report.append("THREAT DETECTION REPORT")
    report.append("="*60)
    report.append(f"Generated: {get_current_timestamp()}")
    report.append(f"Total Alerts: {len(alerts)}")
    report.append("="*60 + "\n")
    
    if not alerts:
        report.append("No threats detected.")
    else:
        # Group by threat type
        threat_counts = {}
        for alert in alerts:
            threat_type = alert.get("type", "Unknown")
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        report.append("Threat Breakdown:")
        for threat, count in threat_counts.items():
            report.append(f"  - {threat}: {count}")
    
    return "\n".join(report)


class PacketCounter:
    """Simple counter for tracking packet statistics"""
    
    def __init__(self):
        self.count = 0
        self.start_time = datetime.now()
    
    def increment(self):
        self.count += 1
    
    def reset(self):
        self.count = 0
        self.start_time = datetime.now()
    
    def get_rate(self):
        """Get packets per second"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if elapsed > 0:
            return self.count / elapsed
        return 0