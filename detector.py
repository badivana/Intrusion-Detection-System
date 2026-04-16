"""
Detection Module for Intrusion Detection System
================================================
Core detection engine that analyzes network packets and 
detects various attack patterns using statistical thresholds.
"""

import os
import sys
import time
from datetime import datetime, timedelta
from collections import defaultdict
import colorama

colorama.init(autoreset=True)
colorama.init(autoreset=True)


class AttackDetector:
    """
    Main detection class for identifying network attacks
    Uses time-based sliding windows and threshold detection
    """
    
    def __init__(self, config, logger):
        """
        Initialize the attack detector
        
        Args:
            config: Configuration object with thresholds
            logger: Logger instance for recording alerts
        """
        self.config = config
        self.logger = logger
        
        # SYN Flood Detection: Track SYN packets per source IP
        self.syn_tracker = defaultdict(list)
        
        # Port Scan Detection: Track ports accessed per source IP
        self.port_scan_tracker = defaultdict(list)
        
        # ICMP Flood Detection: Track ICMP packets per source IP
        self.icmp_tracker = defaultdict(list)
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "syn_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "attacks_detected": 0,
            "blocked_ips": set()
        }
        
        # Lock for thread safety
        self.lock = False
        
        print(f"{colorama.Fore.GREEN}[+] Attack Detector initialized")
    
    def reset_trackers(self):
        """Reset all trackers to clear old data"""
        self.syn_tracker.clear()
        self.port_scan_tracker.clear()
        self.icmp_tracker.clear()
        print(f"{colorama.Fore.YELLOW}[!] Trackers reset{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
    
    def analyze_packet(self, packet):
        """
        Main packet analysis function
        Analyzes each packet and checks for attack patterns
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Detection result or None
        """
        self.stats["total_packets"] += 1
        
        # Extract packet information
        try:
            src_ip = packet.src if hasattr(packet, 'src') else "Unknown"
            dst_ip = packet.dst if hasattr(packet, 'dst') else "Unknown"
            
            # TCP packet analysis
            if packet.haslayer('TCP'):
                self.stats["tcp_packets"] += 1
                return self._analyze_tcp_packet(packet, src_ip, dst_ip)
            
            # ICMP packet analysis
            elif packet.haslayer('ICMP'):
                self.stats["icmp_packets"] += 1
                return self._analyze_icmp_packet(packet, src_ip, dst_ip)
            
            # UDP packet analysis
            elif packet.haslayer('UDP'):
                self.stats["udp_packets"] += 1
                return self._analyze_udp_packet(packet, src_ip, dst_ip)
                
        except Exception as e:
            self.logger.debug(f"Error analyzing packet: {e}")
        
        return None
    
    def _analyze_tcp_packet(self, packet, src_ip, dst_ip):
        """
        Analyze TCP packets for SYN flood and port scanning
        
        Args:
            packet: TCP packet
            src_ip: Source IP address
            dst_ip: Destination IP address
            
        Returns:
            dict: Detection result or None
        """
        tcp_layer = packet['TCP']
        
        # Check for SYN flag (half-open connection)
        flags = tcp_layer.flags
        if 'S' in str(flags):  # SYN flag set
            self.stats["syn_packets"] += 1
            return self._detect_syn_flood(src_ip, dst_ip, tcp_layer)
        
        # Check for potential port scanning
        return self._detect_port_scan(src_ip, dst_ip, tcp_layer)
    
    def _analyze_icmp_packet(self, packet, src_ip, dst_ip):
        """
        Analyze ICMP packets for ping flood attack
        
        Args:
            packet: ICMP packet
            src_ip: Source IP address
            dst_ip: Destination IP address
            
        Returns:
            dict: Detection result or None
        """
        return self._detect_icmp_flood(src_ip, dst_ip, packet)
    
    def _analyze_udp_packet(self, packet, src_ip, dst_ip):
        """Analyze UDP packets (for future expansion)"""
        return None
    
    def _detect_syn_flood(self, src_ip, dst_ip, tcp_layer):
        """
        Detect SYN Flood Attack
        
        Logic: 
        - Track SYN packets from each source IP
        - If number of SYN packets exceeds threshold within time window
        - Flag as SYN flood attack
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            tcp_layer: TCP layer of packet
            
        Returns:
            dict: Detection result or None
        """
        current_time = time.time()
        threshold = self.config.SYN_THRESHOLD
        window = self.config.SYN_WINDOW_SECONDS
        
        # Add current SYN packet to tracker
        self.syn_tracker[src_ip].append(current_time)
        
        # Clean old entries outside the time window
        self.syn_tracker[src_ip] = [
            t for t in self.syn_tracker[src_ip]
            if current_time - t <= window
        ]
        
        syn_count = len(self.syn_tracker[src_ip])
        
        # Check if SYN count exceeds threshold
        if syn_count > threshold:
            severity = self._calculate_severity(syn_count, threshold)
            
            detection = {
                "type": "SYN FLOOD",
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "port": tcp_layer.dport if hasattr(tcp_layer, 'dport') else "Unknown",
                "count": syn_count,
                "threshold": threshold,
                "window": window,
                "severity": severity,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.stats["attacks_detected"] += 1
            
            # Log the attack
            self._log_attack(detection)
            
            # Optional: Block the IP
            if self.config.SYN_BLOCK_ENABLED:
                self._block_ip(src_ip, "SYN Flood")
            
            # Clear tracker for this IP to prevent repeated alerts
            self.syn_tracker[src_ip] = []
            
            return detection
        
        return None
    
    def _detect_port_scan(self, src_ip, dst_ip, tcp_layer):
        """
        Detect Port Scanning Attack
        
        Logic:
        - Track unique destination ports accessed by each source IP
        - If number of unique ports exceeds threshold within time window
        - Flag as port scanning attack
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            tcp_layer: TCP layer of packet
            
        Returns:
            dict: Detection result or None
        """
        current_time = time.time()
        threshold = self.config.PORT_SCAN_THRESHOLD
        window = self.config.PORT_SCAN_WINDOW_SECONDS
        
        # Get destination port
        dst_port = tcp_layer.dport if hasattr(tcp_layer, 'dport') else 0
        
        # Add port to tracker
        key = f"{src_ip}:{dst_ip}"
        if key not in self.port_scan_tracker:
            self.port_scan_tracker[key] = []
        
        # Only track unique ports
        if dst_port not in [p[0] for p in self.port_scan_tracker[key]]:
            self.port_scan_tracker[key].append((dst_port, current_time))
        
        # Clean old entries
        self.port_scan_tracker[key] = [
            (port, t) for port, t in self.port_scan_tracker[key]
            if current_time - t <= window
        ]
        
        unique_ports = len(self.port_scan_tracker[key])
        
        # Check if unique port count exceeds threshold
        if unique_ports > threshold:
            severity = self._calculate_severity(unique_ports, threshold)
            
            # Get list of scanned ports
            scanned_ports = [p[0] for p in self.port_scan_tracker[key]]
            
            detection = {
                "type": "PORT SCAN",
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "scanned_ports": scanned_ports,
                "count": unique_ports,
                "threshold": threshold,
                "window": window,
                "severity": severity,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.stats["attacks_detected"] += 1
            
            # Log the attack
            self._log_attack(detection)
            
            # Clear tracker
            self.port_scan_tracker[key] = []
            
            return detection
        
        return None
    
    def _detect_icmp_flood(self, src_ip, dst_ip, packet):
        """
        Detect ICMP Flood (Ping Flood) Attack
        
        Logic:
        - Track ICMP packets from each source IP
        - If number of ICMP packets exceeds threshold within time window
        - Flag as ICMP flood attack
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            packet: ICMP packet
            
        Returns:
            dict: Detection result or None
        """
        current_time = time.time()
        threshold = self.config.ICMP_THRESHOLD
        window = self.config.ICMP_WINDOW_SECONDS
        
        # Add ICMP packet to tracker
        self.icmp_tracker[src_ip].append(current_time)
        
        # Clean old entries
        self.icmp_tracker[src_ip] = [
            t for t in self.icmp_tracker[src_ip]
            if current_time - t <= window
        ]
        
        icmp_count = len(self.icmp_tracker[src_ip])
        
        # Check if ICMP count exceeds threshold
        if icmp_count > threshold:
            severity = self._calculate_severity(icmp_count, threshold)
            
            # Get packet info
            icmp_type = None
            if packet.haslayer('ICMP'):
                icmp_layer = packet['ICMP']
                icmp_type = icmp_layer.type if hasattr(icmp_layer, 'type') else "Unknown"
            
            detection = {
                "type": "ICMP FLOOD",
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "icmp_type": icmp_type,
                "count": icmp_count,
                "threshold": threshold,
                "window": window,
                "severity": severity,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.stats["attacks_detected"] += 1
            
            # Log the attack
            self._log_attack(detection)
            
            # Clear tracker to prevent repeated alerts
            self.icmp_tracker[src_ip] = []
            
            return detection
        
        return None
    
    def _calculate_severity(self, count, threshold):
        """Calculate severity based on count vs threshold"""
        ratio = count / threshold
        
        if ratio >= 4:
            return "CRITICAL"
        elif ratio >= 2:
            return "HIGH"
        elif ratio >= 1.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _log_attack(self, detection):
        """Log attack detection"""
        attack_type = detection["type"]
        source_ip = detection["source_ip"]
        count = detection["count"]
        threshold = detection["threshold"]
        severity = detection["severity"]
        
        if attack_type == "SYN FLOOD":
            message = (f"SYN Flood detected from {source_ip} - "
                      f"{count} SYN packets (threshold: {threshold})")
        elif attack_type == "PORT SCAN":
            message = (f"Port Scan detected from {source_ip} to {detection['dest_ip']} - "
                      f"{count} ports scanned (threshold: {threshold})")
        elif attack_type == "ICMP FLOOD":
            message = (f"ICMP Flood detected from {source_ip} - "
                      f"{count} ICMP packets (threshold: {threshold})")
        else:
            message = f"Attack detected from {source_ip}"
        
        self.logger.alert(message, severity)
    
    def _block_ip(self, ip_address, reason):
        """
        Block IP address using iptables (Linux only, requires root)
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
        """
        if ip_address in self.stats["blocked_ips"]:
            return
        
        try:
            if os.name == 'posix':  # Linux
                os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
                self.stats["blocked_ips"].add(ip_address)
                print(f"{colorama.Fore.RED}[!] Blocked IP: {ip_address} ({reason}){colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
            else:
                print(f"{colorama.Fore.YELLOW}[!] IP blocking not supported on this OS{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
        except Exception as e:
            print(f"{colorama.Fore.RED}[!] Failed to block IP: {e}{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
    
    def get_statistics(self):
        """Get current statistics"""
        return self.stats.copy()
    
    def get_active_trackers(self):
        """Get number of active trackers"""
        return {
            "syn_tracked_ips": len(self.syn_tracker),
            "port_scan_tracked": len(self.port_scan_tracker),
            "icmp_tracked_ips": len(self.icmp_tracker)
        }


def create_detector(config, logger):
    """Factory function to create detector"""
    return AttackDetector(config, logger)