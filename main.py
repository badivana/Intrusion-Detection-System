"""
Intrusion Detection System (IDS) - Main Module
===============================================
This is the main entry point for the IDS application.
It coordinates all modules and provides the CLI interface.

Project: Network Security Monitor
Author: Information Science Student
Subject: Information and Network Security
"""

import os
import sys
import time
import signal
from datetime import datetime
import colorama

# Import scapy layers (used for packet inspection)
from scapy.all import IP

# Import project modules
import config
import logger
import utils
import detector

# Initialize colorama
colorama.init(autoreset=True)


class IntrusionDetectionSystem:
    """
    Main IDS class that coordinates all components
    """
    
    def __init__(self):
        """Initialize the IDS system"""
        self.config = config.Config()
        self.log = logger.create_logger(self.config)
        self.detect = detector.create_detector(self.config, self.log)
        self.running = False
        self.sniffer = None
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n{colorama.Fore.YELLOW}[!] Shutdown signal received...{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
        self.stop()
        sys.exit(0)
    
    def display_banner(self):
        """Display the IDS banner"""
        utils.clear_screen()
        utils.print_banner(self.config.BANNER_WIDTH)
        print(f"""
{colorama.Fore.CYAN}System Information:{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}
  - Log File: {self.config.LOG_FILE}
  - SYN Threshold: {self.config.SYN_THRESHOLD} packets/{self.config.SYN_WINDOW_SECONDS}s
  - Port Scan Threshold: {self.config.PORT_SCAN_THRESHOLD} ports/{self.config.PORT_SCAN_WINDOW_SECONDS}s
  - ICMP Threshold: {self.config.ICMP_THRESHOLD} packets/{self.config.ICMP_WINDOW_SECONDS}s
  
{colorama.Fore.YELLOW}Starting packet capture... Press Ctrl+C to stop{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}
        """)
    
    def start(self):
        """Start the IDS packet sniffer"""
        self.running = True
        
        try:
            # Import scapy here to handle import errors gracefully
            from scapy.all import sniff, IP, TCP, ICMP, UDP
            
            self.display_banner()
            
            # Start sniffing packets
            self.sniffer = sniff(
                iface=self.config.INTERFACE,
                promisc=self.config.PROMISCUOUS_MODE,
                filter=self.config.BPF_FILTER,
                prn=self._packet_handler,
                store=0
            )
            
        except ImportError:
            print(f"""
{colorama.Fore.RED}ERROR: Scapy is not installed!
{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}
Please install Scapy:
  pip install scapy

Or on Linux/macOS:
  sudo pip install scapy
            """)
            sys.exit(1)
            
        except PermissionError:
            print(f"""
{colorama.Fore.RED}ERROR: Permission denied!
{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}
This program requires administrator/root privileges to sniff packets.

Run with:
  - Windows: Run as Administrator
  - Linux/macOS: sudo python main.py
            """)
            sys.exit(1)
            
        except Exception as e:
            print(f"{colorama.Fore.RED}ERROR: {str(e)}{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
            sys.exit(1)
    
    def _packet_handler(self, packet):
        """
        Callback function for each captured packet
        This is called by scapy for every packet captured
        
        Args:
            packet: Scapy packet object
        """
        if not self.running:
            return
        
        try:
            # Check if packet has IP layer
            if IP in packet:
                # Analyze packet for attacks
                result = self.detect.analyze_packet(packet)
                
                # Print packet summary if enabled
                if self.config.SHOW_PACKET_SUMMARY and result is None:
                    src = packet['IP'].src
                    dst = packet['IP'].dst
                    proto = packet.lastlayer().name
                    print(f"  {colorama.Fore.CYAN}[→]{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL} {src} → {dst} | {proto}")
                
                # Update statistics display periodically
                if self.detect.stats["total_packets"] % 100 == 0:
                    self._display_stats()
                    
        except Exception as e:
            self.log.debug(f"Packet handler error: {e}")
    
    def _display_stats(self):
        """Display live statistics"""
        stats = self.detect.get_statistics()
        active = self.detect.get_active_trackers()
        
        # Print inline stats update
        print(f"\n{colorama.Fore.GREEN}Stats: {stats['total_packets']} packets | "
              f"Attacks: {stats['attacks_detected']} | "
              f"Active Trackers: SYN:{active['syn_tracked_ips']} "
              f"Port:{active['port_scan_tracked']} ICMP:{active['icmp_tracked_ips']}{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}\n")
    
    def stop(self):
        """Stop the IDS"""
        self.running = False
        print(f"""
{colorama.Fore.CYAN}{'='*60}
  IDS SHUTDOWN SUMMARY
{'='*60}{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}
  Total Packets Processed: {self.detect.stats['total_packets']}
  TCP Packets: {self.detect.stats['tcp_packets']}
  ICMP Packets: {self.detect.stats['icmp_packets']}
  UDP Packets: {self.detect.stats['udp_packets']}
  SYN Packets: {self.detect.stats['syn_packets']}
  Total Attacks Detected: {self.detect.stats['attacks_detected']}
  IPs Blocked: {len(self.detect.stats['blocked_ips'])}
  
  Log file: {self.config.LOG_FILE}
{colorama.Fore.CYAN}{'='*60}{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}
        """)
        self.log.info("IDS stopped")


def view_logs():
    """View the alert logs"""
    print(f"\n{colorama.Fore.CYAN}=== Alert Logs ==={colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}\n")
    
    try:
        with open(config.Config.LOG_FILE, 'r') as f:
            lines = f.readlines()
            if lines:
                # Show last 50 lines
                for line in lines[-50:]:
                    print(line.rstrip())
            else:
                print("No logs found.")
    except FileNotFoundError:
        print("Log file not found. Start the IDS first.")


def view_config():
    """Display current configuration"""
    print(f"\n{colorama.Fore.CYAN}=== Current Configuration ==={colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}\n")
    
    cfg = config.Config.to_dict()
    for key, value in cfg.items():
        print(f"  {key}: {value}")


def clear_logs():
    """Clear the log file"""
    log_obj = logger.IDSLogger(config.Config.LOG_FILE)
    if log_obj.clear_logs():
        print(f"{colorama.Fore.GREEN}[+] Logs cleared successfully{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
    else:
        print(f"{colorama.Fore.RED}[!] Failed to clear logs{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")


def network_info():
    """Display network information"""
    print(f"\n{colorama.Fore.CYAN}=== Network Information ==={colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}\n")
    
    try:
        import scapy.all as scapy
        interfaces = scapy.get_if_list()
        print(f"Available Interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
    except ImportError:
        print("Scapy not installed. Cannot retrieve network info.")
    except Exception as e:
        print(f"Error: {e}")


def main_menu():
    """Display main menu and handle user input"""
    ids = IntrusionDetectionSystem()
    
    while True:
        utils.clear_screen()
        utils.print_banner()
        utils.print_menu()
        
        choice = input(f"\n{colorama.Fore.YELLOW}Enter your choice: {colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
        
        if choice == '1':
            try:
                ids.start()
            except KeyboardInterrupt:
                ids.stop()
                print(f"\n{colorama.Fore.GREEN}[+] Stopped by user{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
                input("\nPress Enter to continue...")
                
        elif choice == '2':
            view_logs()
            input("\nPress Enter to continue...")
            
        elif choice == '3':
            view_config()
            input("\nPress Enter to continue...")
            
        elif choice == '4':
            clear_logs()
            input("\nPress Enter to continue...")
            
        elif choice == '5':
            network_info()
            input("\nPress Enter to continue...")
            
        elif choice == '6':
            print(f"\n{colorama.Fore.GREEN}Thank you for using IDS!{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}\n")
            sys.exit(0)
            
        else:
            print(f"\n{colorama.Fore.RED}Invalid choice! Please try again.{colorama.Style.BRIGHT + colorama.Style.NORMAL + colorama.Style.DIM + colorama.Back.RESET + colorama.Fore.RESET + colorama.Style.RESET_ALL}")
            time.sleep(1)


def quick_start():
    """Quick start mode - run IDS directly"""
    ids = IntrusionDetectionSystem()
    try:
        ids.start()
    except KeyboardInterrupt:
        ids.stop()


# Entry point
if __name__ == "__main__":
    # Check if running in menu mode or direct mode
    if len(sys.argv) > 1:
        if sys.argv[1] == '--menu' or sys.argv[1] == '-m':
            main_menu()
        elif sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print("""
Intrusion Detection System (IDS)
================================

Usage:
  python main.py           - Quick start (direct mode)
  python main.py --menu    - Menu mode
  python main.py --help    - Show this help

Requirements:
  - Python 3.x
  - Scapy library (pip install scapy)
  - Administrator/root privileges

Features:
  - SYN Flood Detection
  - Port Scanning Detection  
  - ICMP Flood Detection
  - Real-time alerting
  - Log file management
            """)
        else:
            print("Unknown option. Use --help for usage information.")
    else:
        quick_start()