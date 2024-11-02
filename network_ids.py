#!/usr/bin/env python3

import os
import sys
from scapy.all import *
import datetime
from collections import defaultdict
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import netifaces
import configparser
import argparse

class NetworkIDS:
    def __init__(self, config_file='config.ini'):
        self.config = self.load_config(config_file)
        self.packet_count = 0
        self.suspicious_count = 0
        self.syn_count = defaultdict(int)
        self.icmp_count = defaultdict(list)
        self.setup_logging()
        
    def load_config(self, config_file):
        config = configparser.ConfigParser()
        try:
            config.read(config_file)
            if not config.sections():
                raise configparser.Error("Config file is empty or not found")
        except configparser.Error as e:
            print(f"Error reading config file: {e}")
            print("Using default configuration.")
            config['Thresholds'] = {
                'SYN_THRESHOLD': '100',
                'ICMP_THRESHOLD': '50',
                'REPORT_INTERVAL': '10'
            }
            config['Logging'] = {
                'LOG_FILE': 'network_ids.log',
                'MAX_LOG_SIZE': '5242880',
                'BACKUP_COUNT': '3'
            }
        return config

    def setup_logging(self):
        """Setup logging configuration with rotation"""
        try:
            log_file = self.config.get('Logging', 'LOG_FILE', fallback='network_ids.log')
            max_log_size = self.config.getint('Logging', 'MAX_LOG_SIZE', fallback=5242880)
            backup_count = self.config.getint('Logging', 'BACKUP_COUNT', fallback=3)
        except ValueError as e:
            print(f"Error reading config: {e}")
            print("Using default values for logging configuration.")
            log_file = 'network_ids.log'
            max_log_size = 5242880
            backup_count = 3

        handler = RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=backup_count)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            handlers=[
                handler,
                logging.StreamHandler()
            ]
        )
        
    def check_privileges(self):
        """Check if script is running with root privileges"""
        return os.geteuid() == 0
    
    def clean_old_records(self, current_time):
        """Clean old records from tracking dictionaries"""
        for ip in list(self.icmp_count.keys()):
            self.icmp_count[ip] = [
                (time, count) for time, count in self.icmp_count[ip]
                if (current_time - time).seconds <= 60
            ]
            if not self.icmp_count[ip]:
                del self.icmp_count[ip]
    
    def check_tcp_scan(self, src_ip, flags):
        """Check for TCP scanning behavior"""
        syn_threshold = self.config.getint('Thresholds', 'SYN_THRESHOLD', fallback=100)
        if flags == 2:  # SYN flag
            self.syn_count[src_ip] += 1
            if self.syn_count[src_ip] > syn_threshold:
                return True
        return False
    
    def check_icmp_flood(self, src_ip, icmp_type):
        """Check for ICMP flood attacks"""
        icmp_threshold = self.config.getint('Thresholds', 'ICMP_THRESHOLD', fallback=50)
        if icmp_type == 8:  # Echo Request
            current_time = datetime.datetime.now()
            self.icmp_count[src_ip].append((current_time, 1))
            
            recent_count = sum(
                count for time, count in self.icmp_count[src_ip]
                if (current_time - time).seconds <= 60
            )
            
            self.clean_old_records(current_time)
            
            if recent_count > icmp_threshold:
                return True
        return False

    def check_dns_amplification(self, packet):
        """Check for potential DNS amplification attacks"""
        if DNS in packet and packet.haslayer(UDP):
            if packet[DNS].qr == 1:  # DNS response
                if len(packet) > 512:  # Large DNS response
                    return True
        return False

    def check_arp_spoofing(self, packet):
        """Check for potential ARP spoofing attacks"""
        if ARP in packet:
            if packet[ARP].op == 2:  # ARP reply
                # You might want to maintain a list of known MAC-IP pairs
                # and check against that for inconsistencies
                return True
        return False
    
    def analyze_packet(self, packet):
        """Analyze incoming network packets"""
        self.packet_count += 1
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_parts = [f"[{timestamp}]"]
        
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                log_parts.append(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = packet[TCP].flags
                    log_parts.append(
                        f"Protocol: TCP, Source Port: {src_port}, "
                        f"Dest Port: {dst_port}, Flags: {flags}"
                    )
                    
                    if self.check_tcp_scan(src_ip, flags):
                        log_parts.append("[CONFIRMED PORT SCAN DETECTED]")
                        self.suspicious_count += 1
                
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    log_parts.append(
                        f"Protocol: UDP, Source Port: {src_port}, "
                        f"Dest Port: {dst_port}"
                    )
                    
                    if self.check_dns_amplification(packet):
                        log_parts.append("[POTENTIAL DNS AMPLIFICATION ATTACK DETECTED]")
                        self.suspicious_count += 1
                
                elif ICMP in packet:
                    icmp_type = packet[ICMP].type
                    icmp_code = packet[ICMP].code
                    log_parts.append(f"Protocol: ICMP, Type: {icmp_type}, Code: {icmp_code}")
                    
                    if icmp_type == 8 and icmp_code == 0:
                        log_parts.append("ICMP Echo Request (Ping)")
                    
                    if self.check_icmp_flood(src_ip, icmp_type):
                        log_parts.append("[CONFIRMED ICMP FLOOD DETECTED]")
                        self.suspicious_count += 1
            
            elif ARP in packet:
                if self.check_arp_spoofing(packet):
                    log_parts.append("[POTENTIAL ARP SPOOFING DETECTED]")
                    self.suspicious_count += 1
                
            log_message = " | ".join(log_parts)
            logging.info(log_message)
            
            report_interval = self.config.getint('Thresholds', 'REPORT_INTERVAL', fallback=10)
            if self.packet_count % report_interval == 0:
                self.print_status()
                
        except Exception as e:
            logging.error(f"Error analyzing packet: {str(e)}")
    
    def print_status(self):
        """Print current status"""
        print(f"\nStatus Update:")
        print(f"Packets analyzed: {self.packet_count}")
        print(f"Suspicious activities detected: {self.suspicious_count}")
        print(f"Active monitoring IPs - SYN: {len(self.syn_count)}, "
              f"ICMP: {len(self.icmp_count)}")

def get_network_interfaces():
    """Get a list of available network interfaces"""
    return netifaces.interfaces()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument("-c", "--config", default="config.ini", help="Path to configuration file")
    return parser.parse_args()

def main():
    args = parse_arguments()
    ids = NetworkIDS(config_file=args.config)
    
    if not ids.check_privileges():
        print("Error: This script requires root privileges.")
        print("Please run with sudo: sudo python3 network_ids.py")
        sys.exit(1)
    
    print("Starting Network IDS...")
    print(f"Logging to: {ids.config.get('Logging', 'LOG_FILE', fallback='network_ids.log')}")
    
    interfaces = get_network_interfaces()
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    
    while True:
        try:
            choice = int(input("Enter the number of the interface to monitor: ")) - 1
            if 0 <= choice < len(interfaces):
                chosen_interface = interfaces[choice]
                break
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    print(f"Monitoring network traffic on interface {chosen_interface}... Press Ctrl+C to stop.")
    
    try:
        sniff(iface=chosen_interface, prn=ids.analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\nStopping Network IDS...")
        ids.print_status()
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
