#!/usr/bin/env python3
"""
Advanced Network Security Monitor
Real-time intrusion detection and traffic analysis
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
import threading
import time
import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, deque
import ipaddress
import socket
import hashlib

class NetworkSecurityMonitor:
    def __init__(self, interface=None, alert_callback=None):
        self.interface = interface or self.get_default_interface()
        self.alert_callback = alert_callback or self.default_alert
        self.running = False
        
        # Detection thresholds
        self.port_scan_threshold = 10  # ports in 60 seconds
        self.dns_threshold = 50        # queries in 60 seconds
        self.arp_threshold = 5         # requests in 30 seconds
        
        # Tracking dictionaries
        self.arp_table = {}            # MAC -> IP mapping
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.dns_queries = defaultdict(deque)
        self.connection_tracker = defaultdict(int)
        self.suspicious_domains = set()
        
        # Time windows for analysis
        self.time_window = 60  # seconds
        self.arp_window = 30   # seconds
        
        # Initialize database
        self.init_database()
        
        # Load threat intelligence
        self.load_threat_intel()
        
    def get_default_interface(self):
        """Get the default network interface"""
        try:
            # Get default gateway interface
            gws = scapy.conf.route.route("0.0.0.0")
            return gws[0]
        except:
            return "eth0"  # fallback
    
    def init_database(self):
        """Initialize SQLite database for logging"""
        self.conn = sqlite3.connect('network_monitor.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                severity TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                details TEXT,
                raw_packet TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                protocol TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                packet_size INTEGER
            )
        ''')
        
        self.conn.commit()
    
    def load_threat_intel(self):
        """Load known malicious domains and IPs"""
        # Add some common malicious domains for demo
        self.suspicious_domains.update([
            'malware.com', 'phishing.net', 'botnet.org',
            'exploit.kit', 'ransomware.biz'
        ])
        
        # You can extend this to load from threat feeds
        
    def default_alert(self, alert_type, severity, details):
        """Default alert handler"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {severity}: {alert_type} - {details}")
    
    def log_alert(self, alert_type, severity, src_ip, dst_ip, details, packet=None):
        """Log alert to database"""
        timestamp = datetime.now().isoformat()
        raw_packet = str(packet) if packet else ""
        
        self.cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, severity, source_ip, 
                              destination_ip, details, raw_packet)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, alert_type, severity, src_ip, dst_ip, details, raw_packet))
        
        self.conn.commit()
        
        # Trigger callback
        self.alert_callback(alert_type, severity, details)
    
    def log_traffic(self, packet):
        """Log traffic statistics"""
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            protocol = ip_layer.proto
            
            # Map protocol numbers to names
            proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol_name = proto_map.get(protocol, str(protocol))
            
            src_port = dst_port = 0
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            timestamp = datetime.now().isoformat()
            
            self.cursor.execute('''
                INSERT INTO traffic_stats (timestamp, protocol, source_ip, 
                                         destination_ip, source_port, 
                                         destination_port, packet_size)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, protocol_name, ip_layer.src, ip_layer.dst,
                  src_port, dst_port, len(packet)))
    
    def detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        if packet.haslayer(ARP):
            arp_packet = packet[ARP]
            
            if arp_packet.op == 2:  # ARP reply
                ip = arp_packet.psrc
                mac = arp_packet.hwsrc
                
                # Check if we've seen this IP with a different MAC
                if ip in self.arp_table:
                    if self.arp_table[ip] != mac:
                        details = f"ARP spoofing detected: IP {ip} changed from MAC {self.arp_table[ip]} to {mac}"
                        self.log_alert("ARP_SPOOFING", "HIGH", arp_packet.psrc, 
                                     arp_packet.pdst, details, packet)
                        return True
                
                self.arp_table[ip] = mac
        
        return False
    
    def detect_port_scan(self, packet):
        """Detect port scanning attempts"""
        if packet.haslayer(TCP):
            tcp_packet = packet[TCP]
            ip_packet = packet[IP]
            
            src_ip = ip_packet.src
            dst_ip = ip_packet.dst
            dst_port = tcp_packet.dport
            
            # Track SYN packets (potential port scan)
            if tcp_packet.flags == 2:  # SYN flag
                current_time = time.time()
                
                # Clean old entries
                cutoff_time = current_time - self.time_window
                for ip in list(self.port_scan_tracker.keys()):
                    for target in list(self.port_scan_tracker[ip].keys()):
                        self.port_scan_tracker[ip][target] = {
                            port for port in self.port_scan_tracker[ip][target]
                            if current_time - port < self.time_window
                        }
                
                # Add current port
                self.port_scan_tracker[src_ip][dst_ip].add(current_time)
                
                # Check if threshold exceeded
                if len(self.port_scan_tracker[src_ip][dst_ip]) > self.port_scan_threshold:
                    details = f"Port scan detected: {src_ip} -> {dst_ip} ({len(self.port_scan_tracker[src_ip][dst_ip])} ports in {self.time_window}s)"
                    self.log_alert("PORT_SCAN", "MEDIUM", src_ip, dst_ip, details, packet)
                    
                    # Reset counter to avoid spam
                    self.port_scan_tracker[src_ip][dst_ip].clear()
                    return True
        
        return False
    
    def detect_dns_poisoning(self, packet):
        """Detect DNS poisoning and suspicious queries"""
        if packet.haslayer(DNS):
            dns_packet = packet[DNS]
            
            # DNS query analysis
            if dns_packet.qr == 0:  # Query
                if dns_packet.qd:
                    query_name = dns_packet.qd.qname.decode('utf-8').rstrip('.')
                    src_ip = packet[IP].src
                    
                    # Check for suspicious domains
                    for suspicious in self.suspicious_domains:
                        if suspicious in query_name.lower():
                            details = f"Suspicious DNS query: {query_name} from {src_ip}"
                            self.log_alert("SUSPICIOUS_DNS", "MEDIUM", src_ip, 
                                         packet[IP].dst, details, packet)
                            return True
                    
                    # Track DNS query frequency
                    current_time = time.time()
                    self.dns_queries[src_ip].append(current_time)
                    
                    # Clean old entries
                    cutoff_time = current_time - self.time_window
                    while (self.dns_queries[src_ip] and 
                           self.dns_queries[src_ip][0] < cutoff_time):
                        self.dns_queries[src_ip].popleft()
                    
                    # Check for DNS flooding
                    if len(self.dns_queries[src_ip]) > self.dns_threshold:
                        details = f"DNS flooding detected: {len(self.dns_queries[src_ip])} queries from {src_ip} in {self.time_window}s"
                        self.log_alert("DNS_FLOOD", "HIGH", src_ip, 
                                     packet[IP].dst, details, packet)
                        return True
            
            # DNS response analysis
            elif dns_packet.qr == 1:  # Response
                if dns_packet.ancount > 0:
                    # Check for multiple A records (potential poisoning)
                    a_records = []
                    for i in range(dns_packet.ancount):
                        if dns_packet.an[i].type == 1:  # A record
                            a_records.append(dns_packet.an[i].rdata)
                    
                    if len(a_records) > 3:  # Suspicious number of A records
                        details = f"Potential DNS poisoning: {len(a_records)} A records in response"
                        self.log_alert("DNS_POISONING", "HIGH", packet[IP].src,
                                     packet[IP].dst, details, packet)
                        return True
        
        return False
    
    def detect_suspicious_traffic(self, packet):
        """Detect other suspicious network patterns"""
        if packet.haslayer(IP):
            ip_packet = packet[IP]
            
            # Check for private IP in public communication
            try:
                src_ip = ipaddress.ip_address(ip_packet.src)
                dst_ip = ipaddress.ip_address(ip_packet.dst)
                
                # Detect potential data exfiltration
                if packet.haslayer(TCP) and len(packet) > 1400:  # Large packets
                    tcp_packet = packet[TCP]
                    if tcp_packet.dport in [80, 443, 53]:  # Common exfil ports
                        details = f"Large packet ({len(packet)} bytes) to common service port {tcp_packet.dport}"
                        self.log_alert("POTENTIAL_EXFILTRATION", "LOW", 
                                     ip_packet.src, ip_packet.dst, details, packet)
                        return True
                
            except ValueError:
                pass  # Invalid IP address
        
        return False
    
    def packet_handler(self, packet):
        """Main packet processing function"""
        try:
            # Log traffic for analysis
            self.log_traffic(packet)
            
            # Run detection modules
            self.detect_arp_spoofing(packet)
            self.detect_port_scan(packet)
            self.detect_dns_poisoning(packet)
            self.detect_suspicious_traffic(packet)
            
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_monitoring(self):
        """Start the network monitoring"""
        self.running = True
        print(f"Starting network monitoring on interface: {self.interface}")
        print("Press Ctrl+C to stop...")
        
        try:
            scapy.sniff(iface=self.interface, prn=self.packet_handler, 
                       stop_filter=lambda x: not self.running)
        except KeyboardInterrupt:
            self.stop_monitoring()
        except Exception as e:
            print(f"Error during monitoring: {e}")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop the network monitoring"""
        self.running = False
        self.conn.close()
        print("\nNetwork monitoring stopped.")
    
    def get_statistics(self):
        """Get monitoring statistics"""
        stats = {}
        
        # Get alert counts by type
        self.cursor.execute('''
            SELECT alert_type, severity, COUNT(*) 
            FROM alerts 
            GROUP BY alert_type, severity
        ''')
        
        stats['alerts'] = {}
        for row in self.cursor.fetchall():
            alert_type, severity, count = row
            if alert_type not in stats['alerts']:
                stats['alerts'][alert_type] = {}
            stats['alerts'][alert_type][severity] = count
        
        # Get traffic stats
        self.cursor.execute('''
            SELECT protocol, COUNT(*), AVG(packet_size)
            FROM traffic_stats 
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY protocol
        ''')
        
        stats['traffic'] = {}
        for row in self.cursor.fetchall():
            protocol, count, avg_size = row
            stats['traffic'][protocol] = {
                'count': count,
                'avg_size': round(avg_size, 2)
            }
        
        return stats
    
    def export_to_siem(self, output_file="siem_export.json"):
        """Export alerts in SIEM-compatible format"""
        self.cursor.execute('''
            SELECT * FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT 1000
        ''')
        
        alerts = []
        columns = [desc[0] for desc in self.cursor.description]
        
        for row in self.cursor.fetchall():
            alert = dict(zip(columns, row))
            # Convert to CEF (Common Event Format) style
            cef_alert = {
                "timestamp": alert['timestamp'],
                "deviceVendor": "NetworkSecurityMonitor",
                "deviceProduct": "NSM",
                "deviceVersion": "1.0",
                "signatureId": alert['alert_type'],
                "name": alert['alert_type'],
                "severity": alert['severity'],
                "sourceAddress": alert['source_ip'],
                "destinationAddress": alert['destination_ip'],
                "message": alert['details']
            }
            alerts.append(cef_alert)
        
        with open(output_file, 'w') as f:
            json.dump(alerts, f, indent=2)
        
        print(f"SIEM export saved to {output_file}")

if __name__ == "__main__":
    # Create and start the monitor
    monitor = NetworkSecurityMonitor()
    
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        print("\nShutting down...")
        monitor.stop_monitoring()
        
        # Print statistics
        stats = monitor.get_statistics()
        print("\n=== MONITORING STATISTICS ===")
        print(f"Alerts: {stats.get('alerts', {})}")
        print(f"Traffic: {stats.get('traffic', {})}")
        
        # Export to SIEM
        monitor.export_to_siem()