"""
Network Packet Analyzer - Similar to Wireshark
Captures and analyzes network packets in real-time
"""
import socket
import struct
import textwrap
import datetime
import json
import sys
from collections import defaultdict

class PacketCapture:
    """Handles raw packet capture from network interface"""
    
    def __init__(self, interface=''):
        self.interface = interface
        self.packet_count = 0
        self.packets = []
        
    def create_socket(self):
        """Create raw socket for packet capture"""
        try:
            # Windows
            if sys.platform == 'win32':
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.get_local_ip(), 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            # Linux/Mac
            else:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            print("[+] Socket created successfully")
            return True
        except PermissionError:
            print("[!] Permission denied. Run with administrator/sudo privileges")
            return False
        except Exception as e:
            print(f"[!] Error creating socket: {e}")
            return False
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def capture_packets(self):
        """Capture packets until user stops"""
        print(f"[*] Starting continuous packet capture...")
        print(f"[*] Press Ctrl+C to stop capture\n")
        
        try:
            while True:
                raw_data, addr = self.sock.recvfrom(65535)
                self.packet_count += 1
                
                timestamp = datetime.datetime.now()
                packet_info = self.parse_packet(raw_data, timestamp)
                
                if packet_info:
                    self.packets.append(packet_info)
                    self.display_packet_summary(packet_info, self.packet_count)
                    
        except KeyboardInterrupt:
            print("\n[*] Capture stopped by user")
        finally:
            if sys.platform == 'win32':
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sock.close()
            print(f"\n[+] Captured {self.packet_count} packets total")
    
    def parse_packet(self, raw_data, timestamp):
        """Parse raw packet data"""
        packet = {'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}
        
        try:
            # Skip Ethernet header on Linux (14 bytes)
            if sys.platform != 'win32' and len(raw_data) > 14:
                eth_header = raw_data[:14]
                packet['eth'] = self.parse_ethernet(eth_header)
                raw_data = raw_data[14:]
            
            # Parse IP header
            if len(raw_data) >= 20:
                ip_header = raw_data[:20]
                packet['ip'] = self.parse_ipv4(ip_header)
                
                # Get protocol data
                protocol = packet['ip']['protocol']
                data = raw_data[packet['ip']['header_length']:]
                
                # Parse TCP
                if protocol == 6 and len(data) >= 20:
                    packet['tcp'] = self.parse_tcp(data)
                    packet['protocol_name'] = 'TCP'
                
                # Parse UDP
                elif protocol == 17 and len(data) >= 8:
                    packet['udp'] = self.parse_udp(data)
                    packet['protocol_name'] = 'UDP'
                
                # Parse ICMP
                elif protocol == 1 and len(data) >= 8:
                    packet['icmp'] = self.parse_icmp(data)
                    packet['protocol_name'] = 'ICMP'
                
                else:
                    packet['protocol_name'] = f'Protocol-{protocol}'
                
                return packet
        except Exception as e:
            print(f"[!] Error parsing packet: {e}")
        
        return None
    
    def parse_ethernet(self, data):
        """Parse Ethernet header"""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data)
        return {
            'dest_mac': self.format_mac(dest_mac),
            'src_mac': self.format_mac(src_mac),
            'protocol': proto
        }
    
    def parse_ipv4(self, data):
        """Parse IPv4 header"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        return {
            'version': version,
            'header_length': header_length,
            'ttl': ttl,
            'protocol': proto,
            'src': self.ipv4(src),
            'dest': self.ipv4(dest)
        }
    
    def parse_tcp(self, data):
        """Parse TCP segment"""
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgment': acknowledgment,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            }
        }
    
    def parse_udp(self, data):
        """Parse UDP segment"""
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'size': size
        }
    
    def parse_icmp(self, data):
        """Parse ICMP packet"""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return {
            'type': icmp_type,
            'code': code,
            'checksum': checksum
        }
    
    @staticmethod
    def ipv4(addr):
        """Format IPv4 address"""
        return '.'.join(map(str, addr))
    
    @staticmethod
    def format_mac(addr):
        """Format MAC address"""
        return ':'.join(map('{:02x}'.format, addr))
    
    def display_packet_summary(self, packet, num):
        """Display one-line packet summary"""
        proto = packet.get('protocol_name', 'Unknown')
        src = packet['ip']['src']
        dest = packet['ip']['dest']
        
        info = f"{src} → {dest}"
        
        if 'tcp' in packet:
            info += f" [TCP {packet['tcp']['src_port']}→{packet['tcp']['dest_port']}]"
        elif 'udp' in packet:
            info += f" [UDP {packet['udp']['src_port']}→{packet['udp']['dest_port']}]"
        
        print(f"[{num:04d}] {packet['timestamp']} | {proto:8s} | {info}")

class PacketAnalyzer:
    """Analyzes captured packets for statistics and patterns"""
    
    def __init__(self, packets):
        self.packets = packets
    
    def generate_statistics(self):
        """Generate packet statistics"""
        stats = {
            'total_packets': len(self.packets),
            'protocols': defaultdict(int),
            'top_sources': defaultdict(int),
            'top_destinations': defaultdict(int),
            'tcp_flags': defaultdict(int),
            'port_distribution': defaultdict(int)
        }
        
        for packet in self.packets:
            # Protocol distribution
            proto = packet.get('protocol_name', 'Unknown')
            stats['protocols'][proto] += 1
            
            # IP addresses
            if 'ip' in packet:
                stats['top_sources'][packet['ip']['src']] += 1
                stats['top_destinations'][packet['ip']['dest']] += 1
            
            # TCP flags
            if 'tcp' in packet:
                for flag, value in packet['tcp']['flags'].items():
                    if value:
                        stats['tcp_flags'][flag] += 1
                
                stats['port_distribution'][packet['tcp']['dest_port']] += 1
            
            # UDP ports
            if 'udp' in packet:
                stats['port_distribution'][packet['udp']['dest_port']] += 1
        
        return stats
    
    def display_statistics(self, stats):
        """Display formatted statistics"""
        print("\n" + "="*70)
        print("PACKET ANALYSIS STATISTICS")
        print("="*70)
        
        print(f"\nTotal Packets Captured: {stats['total_packets']}")
        
        print(f"\nProtocol Distribution:")
        print("-" * 40)
        for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_packets']) * 100
            print(f"  {proto:15s}: {count:4d} ({percentage:5.1f}%)")
        
        print(f"\nTop 5 Source IPs:")
        print("-" * 40)
        for ip, count in sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip:15s}: {count:4d} packets")
        
        print(f"\nTop 5 Destination IPs:")
        print("-" * 40)
        for ip, count in sorted(stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip:15s}: {count:4d} packets")
        
        if stats['tcp_flags']:
            print(f"\nTCP Flags Distribution:")
            print("-" * 40)
            for flag, count in sorted(stats['tcp_flags'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {flag:5s}: {count:4d}")
        
        print(f"\nTop 10 Destination Ports:")
        print("-" * 40)
        for port, count in sorted(stats['port_distribution'].items(), key=lambda x: x[1], reverse=True)[:10]:
            service = self.get_port_service(port)
            print(f"  {port:5d} ({service:15s}): {count:4d}")
    
    @staticmethod
    def get_port_service(port):
        """Get common service name for port"""
        services = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
            110: 'POP3', 143: 'IMAP', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def detect_suspicious_activity(self):
        """Detect potentially suspicious network patterns"""
        alerts = []
        
        # Check for port scanning (multiple ports from same source)
        source_ports = defaultdict(set)
        for packet in self.packets:
            if 'tcp' in packet and 'ip' in packet:
                src = packet['ip']['src']
                dest_port = packet['tcp']['dest_port']
                source_ports[src].add(dest_port)
        
        for src, ports in source_ports.items():
            if len(ports) > 10:
                alerts.append({
                    'type': 'Possible Port Scan',
                    'source': src,
                    'details': f'Accessed {len(ports)} different ports'
                })
        
        # Check for SYN flood
        syn_counts = defaultdict(int)
        for packet in self.packets:
            if 'tcp' in packet and packet['tcp']['flags']['SYN'] and not packet['tcp']['flags']['ACK']:
                syn_counts[packet['ip']['src']] += 1
        
        for src, count in syn_counts.items():
            if count > 50:
                alerts.append({
                    'type': 'Possible SYN Flood',
                    'source': src,
                    'details': f'{count} SYN packets detected'
                })
        
        return alerts
    
    def display_alerts(self, alerts):
        """Display security alerts"""
        if alerts:
            print("\n" + "="*70)
            print("SECURITY ALERTS")
            print("="*70)
            
            for i, alert in enumerate(alerts, 1):
                print(f"\n[Alert {i}] {alert['type']}")
                print(f"  Source: {alert['source']}")
                print(f"  Details: {alert['details']}")
        else:
            print("\n[+] No suspicious activity detected")

class ReportExporter:
    """Export analysis results to various formats"""
    
    @staticmethod
    def export_to_markdown(packets, stats, alerts, filename='packet_analysis_report.md'):
        """Export to Markdown format"""
        with open(filename, 'w') as f:
            # Header
            f.write("# Network Packet Analysis Report\n\n")
            f.write(f"**Report Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            
            # Summary
            f.write("## Summary\n\n")
            f.write(f"- **Total Packets Captured:** {stats['total_packets']}\n")
            if packets:
                f.write(f"- **Capture Start:** {packets[0]['timestamp']}\n")
                f.write(f"- **Capture End:** {packets[-1]['timestamp']}\n")
            f.write("\n")
            
            # Protocol Distribution
            f.write("## Protocol Distribution\n\n")
            f.write("| Protocol | Count | Percentage |\n")
            f.write("|----------|-------|------------|\n")
            for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / stats['total_packets']) * 100
                f.write(f"| {proto} | {count} | {percentage:.1f}% |\n")
            f.write("\n")
            
            # Top Source IPs
            f.write("## Top Source IP Addresses\n\n")
            f.write("| IP Address | Packet Count |\n")
            f.write("|------------|-------------|\n")
            for ip, count in sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f"| {ip} | {count} |\n")
            f.write("\n")
            
            # Top Destination IPs
            f.write("## Top Destination IP Addresses\n\n")
            f.write("| IP Address | Packet Count |\n")
            f.write("|------------|-------------|\n")
            for ip, count in sorted(stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f"| {ip} | {count} |\n")
            f.write("\n")
            
            # TCP Flags
            if stats['tcp_flags']:
                f.write("## TCP Flags Distribution\n\n")
                f.write("| Flag | Count |\n")
                f.write("|------|-------|\n")
                for flag, count in sorted(stats['tcp_flags'].items(), key=lambda x: x[1], reverse=True):
                    f.write(f"| {flag} | {count} |\n")
                f.write("\n")
            
            # Port Distribution
            f.write("## Top Destination Ports\n\n")
            f.write("| Port | Service | Count |\n")
            f.write("|------|---------|-------|\n")
            for port, count in sorted(stats['port_distribution'].items(), key=lambda x: x[1], reverse=True)[:15]:
                service = PacketAnalyzer.get_port_service(port)
                f.write(f"| {port} | {service} | {count} |\n")
            f.write("\n")
            
            # Security Alerts
            f.write("## Security Alerts\n\n")
            if alerts:
                for i, alert in enumerate(alerts, 1):
                    f.write(f"### Alert {i}: {alert['type']}\n\n")
                    f.write(f"- **Source:** {alert['source']}\n")
                    f.write(f"- **Details:** {alert['details']}\n\n")
            else:
                f.write("✅ No suspicious activity detected\n\n")
            
            # Sample Packets
            f.write("## Sample Captured Packets (First 20)\n\n")
            f.write("| # | Timestamp | Protocol | Source | Destination | Ports |\n")
            f.write("|---|-----------|----------|--------|-------------|-------|\n")
            for i, packet in enumerate(packets[:20], 1):
                proto = packet.get('protocol_name', 'Unknown')
                src = packet['ip']['src'] if 'ip' in packet else 'N/A'
                dest = packet['ip']['dest'] if 'ip' in packet else 'N/A'
                
                ports = ''
                if 'tcp' in packet:
                    ports = f"{packet['tcp']['src_port']}→{packet['tcp']['dest_port']}"
                elif 'udp' in packet:
                    ports = f"{packet['udp']['src_port']}→{packet['udp']['dest_port']}"
                else:
                    ports = 'N/A'
                
                f.write(f"| {i} | {packet['timestamp']} | {proto} | {src} | {dest} | {ports} |\n")
            
            f.write("\n---\n\n")
            f.write("*Report generated by Network Packet Analyzer*\n")
        
        print(f"\n[+] Analysis report exported to {filename}")
    
    @staticmethod
    def export_to_csv(packets, filename='packets.csv'):
        """Export packets to CSV format"""
        with open(filename, 'w') as f:
            f.write("Timestamp,Protocol,Source IP,Dest IP,Src Port,Dest Port\n")
            
            for packet in packets:
                timestamp = packet['timestamp']
                proto = packet.get('protocol_name', 'Unknown')
                src_ip = packet['ip']['src'] if 'ip' in packet else 'N/A'
                dest_ip = packet['ip']['dest'] if 'ip' in packet else 'N/A'
                
                src_port = 'N/A'
                dest_port = 'N/A'
                
                if 'tcp' in packet:
                    src_port = packet['tcp']['src_port']
                    dest_port = packet['tcp']['dest_port']
                elif 'udp' in packet:
                    src_port = packet['udp']['src_port']
                    dest_port = packet['udp']['dest_port']
                
                f.write(f"{timestamp},{proto},{src_ip},{dest_ip},{src_port},{dest_port}\n")
        
        print(f"[+] Packets exported to {filename}")

def main():
    """Main execution function"""
    
    # Initialize packet capture
    capture = PacketCapture()
    
    if not capture.create_socket():
        return
    
    # Capture packets (continuous until Ctrl+C)
    capture.capture_packets()
    
    if not capture.packets:
        print("[!] No packets captured")
        return
    
    # Analyze packets
    print("\n[*] Analyzing captured packets...")
    analyzer = PacketAnalyzer(capture.packets)
    
    # Generate and display statistics
    stats = analyzer.generate_statistics()
    analyzer.display_statistics(stats)
    
    # Detect suspicious activity
    alerts = analyzer.detect_suspicious_activity()
    analyzer.display_alerts(alerts)
    
    # Export results
    print("\n[*] Exporting results...")
    exporter = ReportExporter()
    exporter.export_to_markdown(capture.packets, stats, alerts)
    exporter.export_to_csv(capture.packets)
    
    print("\n[+] Analysis complete!")

def print_banner():
    """Print ASCII art banner"""
    banner = r"""
    ____             __        __     ___                __                     
   / __ \____ ______/ /_____  / /_   /   |  ____  ____ _/ /_  ______  ___  _____
  / /_/ / __ `/ ___/ //_/ _ \/ __/  / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 / ____/ /_/ / /__/ ,< /  __/ /_   / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/_/    \__,_/\___/_/|_|\___/\__/  /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                        /____/                   
"""
    print("\033[91m" + banner + "\033[0m")  # Red color
    print("\033[93m# Coded By Infinity_sec(Nir_____)\033[0m")  # Yellow color
    print("\033[96m" + "="*80 + "\033[0m\n")  # Cyan color

if __name__ == "__main__":
    print_banner()
    
    print("\033[93m*** IMPORTANT NOTICE ***\033[0m")
    print("This tool requires administrator/root privileges to capture packets.")
    print("Only capture packets on networks you own or have permission to monitor.")
    print("Unauthorized packet capture may be illegal.\n")
    
    response = input("Do you have authorization to capture packets? (yes/no): ")
    if response.lower() == 'yes':
        main()
    else:
        print("Capture cancelled. Please obtain proper authorization.")