"""
Network Protocol Stack Analyzer
Course: Computer Networks 
Institution: University of Kurdistan
Author: Serve Rabani
Description: A modular, and professionally commented Python script 
             to dissect HTTP layers (3, 4, and 7) from a PCAPNG file.
"""

import os
import sys

try:
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP
except ImportError:
    print("[!] Error: 'scapy' library is missing. Please run: pip install scapy")
    sys.exit(1)


class PcapHttpAnalyzer:
    """Handles PCAPNG file validation and HTTP network layer dissection."""
    
    def __init__(self, file_path):
        self.file_path = file_path

    def validate_file(self):
        """Ensures the target file exists before starting the parsing process."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Target file not found at: {self.file_path}")
        return True

    def _extract_http_layer(self, packet):
        """Dissects TCP payload to extract plain-text Layer 7 HTTP data."""
        if packet.haslayer(TCP):
            # Target Port 80 to isolate standard unencrypted HTTP web traffic
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                
                # Convert raw network bytes to string; ignore errors to prevent crashes on media bytes
                payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
                
                if payload:
                    # Isolate the very first line of the header (Request Line or Status Line)
                    first_line = payload.split('\r\n')[0]
                    
                    # Filter out empty TCP control packets (like pure ACK/SYN) by matching HTTP keywords
                    if any(keyword in first_line for keyword in ["GET", "POST", "HTTP/1."]):
                        return first_line
        return None

    def process_traffic(self):
        """Parses the packet array, extracts layer metadata, and prints a structured summary."""
        self.validate_file()
        
        print("\n" + "=" * 90)
        print(f"{'Source IP':<15} | {'Dest IP':<15} | {'Src Port':<8} | {'Dst Port':<8} | {'HTTP Layer Message (Layer 7)':<30}")
        print("=" * 90)

        try:
            # Load the network capture file into memory
            packets = rdpcap(self.file_path)
            detected_count = 0
            
            for pkt in packets:
                # Check for mandatory Layer 3 (IP) and Layer 4 (TCP) headers
                if pkt.haslayer(IP) and pkt.haslayer(TCP):
                    http_info = self._extract_http_layer(pkt)
                    
                    if http_info:
                        # Extract 32-bit IP addresses and 16-bit Port numbers
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        
                        print(f"{src_ip:<15} | {dst_ip:<15} | {src_port:<8} | {dst_port:<8} | {http_info[:35]}")
                        detected_count += 1
                        
            if detected_count == 0:
                print("[-] Info: No raw HTTP plain-text payloads detected.")
                
        except Exception as e:
            print(f"[!] Critical Error during packet dissection: {e}")
            
        print("=" * 90 + "\n")


if __name__ == "__main__":
    # Standard repository structure path: captures/phase1.pcapng
    target_pcap = os.path.join("captures", "phase1.pcapng")
    
    analyzer = PcapHttpAnalyzer(target_pcap)
    analyzer.process_traffic()