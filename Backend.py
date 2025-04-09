from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
import socket
import datetime
import os

# Get the Downloads folder 
DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
LOG_FILE = os.path.join(DOWNLOADS_DIR, "network_logs.txt")

# Clear log file at the start of each session
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)

def get_hostname(ip):
    """Resolve IP address to hostname (if possible)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip  
    
def process_packet(packet):
    """Capture packets and log website visits and packet details."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            packet_size = len(packet)
            
            # Resolve destination host
            website = get_hostname(dst_ip)

            # Detect DNS queries to capture visited websites
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                queried_domain = packet[DNSQR].qname.decode("utf-8")
                log_entry = f"{timestamp} | Website: {queried_domain} | Source: {src_ip} | Destination: {dst_ip} | Protocol: {protocol} | Size: {packet_size} bytes\n"
            else:
                log_entry = f"{timestamp} | Website: {website} | Source: {src_ip} | Destination: {dst_ip} | Protocol: {protocol} | Size: {packet_size} bytes\n"

            # Append to log file
            with open(LOG_FILE, "a") as file:
                file.write(log_entry)

            print(log_entry, end="")  

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing():
    """Start network packet sniffing."""
    print("🔍 Network monitoring started... (Press Ctrl+C to stop)")
    try:
        sniff(prn=process_packet, store=False, filter="ip")
    except KeyboardInterrupt:
        print(f"\n📁 Logs saved at: {LOG_FILE}")

if __name__ == "__main__":
    start_sniffing()
