from scapy.all import *
import logging
import subprocess
import platform

# Configure logging
logging.basicConfig(filename='Traff.logs', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables for statistical analysis
packet_sizes = []
packet_count = 0

def block_ip(ip_address):
    system = platform.system()
    if system == 'Windows':
        # Block IP using Windows firewall (requires administrative privileges)
        command = f"netsh advfirewall firewall add rule name='Blocked IP' dir=in action=block remoteip={ip_address}"
    elif system == 'Linux':
        # Block IP using iptables (requires administrative privileges)
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    else:
        logging.error(f"Unsupported OS: {system}")
        print(f"Unsupported OS: {system}")
        return

    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Blocked IP: {ip_address}")  # Log the blocked IP address
        print(f"Blocked IP: {ip_address}")  # Print to console
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip_address}. Error: {e}")
        print(f"Failed to block IP {ip_address}. Error: {e}")  # Print to console

def packet_callback(packet):
    global packet_sizes, packet_count
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)
        
        # Update packet statistics
        packet_sizes.append(packet_size)
        packet_count += 1
        
        # Detect large packets
        if packet_size > 1500:
            logging.warning(f"Suspiciously large packet ({packet_size} bytes) detected from {ip_src} to {ip_dst}")
            print(f"Suspiciously large packet ({packet_size} bytes) detected from {ip_src} to {ip_dst}")
        
        # Detect frequent requests from a single source
        if packet_count >= 20 and len(set(packet_sizes[-20:])) == 1:
            logging.warning(f"Suspiciously repetitive traffic detected from {ip_src}")
            print(f"Suspiciously repetitive traffic detected from {ip_src}")
            block_ip(ip_src)  

def start_ids():
    logging.info("Starting packet sniffing...")  # Log when sniffing starts
    print("Starting packet sniffing...")  # Print to console
    sniff(prn=packet_callback, store=0)

