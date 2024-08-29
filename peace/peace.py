import socket  # menentukan IP lokal & buat koneksi IP eksternal
import ipaddress  # menghitung dan mengelola rentang subnet dari IP local
import platform  # menentukan sistem operasi untuk penggunaan malware
import subprocess
import os
import time
import hashlib  # computing file hashes
import requests  # download malicious data
import logging
from scapy.all import *
from prettytable import PrettyTable

# Configure logging for Traffic monitoring
logging.basicConfig(filename='Traff.logs', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables for Traffic monitoring
packet_sizes = []
packet_count = 0

def generate_banner(tool_name):
    banner = f"""
                  **************************************************
                  *                                                *
                  *            WELCOME TUGAS LAS WEEK-4            *
                  *                                                *
                  *       This tools for Network Scanning          *
                  *                                                *
                  *          GUSTI AYU ADINDHA JYOTHI              *
                  *                                                *
                  *                  ID : 2419                     *     
                  **************************************************
    """
    print(banner)

# Find local IP
def find_local_ip():
    try:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))
        local_ip = temp_socket.getsockname()[0]
        temp_socket.close()
        return local_ip  # Mengembalikan IP lokal
    except Exception as error:
        print("Error:", error)
        return None

# Calculate IP subnet range based on the local IP
def find_subnet_range(ip):
    network_obj = ipaddress.ip_network(f"{ip}/24", strict=False)
    return network_obj

# Print results of the scanned subnets
def ip_range(subnet):
    print(f"The IP range is {subnet.network_address} - {subnet.broadcast_address} ({len(list(subnet.hosts()))} hosts)")

# Scan subnet for open ports and vulnerabilities
def scan_subnet(subnet, ports="1-65535", script="vuln"):
    try:
        command = f'nmap -p {ports} -sV --script {script} {subnet}'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as error:
        print(f"Error occurred: {error}")
        return None

# Block IP if suspicious activity is detected
def block_ip(ip_address):
    os_name = platform.system()  # Mengganti variabel 'system' menjadi 'os_name'
    if os_name == 'Windows':
        command = f"netsh advfirewall firewall add rule name='Blocked IP' dir=in action=block remoteip={ip_address}"
    elif os_name == 'Linux':
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    else:
        logging.error(f"Unsupported OS: {os_name}")
        print(f"Unsupported OS: {os_name}")
        return

    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Blocked IP: {ip_address}")  # Log the blocked IP address
        print(f"Blocked IP: {ip_address}")  # Print to console
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip_address}. Error: {e}")
        print(f"Failed to block IP {ip_address}. Error: {e}")  # Print to console

# Callback function for Scapy sniffing
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
        if packet_count >= 100 and len(set(packet_sizes[-20:])) == 1:
            logging.warning(f"Suspiciously repetitive traffic detected from {ip_src}")
            print(f"Suspiciously repetitive traffic detected from {ip_src}")
            block_ip(ip_src)

# Start Intrusion Detection System (IDS)
def start_ids():
    logging.info("Starting packet sniffing...")  # Log when sniffing starts
    print("Starting packet sniffing...")  # Print to console
    sniff(prn=packet_callback, store=0)

# Computes MD5, SHA1, and SHA256 hashes for a file
def compute_hashes(file_path):
    hashers = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    with open(file_path, 'rb') as f:  # Open file in binary mode
        while chunk := f.read(65536):  # Read file in chunks
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}

# Identifies malware type based on hashes
def identify_malware(file_hashes, classification):
    for hash_value in file_hashes.values():
        if hash_value in classification:
            return classification[hash_value]
    return "Unknown"

# Scan a single file for malware
def scan_file(file_path, malicious_hashes, classification, table):
    file_hashes = compute_hashes(file_path)
    if any(hash_value in malicious_hashes for hash_value in file_hashes.values()):
        malware_type = identify_malware(file_hashes, classification)  # Identify malware type
        table.add_row([file_path, malware_type])  # Add result to table
        os.system('cls' if platform.system() == 'Windows' else 'clear')
        print(table)

# Scan a directory for malware
def scan_directory(directory, malicious_hashes, classification, table):
    count = 0
    for root, _, files in os.walk(directory):
        for file in files:
            try:
                scan_file(os.path.join(root, file), malicious_hashes, classification, table)
                count += 1
            except (PermissionError, KeyboardInterrupt):
                continue
    return count

# Download malicious hash list and start scanning for malware
def scan_malware(directories):
    url = "https://raw.githubusercontent.com/eminunal1453/Various-Malware-Hashes/main/hashes.txt"
    response = requests.get(url)
    malicious_hashes = set(response.text.splitlines())

    malware_types = {
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Ransomware",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Trojan",
        "8754c2a98e3b9c86aa49d4a35b8835e5fc6d5e6f53d6bce44a7f8db9c524de7a": "Virus",
        "3dc3c3f1bce75e029b1c7a8db9a20dfb2c6f68c925b1898db0d49f7a1d0520a6": "Spyware",
        "d301f9c47a8dd8331c4597feefcb056d08e3a3b4c4f4d03f9c1436a1a5f5b6b5": "Adware",
        "1e8a9f5127d527fb9c97d7fd8be2b883cc7f75e20e437d7b19db69b42c42220c": "Worm"
    }

    table = PrettyTable(["File Path", "Malware Type"])
    start_time = time.time()

    total_files = 0
    for directory in directories:
        total_files += scan_directory(directory, malicious_hashes, malware_types, table)

    print(table)
    print(f"\nTotal files scanned: {total_files}")
    print(f"Runtime: {time.time() - start_time:.2f} seconds")


if __name__ == "__main__":
    tool_name = ""

    while True:
        generate_banner(tool_name)

        local_ip = find_local_ip()

        if local_ip:
            print(f"Your local IP Address is: {local_ip}")
            subnet = find_subnet_range(local_ip)
            print(f"The calculated CIDR notation is: {subnet}")
            ip_range(subnet)

            # Asks users for their choice of scan
            print()
            print("Choose a scan option:")
            print()
            print("1. Scan all active hosts for open ports and identify any services with vulnerabilities")
            print("2. Packet Detecting & Anomaly Detection")
            print("3. Scan for Malware")

            print()
            choice = input("Enter your choice (1/2/3): ")
            
            # Based on choice, run the appropriate scan
            if choice == "1":
                print()
                print("Scanning all active hosts for open ports and identifying services with vulnerabilities...")
                scan_result = scan_subnet(subnet)
                print(scan_result)

            elif choice == "2":
                print()
                print("Starting packet sniffing and anomaly detection...")
                start_ids()

            elif choice == "3":
                print()
                print("Scanning for Malware...")
                directories = input("Enter the directory paths to scan (separated by commas): ").split(',')
                directories = [directory.strip() for directory in directories]
                scan_malware(directories)

            else:
                print("Invalid choice. Please try again.")
            
            # Ask if the user wants to run another scan
            again = input("Do you want to run another scan? (y/n): ").lower()
            if again != "y":
                print("Exiting the tool. Thank you for using!")
                break
        else:
            print("Failed to find the local IP address. Exiting.")
            break
